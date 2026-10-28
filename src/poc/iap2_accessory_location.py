#!/usr/bin/env python3
"""
iAP2 配件定位客户端（实验性 PoC，软件模拟外接 GPS 配件）
----------------------------------------------------------
通过 USB 上已信任的 lockdown 连接打开 com.apple.carkit.service，以 iAP2
配件身份完成识别与 MFi-v3 挑战应答认证，随后按手机订阅（FFFA）持续发送
NMEA GGA/RMC（FFFB），使 iPhone 把本机当作外接定位配件。

与 src/poc/coredevice_location_poc.py 的边界：
- CoreDevice/DVT 是「开发者软件模拟」来源（isSimulatedBySoftware）；本通道
  是「外接配件」来源（isProducedByAccessory），二者在 Core Location 中是
  不同的定位来源标记。
- 本通道为会话制：发送期间定位被系统采信，停止发送后手机恢复自身定位，
  不具备 CoreDevice 主线的「拔线保持」语义。

重要边界（与仓库既有证据纪律一致）：
- 本文件不携带、不生成、不下载任何 MFi 凭据。身份文件（DER PKCS#7 证书
  容器 + DER PKCS#8 P-256 私钥）必须由使用者自行提供并自负授权责任；
  使用非授权身份可能违反 Apple MFi 计划条款与相关法律。
- FFFB 报文被链路 ACK 只证明送达，不证明 iOS 采信坐标；`finished` 事件中
  phone_location_verified 恒为 False，坐标采信必须按
  docs/research/iap2-accessory-location-implementation-2026-10-25.md 的
  分层验收在真机上单独证明。

协议事实来源（wire 常量与消息格式为公开协议研究结论，实现为本仓库独立
编写，未复制任何 GPL-3.0-only 项目代码）：
- JJTech0130 CarKit probe（USB lockdown 服务与 iAP2 控制会话）
- wiomoc MFi/iAP 研究、shilapi/xcertplay（控制消息与位置订阅）
- aur3l14no/accessory-location 的协议文档（消息/参数表）

用法：
    python3 src/poc/iap2_accessory_location.py probe --duration 20
    python3 src/poc/iap2_accessory_location.py send \
        --cert-file cert.p7b --key-file identity.pk8 \
        --latitude 1.2830 --longitude 103.8601 --duration 300
身份文件也可用环境变量 LOCALWARP_IAP2_CERT_FILE / LOCALWARP_IAP2_KEY_FILE 提供。
"""

import argparse
import asyncio
import json
import math
import os
import secrets
import struct
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Optional

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

CARKIT_SERVICE_NAME = "com.apple.carkit.service"

# 链路层 flags
FLAG_SYN, FLAG_ACK, FLAG_EAK, FLAG_RST = 0x80, 0x40, 0x20, 0x10

# 控制消息标识
MSG_IDENTIFY_START = 0x1D00      # 手机 → 配件：开始识别
MSG_IDENTIFY_RESPONSE = 0x1D01   # 配件 → 手机：身份与能力
MSG_IDENTIFY_ACCEPTED = 0x1D02
MSG_IDENTIFY_REJECTED = 0x1D03
MSG_AUTH_REQUEST_CERT = 0xAA00   # 手机 → 配件：请求证书
MSG_AUTH_CERTIFICATE = 0xAA01
MSG_AUTH_CHALLENGE = 0xAA02
MSG_AUTH_SIGNATURE = 0xAA03
MSG_AUTH_FAILED = 0xAA04
MSG_AUTH_SUCCEEDED = 0xAA05
MSG_LOCATION_START = 0xFFFA      # 手机 → 配件：订阅定位（参数 1=GGA 2=RMC）
MSG_LOCATION_INFORMATION = 0xFFFB
MSG_LOCATION_STOP = 0xFFFC

# 有线 CarPlay 会话（LIVI 流程；参数编码参照 xcertplay 真车实现）。
# 关键假设：手机只把"有活跃 CarPlay 会话的配件"当连续可信定位源——
# 无会话的裸定位配件仅在定位服务重初始化时被采样一次（真机实测）。
MSG_CARPLAY_AVAILABILITY = 0x4300   # 手机 → 配件：CarPlay 可用性询问
MSG_CARPLAY_START_SESSION = 0x4301  # 配件 → 手机：开始会话（有线，无需真实 AirPlay 流）
MSG_START_NOW_PLAYING_UPDATES = 0x5000       # 认证后配件主动订阅的手机侧更新
MSG_START_ROUTE_GUIDANCE_UPDATES = 0x5200
MSG_START_POWER_UPDATES = 0xAE00
MSG_START_COMMUNICATIONS_UPDATES = 0x4157
MSG_START_CALL_STATE_UPDATES = 0x4154

# LIVI 有线配件声明的能力表（混合模式：保留 LIVI 项 + 显式声明定位消息）
CARPLAY_SENT_MESSAGES = (
    MSG_LOCATION_INFORMATION,
    0x5000, 0x5002, 0x5200, 0x5203, 0xAE00, 0xAE02,
    0x4157, 0x4159, 0x4154, 0x4156, 0xAE03,
    MSG_CARPLAY_START_SESSION, 0x6800, 0x6802, 0x6803,
)
CARPLAY_RECEIVED_MESSAGES = (
    MSG_LOCATION_START, MSG_LOCATION_STOP,
    0xEA00, 0xEA01, 0x5001, 0x5201, 0x5202, 0xAE01,
    0x4158, 0x4155, MSG_CARPLAY_AVAILABILITY, 0x6801,
)

# 0x4301 有线端点参数；会话不建立真实流，手机不校验其连通性
CARPLAY_WIRED_IPV6 = "fe80::1"
CARPLAY_AIRPLAY_PORT = 7236
CARPLAY_PUBLIC_KEY_HEX = "30" * 32
CARPLAY_SOURCE_VERSION = "366.0"
CARPLAY_DEVICE_IDENTIFIER = "02:00:00:00:00:01"

# FFFA 中可选的最小发送间隔参数（32 位毫秒），0x8000 偏移对应句型 1/2
INTERVAL_PARAM_BASE = 0x8000

# 控制会话固定为 (id=1, type=0, version=2)；SYN 附带的链路参数块
CONTROL_SESSION_TRIPLET = bytes([1, 0, 2])
LINK_OFFER = struct.pack(">BBHHHBB", 1, 1, 4096, 2000, 22, 5, 1) + CONTROL_SESSION_TRIPLET

MAX_PACKET = 4096
MAX_IDENTITY_BYTES = 16 * 1024
MIN_SEND_INTERVAL = 1.0


class ProtocolError(ValueError):
    """iAP2 wire 层解析失败（帧损坏、参数越界等）。"""


class AuthenticationRequiredError(RuntimeError):
    """手机发起配件认证但本地未配置身份文件。"""


# ---------------------------------------------------------------------------
# 坐标校验（与 coredevice_location_poc.py 相同的入口约束）
# ---------------------------------------------------------------------------


def validate_coordinates(latitude: Any, longitude: Any) -> tuple[float, float]:
    if (not isinstance(latitude, (int, float)) or isinstance(latitude, bool)
            or not isinstance(longitude, (int, float)) or isinstance(longitude, bool)):
        raise ValueError("latitude and longitude must be numeric coordinates")
    lat, lon = float(latitude), float(longitude)
    if not (math.isfinite(lat) and math.isfinite(lon)):
        raise ValueError("latitude and longitude must be finite numbers")
    if not -90.0 <= lat <= 90.0:
        raise ValueError("latitude must be between -90 and 90 degrees")
    if not -180.0 <= lon <= 180.0:
        raise ValueError("longitude must be between -180 and 180 degrees")
    return lat, lon


# ---------------------------------------------------------------------------
# Wire：链路分帧与控制消息
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Packet:
    """9 字节头（含校验）+ 可选载荷（自带加法校验）。"""

    flags: int
    sequence: int
    acknowledgement: int
    session: int = 0
    payload: bytes = b""

    def encode(self) -> bytes:
        size = 9 + len(self.payload) + bool(self.payload)
        header = struct.pack(
            ">2sHBBBB", b"\xff\x5a", size,
            self.flags, self.sequence, self.acknowledgement, self.session,
        )
        frame = header + bytes([-sum(header) & 0xFF])
        if self.payload:
            frame += self.payload + bytes([-sum(self.payload) & 0xFF])
        return frame

    @classmethod
    def decode(cls, raw: bytes) -> "Packet":
        if len(raw) < 9 or raw[:2] != b"\xff\x5a":
            raise ProtocolError("Bad link marker or truncated header")
        if int.from_bytes(raw[2:4], "big") != len(raw) or sum(raw[:9]) & 0xFF:
            raise ProtocolError("Bad link length or header checksum")
        # 长度 10 表示载荷缺失校验字节，同样非法
        if len(raw) == 10 or (len(raw) > 9 and sum(raw[9:]) & 0xFF):
            raise ProtocolError("Bad link payload or checksum")
        return cls(*raw[4:8], raw[9:-1] if len(raw) > 9 else b"")


def parameter(identifier: int, data: bytes = b"") -> bytes:
    return struct.pack(">HH", len(data) + 4, identifier) + data


def parse_parameters(raw: bytes) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise ProtocolError("Truncated parameter header")
        size, identifier = struct.unpack_from(">HH", raw, offset)
        if size < 4 or offset + size > len(raw):
            raise ProtocolError("Invalid parameter length")
        result.append((identifier, raw[offset + 4:offset + size]))
        offset += size
    return result


def text_parameter(identifier: int, value: str) -> bytes:
    if "\0" in value:
        raise ValueError("Embedded NUL in protocol string")
    return parameter(identifier, value.encode("utf-8") + b"\0")


@dataclass(frozen=True)
class Message:
    """`@@` + 总长(含 6 字节头) + 标识 + TLV 参数序列。"""

    identifier: int
    body: bytes = b""

    def encode(self) -> bytes:
        return struct.pack(">2sHH", b"@@", len(self.body) + 6, self.identifier) + self.body


class MessageAssembler:
    """控制消息可能跨链路包或共享一个包，按字节流重组。"""

    def __init__(self) -> None:
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[Message]:
        self.buffer.extend(data)
        messages: list[Message] = []
        while len(self.buffer) >= 6:
            marker, size, identifier = struct.unpack_from(">2sHH", self.buffer)
            if marker != b"@@" or size < 6:
                raise ProtocolError("Invalid control message header")
            if len(self.buffer) < size:
                break
            messages.append(Message(identifier, bytes(self.buffer[6:size])))
            del self.buffer[:size]
        return messages


# ---------------------------------------------------------------------------
# NMEA 句子生成
# ---------------------------------------------------------------------------


def nmea_coordinate(value: float, latitude: bool) -> tuple[str, str]:
    limit = 90 if latitude else 180
    if not math.isfinite(value) or not -limit <= value <= limit:
        raise ValueError(f"Coordinate out of range: {value}")
    # 用整数“万分之一分”计算再拆分，避免四舍五入产出非法的 60.0000 分
    units = round(abs(value) * 60 * 10000)
    degrees, minute_units = divmod(units, 600000)
    minutes = minute_units / 10000
    hemisphere = ("S" if value < 0 else "N") if latitude else ("W" if value < 0 else "E")
    width = 2 if latitude else 3
    return f"{degrees:0{width}d}{minutes:07.4f}", hemisphere


def nmea_sentence(body: str) -> str:
    checksum = 0
    for byte in body.encode("ascii"):
        checksum ^= byte
    return f"${body}*{checksum:02X}\r\n"


def location_sentences(latitude: float, longitude: float,
                       when: Optional[datetime] = None) -> dict[int, str]:
    when = (when or datetime.now(UTC)).astimezone(UTC)
    lat, north = nmea_coordinate(latitude, True)
    lon, east = nmea_coordinate(longitude, False)
    # 亚秒精度是硬要求：整秒截断让 fix 时间天然偏旧最多 1 秒，
    # 会被 iOS locationd 的 dataAbsTimeStamp 新鲜度筛查丢弃
    # （实测 2026-10-25，iPhone XS Max / iOS 15.6.1）
    clock = when.strftime("%H%M%S") + f".{when.microsecond // 1000:03d}"
    date = when.strftime("%d%m%y")
    return {
        1: nmea_sentence(
            f"GPGGA,{clock},{lat},{north},{lon},{east},1,08,0.9,10.0,M,0.0,M,,"),
        2: nmea_sentence(
            f"GPRMC,{clock},A,{lat},{north},{lon},{east},0.0,0.0,{date},,,A"),
    }


def location_message(sentences: list[str]) -> Message:
    # 每条 NMEA 句子独占一个参数 0，含 CRLF 与 NUL 终止
    return Message(MSG_LOCATION_INFORMATION,
                   b"".join(text_parameter(0, s) for s in sentences))


# 星座仿真（PRN, 仰角, 方位, 信噪比）：8 星、强信号、全天域分布
_SIMULATED_CONSTELLATION = (
    (4, 42, 292, 44), (5, 15, 43, 38), (9, 61, 184, 41), (12, 27, 118, 35),
    (17, 68, 67, 45), (19, 21, 246, 40), (23, 84, 148, 42), (31, 25, 305, 39),
)


def supplementary_sentences() -> list[str]:
    """GSA/GSV 星座细节，随 GGA 同包发送。

    只发 GGA+RMC 时，locationd 按中等完整性处理该 fix，受 15 km
    positionDiffBound 约束（2026-10-25 实测）；携带与 GGA 卫星数/HDOP
    自洽的星座视图是商业 CarPlay 盒子的通行做法，用于抬高完整性评级。
    """
    sats = len(_SIMULATED_CONSTELLATION)
    active = ",".join(f"{prn:02d}" for prn, *_ in _SIMULATED_CONSTELLATION)
    # PDOP/HDOP/VDOP 与 GGA 的 08 星、HDOP 0.9 对齐；PRN 槽位必须占满 12 个
    gsa = nmea_sentence(
        f"GPGSA,A,3,{active},,,,,2.0,0.9,1.8")
    gsv_total = (sats + 3) // 4
    views = []
    for index in range(gsv_total):
        chunk = _SIMULATED_CONSTELLATION[index * 4:(index + 1) * 4]
        fields = ",".join(f"{prn:02d},{elevation:02d},{azimuth:03d},{snr:02d}"
                          for prn, elevation, azimuth, snr in chunk)
        views.append(nmea_sentence(f"GPGSV,{gsv_total},{index + 1},{sats},{fields}"))
    return [gsa, *views]


# ---------------------------------------------------------------------------
# 配件身份声明（0x1D01）
# ---------------------------------------------------------------------------


def identity_message(transport: str = "usb",
                     bluetooth_address: Optional[bytes] = None) -> Message:
    fields = [
        text_parameter(i, v) for i, v in enumerate(
            ("LocalWarp Lab", "LW-IAP2-1", "LocalWarp Research",
             "LW-LOCAL-001", "0.1", "1"))
    ]
    fields += [
        # 能力表：LIVI 有线配件画像（含 0x4301 会话能力），定位消息走第 22 组
        parameter(6, b"".join(struct.pack(">H", m) for m in CARPLAY_SENT_MESSAGES)),
        parameter(
            7, b"".join(struct.pack(">H", m) for m in CARPLAY_RECEIVED_MESSAGES)),
        parameter(8, b"\x02"),          # 有线配件
        parameter(9, struct.pack(">H", 20)),
        text_parameter(12, "en"),
        text_parameter(13, "en"),
    ]
    component = (parameter(0, b"\0\0")
                 + text_parameter(1, "Location Transport")
                 + parameter(2)
                 + parameter(3, b"\0"))  # CarPlay USB 接口号 0（LIVI 默认）
    if transport == "usb":
        fields.append(parameter(16, component))
    elif transport == "bluetooth":
        if bluetooth_address is None or len(bluetooth_address) != 6:
            raise ValueError("Bluetooth identity needs a six-byte controller address")
        fields.append(parameter(17, component + parameter(3, bluetooth_address)))
    else:
        raise ValueError(f"Unknown transport: {transport}")
    # HID 媒体播放组件（LIVI 画像）
    fields.append(parameter(
        18,
        parameter(0, b"\0\0")
        + text_parameter(1, "Media Playback Remote")
        + parameter(2, b"\x01")))
    # 外部配件协议声明（与消息表中的 0xea00/0xea01 配对，缺失会被拒识）
    fields.append(parameter(
        10,
        parameter(0, b"\x01")
        + text_parameter(1, "dev.localwarp.connector")
        + parameter(2, b"\0")))
    # 定位组：组件 0 + 名称 GPS + 能力槽 17/18（GGA/RMC）；不声明无线 CarPlay
    location = parameter(0, b"\0\0") + text_parameter(1, "GPS")
    fields.append(parameter(22, location + parameter(17) + parameter(18)))
    return Message(MSG_IDENTIFY_RESPONSE, b"".join(fields))


def carplay_start_session_message() -> Message:
    """0x4301 CarPlayStartSession（有线）：声明端点但不建立任何流。"""
    wired = text_parameter(0, CARPLAY_WIRED_IPV6)
    fields = [
        parameter(0, wired),
        parameter(2, struct.pack(">I", CARPLAY_AIRPLAY_PORT)),
        text_parameter(3, CARPLAY_DEVICE_IDENTIFIER),
        text_parameter(4, CARPLAY_PUBLIC_KEY_HEX),
        text_parameter(5, CARPLAY_SOURCE_VERSION),
    ]
    return Message(MSG_CARPLAY_START_SESSION, b"".join(fields))


def bringup_subscriptions() -> list[Message]:
    """认证成功后按 LIVI 流程订阅手机侧更新（媒体/导航/电源/通信/通话）。"""
    now_playing = (
        parameter(0, b"".join(parameter(i) for i in (1, 4, 6, 12, 26)))
        + parameter(1, b"".join(parameter(i) for i in (0, 1, 2, 3, 7)))
    )
    return [
        Message(MSG_START_NOW_PLAYING_UPDATES, now_playing),
        Message(MSG_START_ROUTE_GUIDANCE_UPDATES, b""),
        Message(MSG_START_POWER_UPDATES,
                b"".join(parameter(i) for i in (4, 5, 6))),
        Message(MSG_START_COMMUNICATIONS_UPDATES,
                b"".join(parameter(i) for i in (0, 4, 5))),
        Message(MSG_START_CALL_STATE_UPDATES,
                b"".join(parameter(i) for i in (0, 1, 2, 3, 4, 11))),
    ]


# ---------------------------------------------------------------------------
# 本地 MFi-v3 身份（用户自备；仓库不携带凭据）
# ---------------------------------------------------------------------------


def _der_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 2 > len(data):
        raise ValueError
    tag, size = data[offset:offset + 2]
    offset += 2
    if size & 0x80:
        count = size & 0x7F
        if not 1 <= count <= 4 or offset + count > len(data):
            raise ValueError
        size = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + size
    if end > len(data):
        raise ValueError
    return tag, offset, end


def _looks_like_pkcs8_der(data: bytes) -> bool:
    # PKCS#8：SEQ { INTEGER version, SEQ algorithm, OCTET STRING key }
    try:
        tag, pos, end = _der_tlv(data, 0)
        if tag != 0x30 or end != len(data):
            return False
        tag, _, after = _der_tlv(data, pos)      # version INTEGER
        if tag != 0x02:
            return False
        tag, _, after = _der_tlv(data, after)    # algorithm SEQUENCE
        if tag != 0x30:
            return False
        tag, _, _ = _der_tlv(data, after)        # privateKey OCTET STRING
        return tag == 0x04
    except (ValueError, IndexError):
        return False


class IdentityError(RuntimeError):
    """身份文件缺失、格式不符或证书/私钥不匹配。"""


class LocalMfiIdentity:
    """从调用方提供的文件加载 MFi-v3 身份并执行挑战签名。

    只做结构与密钥一致性校验；不校验 Apple 信任链、授权或吊销状态，
    也不做任何网络/USB/设备操作。授权与合规责任由身份提供者承担。
    """

    def __init__(self, certificate_der: bytes, private_key_der: bytes) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization.pkcs7 import (
            load_der_pkcs7_certificates,
        )

        for data in (certificate_der, private_key_der):
            if not data or len(data) > MAX_IDENTITY_BYTES:
                raise IdentityError(
                    f"Identity files must contain 1..{MAX_IDENTITY_BYTES} bytes")
        try:
            certificates = load_der_pkcs7_certificates(certificate_der)
        except (ValueError, TypeError):
            raise IdentityError("Certificate must be a DER PKCS#7 container") from None
        if not certificates:
            raise IdentityError("PKCS#7 container has no certificates")
        if not _looks_like_pkcs8_der(private_key_der):
            raise IdentityError("Private key must be unencrypted DER PKCS#8")
        try:
            key = serialization.load_der_private_key(private_key_der, password=None)
        except (ValueError, TypeError):
            raise IdentityError("Private key must be unencrypted DER PKCS#8") from None
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
                key.curve, ec.SECP256R1):
            raise IdentityError("Private key must use P-256")
        matching = 0
        for cert in certificates:
            try:
                if cert.extensions.get_extension_for_class(
                        x509.BasicConstraints).value.ca:
                    continue
            except x509.ExtensionNotFound:
                pass
            public = cert.public_key()
            if (isinstance(public, ec.EllipticCurvePublicKey)
                    and isinstance(public.curve, ec.SECP256R1)
                    and public.public_numbers() == key.public_key().public_numbers()):
                matching += 1
        if matching != 1:
            raise IdentityError(
                "Private key must match exactly one non-CA leaf certificate")
        self._key = key
        self._x509 = x509
        self._serialization = serialization
        self._ec = ec
        self.certificate_der = certificate_der

    @classmethod
    def from_files(cls, certificate_path: str, key_path: str) -> "LocalMfiIdentity":
        def read(path: str, label: str) -> bytes:
            try:
                data = Path(path).read_bytes()
            except OSError:
                raise IdentityError(f"Cannot read {label}: {path}") from None
            if not data or len(data) > MAX_IDENTITY_BYTES:
                raise IdentityError(
                    f"{label} must contain 1..{MAX_IDENTITY_BYTES} bytes")
            return data
        return cls(read(certificate_path, "certificate file"),
                   read(key_path, "private key file"))

    def certificate_message(self) -> Message:
        return Message(MSG_AUTH_CERTIFICATE, parameter(0, self.certificate_der))

    def signature_message(self, challenge: bytes) -> Message:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import utils

        if len(challenge) != 32:
            raise ProtocolError("MFi v3 requires exactly 32 challenge bytes")
        der = self._key.sign(
            challenge, self._ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return Message(MSG_AUTH_SIGNATURE, parameter(0, raw))


# ---------------------------------------------------------------------------
# USB 传输：pymobiledevice3 lockdown → com.apple.carkit.service
# ---------------------------------------------------------------------------


class LockdownCarkitStream:
    """把 pymobiledevice3 的 carkit 服务连接适配为 async 字节流。

    仅 USB；Bluetooth 桥为参考实现中的实验特性，本 PoC 不实现。
    """

    def __init__(self, client: Any, service: Any) -> None:
        self._client = client
        self._service = service

    @classmethod
    async def open(cls, udid: Optional[str] = None) -> "LockdownCarkitStream":
        from pymobiledevice3.lockdown import create_using_usbmux

        # udid 缺省时 usbmux 取第一台 USB 设备；多设备并存时必须显式指定
        client = await create_using_usbmux(
            serial=udid, connection_type="USB", autopair=False)
        service = await client.start_lockdown_service(CARKIT_SERVICE_NAME)
        return cls(client, service)

    @property
    def device_info(self) -> dict:
        """USB 上实际设备的标识（取自 lockdown），与任何请求参数无关。"""
        values = getattr(self._client, "all_values", None) or {}
        return {
            "udid": getattr(self._client, "udid", None),
            "product_type": values.get("ProductType"),
            "product_version": values.get("ProductVersion"),
        }

    async def recvall(self, size: int) -> bytes:
        return await self._service.recvall(size)

    async def sendall(self, data: bytes) -> None:
        await self._service.sendall(data)

    async def close(self) -> None:
        for obj, candidates in ((self._service, ("aclose", "close")),
                                (self._client, ("aio_close", "aclose", "close"))):
            for name in candidates:
                closer = getattr(obj, name, None)
                if closer is None:
                    continue
                result = closer()
                if asyncio.iscoroutine(result):
                    await result
                break


# ---------------------------------------------------------------------------
# iAP2 链路：停等 ARQ
# ---------------------------------------------------------------------------


class Iap2Link:
    """单包在途的停等链路；未实现选择重传窗口与文件传输会话。"""

    def __init__(self, stream: Any,
                 emit: Callable[..., None] = lambda **_: None) -> None:
        self.stream = stream
        self.emit = emit
        self.sequence = secrets.randbelow(256)
        self.peer_sequence = 0
        self.session = 1
        self.maximum_packet = MAX_PACKET
        self.retransmit_seconds = 2.0
        self.messages: list[Message] = []
        self.assembler = MessageAssembler()
        self._reader: Optional[asyncio.Task] = None

    async def _read_packet(self) -> Packet:
        header = await self.stream.recvall(9)
        size = int.from_bytes(header[2:4], "big")
        if (header[:2] != b"\xff\x5a" or sum(header) & 0xFF
                or not 9 <= size <= MAX_PACKET):
            raise ProtocolError("Malformed or oversized incoming packet")
        body = await self.stream.recvall(size - 9) if size > 9 else b""
        return Packet.decode(header + body)

    async def _read(self, timeout: float) -> Packet:
        # 读任务跨调用超时存活，半包状态不丢失
        if self._reader is None:
            self._reader = asyncio.create_task(self._read_packet())
        try:
            return await asyncio.wait_for(asyncio.shield(self._reader), timeout)
        except TimeoutError:
            raise
        finally:
            if self._reader.done():
                self._reader = None

    async def _write(self, packet: Packet) -> None:
        await self.stream.sendall(packet.encode())

    async def acknowledge(self) -> None:
        await self._write(Packet(FLAG_ACK, self.sequence, self.peer_sequence))

    async def handshake(self) -> None:
        syn = Packet(FLAG_SYN, self.sequence, 0, payload=LINK_OFFER)
        for _ in range(3):
            await self._write(syn)
            try:
                response = await self._read(2.0)
            except TimeoutError:
                continue
            if response.flags & (FLAG_SYN | FLAG_ACK) != (FLAG_SYN | FLAG_ACK):
                raise ProtocolError("Expected SYN+ACK")
            if (response.acknowledgement != self.sequence
                    or len(response.payload) < 13):
                raise ProtocolError("Invalid handshake acknowledgement or parameters")
            version, window, size, retry, _, _, _ = struct.unpack(
                ">BBHHHBB", response.payload[:10])
            sessions = response.payload[10:]
            if version != 1 or window < 1 or size < 10 or len(sessions) % 3:
                raise ProtocolError("Unsupported link parameters")
            offered = [sessions[i:i + 3] for i in range(0, len(sessions), 3)]
            if CONTROL_SESSION_TRIPLET not in offered:
                raise ProtocolError("Peer did not accept control session 1 version 2")
            self.maximum_packet = min(size, MAX_PACKET)
            self.retransmit_seconds = max(retry / 1000, 0.1)
            self.peer_sequence = response.sequence
            await self.acknowledge()
            self.emit(event="link_ready", control_session=self.session)
            return
        raise TimeoutError("No iAP2 SYN acknowledgement")

    async def accept(self, packet: Packet) -> None:
        if packet.flags & FLAG_RST:
            raise ConnectionError("Peer reset the iAP2 link")
        if packet.flags & FLAG_SYN:
            # 我方握手收尾 ACK 丢失时对端会重发 SYN+ACK
            if packet.sequence != self.peer_sequence:
                raise ProtocolError("Unexpected new SYN during established link")
            await self.acknowledge()
            return
        if packet.payload and not packet.flags & FLAG_EAK:
            if packet.sequence == (self.peer_sequence + 1) & 0xFF:
                self.peer_sequence = packet.sequence
                if packet.session != self.session:
                    raise ProtocolError("Data on an unnegotiated session")
                self.messages.extend(self.assembler.feed(packet.payload))
            # 重复或乱序：只确认最后连续序号，绝不重复投递
            await self.acknowledge()

    async def send(self, message: Message) -> None:
        raw = message.encode()
        chunk = self.maximum_packet - 10
        for offset in range(0, len(raw), chunk):
            self.sequence = (self.sequence + 1) & 0xFF
            payload = raw[offset:offset + chunk]
            acknowledged = False
            for attempt in range(4):
                await self._write(Packet(
                    FLAG_ACK, self.sequence, self.peer_sequence,
                    self.session, payload))
                deadline = asyncio.get_running_loop().time() + self.retransmit_seconds
                while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
                    try:
                        packet = await self._read(remaining)
                    except TimeoutError:
                        break
                    await self.accept(packet)
                    if (packet.flags & FLAG_ACK
                            and packet.acknowledgement == self.sequence):
                        acknowledged = True
                        break
                if acknowledged:
                    break
                self.emit(event="retransmit", attempt=attempt + 1)
            if not acknowledged:
                raise TimeoutError("Peer did not acknowledge data")

    async def receive(self, timeout: float = 10.0) -> Message:
        deadline = asyncio.get_running_loop().time() + timeout
        while not self.messages:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("No control message before deadline")
            await self.accept(await self._read(remaining))
        return self.messages.pop(0)

    async def close(self) -> None:
        if self._reader is not None:
            self._reader.cancel()
            await asyncio.gather(self._reader, return_exceptions=True)
            self._reader = None
        await self.stream.close()


# ---------------------------------------------------------------------------
# 会话状态机：识别 → 认证 → 订阅 → 定期发送
# ---------------------------------------------------------------------------


@dataclass
class SessionSummary:
    identified: bool = False
    authenticated: bool = False
    location_packets_acknowledged: int = 0
    phone_location_verified: bool = False


@dataclass
class LocationTarget:
    """可变定位目标：会话运行期间修改字段即实现热更新（连接器 update 接口依赖此语义）。"""
    latitude: float
    longitude: float


class AccessoryLocationSession:
    """单次配件会话；结束后由调用方负责重连。"""

    def __init__(self, link: Iap2Link,
                 identity: Optional[LocalMfiIdentity],
                 emit: Callable[..., None] = lambda **_: None) -> None:
        self.link = link
        self.identity = identity
        self.emit = emit

    async def run(self, latitude: Optional[float] = None,
                  longitude: Optional[float] = None, *,
                  send: bool = True, duration: float = 60.0,
                  interval: float = 1.0,
                  target: Optional[LocationTarget] = None) -> SessionSummary:
        summary = SessionSummary()
        active: set[int] = set()
        peer_intervals: dict[int, float] = {}
        last_sent: dict[int, float] = {}
        bringup_sent = False
        carplay_sessions_started = 0
        if target is None:
            if send:
                if latitude is None or longitude is None:
                    raise ValueError("send mode requires latitude and longitude")
                validate_coordinates(latitude, longitude)
            target = LocationTarget(latitude or 0.0, longitude or 0.0)
        else:
            validate_coordinates(target.latitude, target.longitude)
        deadline = asyncio.get_running_loop().time() + duration
        try:
            while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
                message: Optional[Message] = None
                try:
                    message = await self.link.receive(min(0.25, remaining))
                except TimeoutError:
                    pass
                except (EOFError, ConnectionError):
                    # 对端关闭链路（拔线/重启）＝会话结束，按已完成状态返回
                    self.emit(event="link_closed")
                    return summary
                if message is not None:
                    fields = parse_parameters(message.body)
                    if message.identifier == MSG_IDENTIFY_START:
                        await self.link.send(identity_message("usb"))
                    elif message.identifier == MSG_IDENTIFY_ACCEPTED:
                        summary.identified = True
                        self.emit(event="identification_accepted")
                    elif message.identifier == MSG_IDENTIFY_REJECTED:
                        raise RuntimeError(
                            f"Identification rejected: {[i for i, _ in fields]}")
                    elif message.identifier == MSG_AUTH_REQUEST_CERT:
                        if self.identity is None:
                            raise AuthenticationRequiredError(
                                "Phone requested accessory authentication; "
                                "no local identity configured")
                        await self.link.send(self.identity.certificate_message())
                    elif message.identifier == MSG_AUTH_CHALLENGE:
                        if self.identity is None:
                            raise AuthenticationRequiredError(
                                "Phone requested accessory authentication; "
                                "no local identity configured")
                        challenges = [b for i, b in fields if i == 0]
                        if len(challenges) != 1:
                            raise RuntimeError(
                                "Invalid authentication challenge parameters")
                        await self.link.send(
                            self.identity.signature_message(challenges[0]))
                    elif message.identifier == MSG_AUTH_SUCCEEDED:
                        summary.authenticated = True
                        self.emit(event="authentication_succeeded")
                        # LIVI 有线握手：认证后订阅手机侧更新，
                        # 让手机把本配件视为完整车机而非裸定位设备
                        if not bringup_sent:
                            bringup_sent = True
                            for subscription in bringup_subscriptions():
                                await self.link.send(subscription)
                            self.emit(event="carplay_bringup_sent")
                    elif message.identifier == MSG_AUTH_FAILED:
                        raise RuntimeError("Accessory authentication failed")
                    elif message.identifier == MSG_CARPLAY_AVAILABILITY:
                        # 与真车一致：每次可用性询问都回开始会话。
                        # LOCALWARP_IAP2_CARPLAY_SESSION=0 用于对照实验（只画像不开会话）
                        if os.environ.get("LOCALWARP_IAP2_CARPLAY_SESSION", "1") != "0":
                            await self.link.send(carplay_start_session_message())
                            carplay_sessions_started += 1
                            self.emit(event="carplay_session_started",
                                      count=carplay_sessions_started)
                        else:
                            self.emit(event="carplay_availability_ignored")
                    elif message.identifier == MSG_LOCATION_START:
                        active = {i for i, b in fields if i in (1, 2) and not b}
                        peer_intervals = {
                            i - INTERVAL_PARAM_BASE: max(MIN_SEND_INTERVAL,
                                                         int.from_bytes(b, "big") / 1000)
                            for i, b in fields
                            if i in (INTERVAL_PARAM_BASE + 1, INTERVAL_PARAM_BASE + 2)
                            and len(b) == 4}
                        last_sent.clear()
                        self.emit(event="location_requested",
                                  sentences=sorted(active),
                                  intervals=peer_intervals)
                    elif message.identifier == MSG_LOCATION_STOP:
                        active.clear()
                        self.emit(event="location_stopped")
                if send and summary.identified and summary.authenticated and active:
                    now = asyncio.get_running_loop().time()
                    due = sorted(
                        i for i in active
                        if now - last_sent.get(i, -math.inf)
                        >= max(interval, peer_intervals.get(i, MIN_SEND_INTERVAL)))
                    if due:
                        # 每次发送前重新读取并校验目标：支持运行中热更新坐标
                        validate_coordinates(target.latitude, target.longitude)
                        sentences = location_sentences(target.latitude, target.longitude)
                        payload = [sentences[i] for i in due]
                        if 1 in due:
                            # GGA 在发时附带星座细节（GSA/GSV）抬高完整性评级
                            payload += supplementary_sentences()
                        await self.link.send(location_message(payload))
                        last_sent.update({i: now for i in due})
                        summary.location_packets_acknowledged += 1
                        if (summary.location_packets_acknowledged == 1
                                or summary.location_packets_acknowledged % 10 == 0):
                            self.emit(
                                event="location_link_acknowledged",
                                count=summary.location_packets_acknowledged)
            return summary
        finally:
            self.emit(event="finished",
                      identified=summary.identified,
                      authenticated=summary.authenticated,
                      location_packets_acknowledged=(
                          summary.location_packets_acknowledged),
                      # 链路 ACK 只证明送达；坐标采信必须由真机验收另行证明
                      phone_location_verified=summary.phone_location_verified)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _emit_json(**event: Any) -> None:
    print(json.dumps(event, ensure_ascii=False), flush=True)


def _resolve_identity(args: argparse.Namespace) -> Optional[LocalMfiIdentity]:
    cert = args.cert_file or os.environ.get("LOCALWARP_IAP2_CERT_FILE")
    key = args.key_file or os.environ.get("LOCALWARP_IAP2_KEY_FILE")
    if not cert and not key:
        return None
    if not cert or not key:
        raise IdentityError("Both certificate and private key files are required")
    return LocalMfiIdentity.from_files(cert, key)


async def _run(args: argparse.Namespace) -> None:
    stream = None
    link = None
    try:
        stream = await LockdownCarkitStream.open()
        _emit_json(event="device_connected", transport="usb")
        link = Iap2Link(stream, _emit_json)
        await link.handshake()
        identity = _resolve_identity(args)
        session = AccessoryLocationSession(link, identity, _emit_json)
        summary = await session.run(
            args.latitude if args.command == "send" else None,
            args.longitude if args.command == "send" else None,
            send=args.command == "send",
            duration=args.duration,
            interval=getattr(args, "interval", 1.0))
        if args.command == "send" and not summary.authenticated:
            _emit_json(event="warning",
                       detail="session ended before authentication succeeded")
    finally:
        if link is not None:
            await link.close()
        elif stream is not None:
            await stream.close()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Experimental iAP2 accessory-location client (USB only)")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("probe", "send"):
        command = commands.add_parser(name)
        command.add_argument("--cert-file", help="DER PKCS#7 certificate container")
        command.add_argument("--key-file", help="unencrypted DER PKCS#8 P-256 key")
        command.add_argument("--duration", type=float,
                             default=20.0 if name == "probe" else 60.0)
        if name == "send":
            command.add_argument("--latitude", type=float, required=True)
            command.add_argument("--longitude", type=float, required=True)
            command.add_argument("--interval", type=float, default=1.0)
    args = parser.parse_args(argv)
    if not math.isfinite(args.duration) or not 0 < args.duration <= 3600:
        parser.error("duration must be between 0 and 3600 seconds")
    if args.command == "send":
        try:
            validate_coordinates(args.latitude, args.longitude)
            if not math.isfinite(args.interval) or args.interval < MIN_SEND_INTERVAL:
                raise ValueError(
                    f"interval must be at least {MIN_SEND_INTERVAL:.0f} second")
        except ValueError as error:
            parser.error(str(error))
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        _emit_json(event="interrupted")
    except Exception as error:  # noqa: BLE001 - CLI 边界统一输出结构化错误
        _emit_json(event="error", type=type(error).__name__, detail=str(error))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
