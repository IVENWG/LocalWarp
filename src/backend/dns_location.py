"""连接器内置的 DNS 劫持定位通道（软件模拟定位，零手机侧安装）。

真机实测结论（2026-10-25，iPhone 14 Pro Max / iOS 26.6.1，详见
docs/research/enhanced-location-acceptance-2026-10-25.md 第四轮）：

- iOS 的系统定位进程 locationd 不查阅 Wi-Fi 手动/PAC 代理设置，但使用系统
  解析器；把手机 Wi-Fi 的 DNS 指向连接器后，两个 Apple 定位域名的查询会被
  本模块应答为连接器自身，定位流量因此在 443 端口被现有 wloc CA 终结。
- 首次生效存在 2–6 分钟“一致应答学习窗口”，之后 locationd 缓存命中即即时
  生效；开关一次定位服务可加速。不需要飞行模式。
- 苹果真实服务器对转发的手机请求一律返回 400（存在请求指纹校验），因此本
  通道只回合成应答，不做上游转发。

TLS 采用 MemoryBIO 手动握手 + ClientHello SNI 解析：不依赖各解释器
sni_callback 行为差异（部分构建不支持回调返回上下文），Mac/Windows 表现一致。

安全边界：rewrite 只改写 HIJACK_HOSTS 两个域名；suppress 仅匹配
SUPPRESS_HOSTS 中显式列出的定位端点，其余查询原样转发上游，
不解析、不记录；443 仅接受 SNI 为劫持域名的 TLS，仅响应 POST /clls/wloc。
端口 53/443 在 Unix 上为特权端口，产品化由安装期的特权助手持有；
测试可用构造参数改用高位端口。
"""
import asyncio
from collections import OrderedDict
import ipaddress
import math
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    from wloc_proxy import (HOSTS, CertificateStore, build_response,  # noqa: F401
                            field as pb_field, fields as pb_fields)
except ImportError:
    from src.backend.wloc_proxy import (HOSTS, CertificateStore,
                                        build_response,
                                        field as pb_field,
                                        fields as pb_fields)

HIJACK_HOSTS = HOSTS


# Explicit DNS names observed alongside renewed external reference fixes on the
# iOS 27.2 test device. This is a working test policy, not a proven minimum set.
SUPPRESS_HOSTS = frozenset(HIJACK_HOSTS) | frozenset({
    'cl2.apple.com', 'cl2-cn.apple.com', 'cl3.apple.com',
    'cl4.apple.com', 'cl4-cn.apple.com', 'iphone-ld.apple.com',
    'cl2-cdn-cn.origin-apple.com.akadns.net',
    'cl3-cn.origin-apple.com.akadns.net',
    'cl2-cn.apple.com.w.cdngslb.com',
})


def is_suppressed_domain(name: str) -> bool:
    """Match observed location endpoints exactly; preserve other map services."""
    return name.lower().rstrip('.') in SUPPRESS_HOSTS


STEPS = ['download_ca', 'trust_ca', 'configure_dns', 'verify_maps']
SUPPRESS_STEPS = ['configure_dns', 'toggle_location', 'verify_maps']
MAX_BODY = 256 * 1024
FALLBACK_UPSTREAMS = ('223.5.5.5', '119.29.29.29')


def constraint_text(mode='rewrite'):
    if mode == 'suppress':
        return ('Start the USB accessory session, set Wi-Fi DNS to this computer, '
                'enable Airplane Mode with Wi-Fi on, then toggle Location Services once. '
                'Verify DNS queries and suppression counters. Cached references and GNSS can still '
                'reject accessory fixes; far-distance adoption is not guaranteed. '
                'Restore DNS to Automatic and disable Airplane Mode when finished.')
    return ('Set the phone Wi-Fi DNS to this computer, trust the LocalWarp CA, '
            'then toggle Location Services once. Verified on iOS 26.6.1: the '
            'blue dot adopts the target after a 2-6 minute learning window of '
            'consistent answers and stays (cached, zero further queries); '
            'no airplane mode needed. Restore DNS to Automatic to revert. '
            'Ports 53/443 need elevation on macOS; not on Windows.')


def normalize_upstream(upstream) -> Tuple[str, int]:
    """标准化上游地址格式为 ('ip', port)。"""
    if isinstance(upstream, tuple) and len(upstream) == 2:
        return (str(upstream[0]), int(upstream[1]))
    if isinstance(upstream, str) and ':' in upstream:
        host, port = upstream.rsplit(':', 1)
        try:
            return (host, int(port))
        except ValueError:
            pass
    return (str(upstream), 53)


def discover_system_nameservers(lan_ip=None, local_port=53) -> Tuple[str, ...]:
    """跨平台可靠发现系统有效 DNS，排除回环、本机地址并兜底。"""
    servers = []

    # 1. macOS: 优先查询 scutil --dns 获取经过配置的有效 Nameserver
    if sys.platform == 'darwin':
        try:
            res = subprocess.run(['scutil', '--dns'], capture_output=True, text=True, timeout=1.5)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    line = line.strip()
                    m = re.match(r'nameserver\[\d+\]\s*:\s*([0-9a-fA-F\.\:]+)', line)
                    if m:
                        ip_str = m.group(1)
                        try:
                            ip = ipaddress.ip_address(ip_str)
                            if ip.version == 4 and not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified:
                                servers.append(str(ip))
                        except ValueError:
                            pass
        except Exception:
            pass

    # 2. Windows: 优先通过 powershell 查询活动网络适配器的 DNS
    elif sys.platform == 'win32':
        try:
            res = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses'],
                capture_output=True, text=True, timeout=2.0)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    ip_str = line.strip()
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        if ip.version == 4 and not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified:
                            servers.append(str(ip))
                    except ValueError:
                        pass
        except Exception:
            pass

    # 3. 回退读取 /etc/resolv.conf
    if not servers:
        try:
            for line in Path('/etc/resolv.conf').read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == 'nameserver':
                    address = parts[1]
                    try:
                        parsed = ipaddress.ip_address(address)
                        if parsed.version == 4 and not parsed.is_loopback and not parsed.is_link_local and not parsed.is_unspecified:
                            servers.append(address)
                    except ValueError:
                        continue
        except OSError:
            pass

    # 防环机制：排除本机 LAN IP、回环及自身监听端口
    filtered = []
    for s in dict.fromkeys(servers):
        if lan_ip and s == lan_ip:
            continue
        filtered.append(s)

    # 保留公共上游作为后备兜底（保持优先级：系统DNS优先，再公共兜底）
    combined = list(dict.fromkeys(filtered + list(FALLBACK_UPSTREAMS)))
    return tuple(combined)


def system_nameservers():
    """向后兼容接口：获取当前系统解析器。"""
    return discover_system_nameservers()


def parse_dns_ttls(data: bytes, qend: int) -> Tuple[Optional[int], List[int]]:
    """解析 Answer 节的最小 TTL 及各 Answer 记录中 TTL 字段在字节流中的偏移量。

    遵守 RFC 1035 / RFC 2181 / RFC 2308：
    - 若出现截断标志 (TC=1) 或 SERVFAIL/FORMERR，返回 (None, []) 表示不可缓存。
    - 若为负应答 (NXDOMAIN 或 NODATA)，返回默认负缓存 TTL 15s。
    - 若有有效 Answer，返回最小 TTL (范围限制 5s ~ 3600s) 及所有 TTL 字节偏移。
    """
    if len(data) < 12:
        return None, []
    flags, qdcount, ancount = struct.unpack('>HHH', data[2:8])
    rcode = flags & 0x0F
    is_truncated = bool(flags & 0x0200)
    if is_truncated or rcode in (1, 2, 4, 5):
        return None, []
    if ancount == 0:
        return 15, []

    pos = qend
    ttls = []
    offsets = []
    data_len = len(data)
    try:
        for _ in range(ancount):
            if pos >= data_len:
                return None, []
            # 跳过 NAME
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while pos < data_len and data[pos] != 0:
                    if data[pos] & 0xC0 == 0xC0:
                        pos += 2
                        break
                    pos += 1 + data[pos]
                else:
                    pos += 1
            if pos + 10 > data_len:
                return None, []
            rr_type, rr_class, rr_ttl, rdlength = struct.unpack('>HHIH', data[pos:pos+10])
            offsets.append(pos + 4)
            ttls.append(rr_ttl)
            pos += 10 + rdlength
        if not ttls:
            return None, []
        min_ttl = max(5, min(min(ttls), 3600))
        return min_ttl, offsets
    except Exception:
        return None, []


class DnsCacheEntry:
    __slots__ = ('payload', 'expire_at', 'ttl_offsets', 'min_ttl', 'is_negative')

    def __init__(self, payload: bytes, expire_at: float, ttl_offsets: List[int],
                 min_ttl: int, is_negative: bool = False):
        self.payload = payload
        self.expire_at = expire_at
        self.ttl_offsets = ttl_offsets
        self.min_ttl = min_ttl
        self.is_negative = is_negative


class DnsCache:
    """轻量级、有容量上限的内存 DNS TTL 缓存。"""

    def __init__(self, max_entries: int = 2048):
        self.max_entries = max_entries
        self.entries: OrderedDict[Tuple[str, int, int], DnsCacheEntry] = OrderedDict()
        self.hits: int = 0
        self.misses: int = 0

    def get(self, query: bytes, name: str, qtype: int, qclass: int) -> Optional[bytes]:
        key = (name.lower().rstrip('.'), qtype, qclass)
        entry = self.entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        now = time.monotonic()
        if entry.expire_at <= now:
            del self.entries[key]
            self.misses += 1
            return None

        self.entries.move_to_end(key)
        self.hits += 1

        remaining_ttl = max(1, int(entry.expire_at - now))
        reply = bytearray(entry.payload)
        # 严格替换为当前请求的 Transaction ID，绝不冲突
        reply[:2] = query[:2]
        # 动态更新各 Answer RR 的剩余 TTL，避免下游 TTL 膨胀
        for off in entry.ttl_offsets:
            if off + 4 <= len(reply):
                reply[off:off+4] = struct.pack('>I', remaining_ttl)
        return bytes(reply)

    def set(self, name: str, qtype: int, qclass: int, response: bytes, qend: int):
        clean_name = name.lower().rstrip('.')
        # 红线防守：定位劫持与抑制域名绝对不能进入普通缓存
        if is_suppressed_domain(clean_name) or clean_name in HIJACK_HOSTS:
            return

        min_ttl, offsets = parse_dns_ttls(response, qend)
        if min_ttl is None:
            return

        key = (clean_name, qtype, qclass)
        now = time.monotonic()
        expire_at = now + min_ttl

        if len(self.entries) >= self.max_entries:
            self.entries.popitem(last=False)

        self.entries[key] = DnsCacheEntry(
            payload=response,
            expire_at=expire_at,
            ttl_offsets=offsets,
            min_ttl=min_ttl,
            is_negative=(offsets == []),
        )

    def clear(self):
        self.entries.clear()

    def __len__(self):
        return len(self.entries)


class UpstreamUdpClient(asyncio.DatagramProtocol):
    """复用单个 UDP Socket 的上游解析客户端，消除每次查询创建 Socket 的系统开销。"""

    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._pending: Dict[Tuple[str, int, int], Tuple[asyncio.Future, Optional[bytes]]] = {}
        self._next_id: int = random.randint(1, 1000)

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if len(data) < 2:
            return
        txid = struct.unpack('>H', data[:2])[0]
        # 1. 尝试精确匹配 (addr, port, txid)
        key = (addr[0], addr[1], txid)
        entry = self._pending.pop(key, None)
        if entry:
            fut, orig_txid = entry
            if not fut.done():
                resp = (orig_txid + data[2:]) if orig_txid else data
                fut.set_result(resp)
            return

        # 2. 回退匹配（针对非标准 DNS 测试 mock 或无 ID 回显的上游）
        fallback_key = next((k for k in self._pending if k[0] == addr[0] and k[1] == addr[1]), None)
        if fallback_key:
            fut, _ = self._pending.pop(fallback_key)
            if not fut.done():
                fut.set_result(data)

    def error_received(self, error: Exception):
        pass

    async def query_one(self, remote: Tuple[str, int], query: bytes,
                        timeout: float = 2.0) -> Optional[bytes]:
        if not self.transport or self.transport.is_closing():
            return None
        loop = asyncio.get_running_loop()

        orig_txid = query[:2]
        orig_id_int = struct.unpack('>H', orig_txid)[0]
        primary_key = (remote[0], remote[1], orig_id_int)

        if primary_key not in self._pending:
            # 无冲突：原样发包
            fut = loop.create_future()
            self._pending[primary_key] = (fut, None)
            out_packet = query
            assigned_key = primary_key
        else:
            # 存在并发相同 ID：分配内部隔离 ID
            for _ in range(200):
                txid = self._next_id
                self._next_id = (self._next_id % 65535) + 1
                key = (remote[0], remote[1], txid)
                if key not in self._pending:
                    break
            else:
                return None
            fut = loop.create_future()
            self._pending[key] = (fut, orig_txid)
            out_packet = struct.pack('>H', txid) + query[2:]
            assigned_key = key

        try:
            self.transport.sendto(out_packet, remote)
            return await asyncio.wait_for(fut, timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            return None
        finally:
            self._pending.pop(assigned_key, None)

    def close(self):
        if self.transport and not self.transport.is_closing():
            self.transport.close()
            self.transport = None
        for fut, _ in list(self._pending.values()):
            if not fut.done():
                fut.cancel()
        self._pending.clear()


class UpstreamManager:
    """管理上游 DNS 地址、自动发现与快速故障转移。"""

    def __init__(self, initial_upstreams=None, lan_ip=None, local_port=53):
        self.lan_ip = lan_ip
        self.local_port = local_port
        self._manual_upstreams = (
            [normalize_upstream(u) for u in initial_upstreams]
            if initial_upstreams else None)
        self._discovered: Tuple[Tuple[str, int], ...] = ()
        self._last_discovery: float = 0.0
        self._failures: Dict[Tuple[str, int], Tuple[int, float]] = {}

    def refresh(self, force: bool = False):
        now = time.monotonic()
        if (force or self._manual_upstreams is None) and (
                now - self._last_discovery > 60.0 or not self._discovered):
            raw = discover_system_nameservers(lan_ip=self.lan_ip, local_port=self.local_port)
            self._discovered = tuple(normalize_upstream(u) for u in raw)
            self._last_discovery = now

    def get_ordered_upstreams(self) -> List[Tuple[str, int]]:
        self.refresh()
        base = (self._manual_upstreams if self._manual_upstreams is not None
                else list(self._discovered))
        now = time.monotonic()
        healthy = []
        penalized = []
        for u in base:
            fails, penalty_until = self._failures.get(u, (0, 0.0))
            if now < penalty_until:
                penalized.append(u)
            else:
                healthy.append(u)
        return healthy + penalized

    def record_success(self, upstream: Tuple[str, int]):
        self._failures.pop(upstream, None)

    def record_failure(self, upstream: Tuple[str, int]):
        now = time.monotonic()
        fails, _ = self._failures.get(upstream, (0, 0.0))
        fails += 1
        penalty = (now + 30.0) if fails >= 2 else 0.0
        self._failures[upstream] = (fails, penalty)


# ---------------------------------------------------------------------------
# DNS：报文构造与解析（纯函数，便于测试）
# ---------------------------------------------------------------------------

def parse_question(data):
    """解析单问题查询；返回 (name, qtype, qclass, question_end) 或 None。"""
    if len(data) < 12:
        return None
    if struct.unpack('>H', data[4:6])[0] != 1:
        return None
    pos, labels = 12, []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 or pos + 1 + length > len(data):
            return None
        labels.append(data[pos + 1:pos + 1 + length])
        pos += 1 + length
    if pos + 4 > len(data):
        return None
    qtype, qclass = struct.unpack('>HH', data[pos:pos + 4])
    name = '.'.join(part.decode('ascii', 'ignore').lower() for part in labels)
    return name, qtype, qclass, pos + 4


def dns_answer(query, question_end, rcode=0, answers=()):
    question = query[12:question_end]
    header = query[:2] + struct.pack('>HHHHH', 0x8580 | rcode, 1,
                                     len(answers), 0, 0)
    return header + question + b''.join(answers)


def hijack_answer(query, question_end, qtype, ip):
    """劫持应答：A 记录指向连接器；AAAA/HTTPS(65) 等返回 NODATA。"""
    if qtype == 1:
        record = (b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 30, 4)
                  + socket.inet_aton(ip))
        return dns_answer(query, question_end, answers=[record])
    return dns_answer(query, question_end)


def servfail(query, question_end):
    return dns_answer(query, question_end, rcode=2)


async def forward_udp(query, upstreams, timeout=2.0, client=None, upstream_mgr=None):
    """原样转发查询；支持复用客户端与故障转移。"""
    norm_upstreams = [normalize_upstream(u) for u in upstreams]
    for remote in norm_upstreams:
        resp = None
        # 1. 优先尝试复用 UDP 客户端
        if client and getattr(client, 'transport', None):
            resp = await client.query_one(remote, query, timeout=timeout)
        # 2. 回退到直接独立 Socket
        if resp is None:
            loop = asyncio.get_running_loop()
            done = loop.create_future()

            class Relay(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not done.done():
                        done.set_result(data)

                def error_received(self, error):
                    if not done.done():
                        done.set_exception(error)

            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: Relay(), remote_addr=remote)
            except OSError:
                if upstream_mgr:
                    upstream_mgr.record_failure(remote)
                continue
            try:
                transport.sendto(query)
                resp = await asyncio.wait_for(done, timeout)
            except (asyncio.TimeoutError, OSError):
                if upstream_mgr:
                    upstream_mgr.record_failure(remote)
                continue
            finally:
                transport.close()

        if resp is not None:
            if upstream_mgr:
                upstream_mgr.record_success(remote)
            return resp
    return None


def build_query(name, qtype=1, qclass=1, query_id=0x1234):
    """构造单问题查询报文（测试与自检用）。"""
    question = b''.join(
        bytes([len(label)]) + label.encode('ascii')
        for label in name.split('.')) + b'\x00'
    question += struct.pack('>HH', qtype, qclass)
    header = struct.pack('>HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
    return header + question


# ---------------------------------------------------------------------------
# 伪造应答：严格 ARPC -> 宽松 ARPC -> 空结果（模拟“服务端不认识这些基站”）
# ---------------------------------------------------------------------------

def coordinate(value):
    scaled = value * 100_000_000
    return math.floor(scaled + .5) if scaled >= 0 else math.ceil(scaled - .5)


def forged_location(latitude, longitude):
    # 精度字段与真机采信通过的参数一致：39m 水平精度 / 1000m 垂直精度
    return b''.join(pb_field(n, v) for n, v in (
        (1, coordinate(latitude)), (2, coordinate(longitude)), (3, 39),
        (4, 3), (5, 100), (6, 1000), (11, 63), (12, 467)))


EMPTY_RESPONSE = b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'


def _walk_strings(body):
    offset = 2
    for _ in range(3):
        if offset + 2 > len(body):
            raise ValueError('truncated envelope')
        length = int.from_bytes(body[offset:offset + 2], 'big')
        offset += 2 + length
    return offset


def tolerant_response(body, latitude, longitude):
    """返回 (response, mode)；mode ∈ strict / tolerant / empty。"""
    try:
        return build_response(body, latitude=latitude, longitude=longitude), 'strict'
    except ValueError:
        pass
    try:
        offset = _walk_strings(body)
        if offset + 8 > len(body):
            raise ValueError('truncated header')
        plen = int.from_bytes(body[offset + 4:offset + 8], 'big')
        proto = body[offset + 8:offset + 8 + plen] if plen else body[offset + 8:]
        location = forged_location(latitude, longitude)
        results = []
        for number, wire, value in pb_fields(proto):
            if number == 2 and wire == 2:
                bssid = next((v for n, w, v in pb_fields(value)
                              if n == 1 and w == 2), None)
                if bssid:
                    results.append(pb_field(2, pb_field(1, bssid)
                                            + pb_field(2, location)))
        if not results:
            raise ValueError('no usable entries')
        protobuf = b''.join(results)
        return (b'\x00\x01\x00\x00\x00\x01\x00\x00'
                + struct.pack('>H', len(protobuf)) + protobuf), 'tolerant'
    except (ValueError, IndexError):
        return EMPTY_RESPONSE, 'empty'


# ---------------------------------------------------------------------------
# TLS：ClientHello SNI 解析 + MemoryBIO 手动握手（跨解释器一致）
# ---------------------------------------------------------------------------

async def read_client_hello(reader, timeout=10):
    """读取并跨记录重组 ClientHello。

    返回 (handshake_msg, wire)。handshake_msg 为去掉 TLS 记录头的完整
    ClientHello 握手消息（供 parse_sni）；wire 为已消费的原始线缆字节含
    记录头与其后已读到的字节（供 MemoryBIO 原样喂入，不能去头）。
    """
    raw = bytearray()
    wire = bytearray()
    handshake = bytearray()

    async def fill():
        chunk = await asyncio.wait_for(reader.read(4096), timeout)
        if not chunk:
            raise ConnectionResetError('client closed before ClientHello')
        raw.extend(chunk)
        wire.extend(chunk)

    while True:
        while len(raw) < 5:
            await fill()
        if raw[0] != 0x16:  # 非 handshake 记录
            raise ValueError('not a TLS handshake record')
        record_length = int.from_bytes(raw[3:5], 'big')
        while len(raw) < 5 + record_length:
            await fill()
        handshake.extend(raw[5:5 + record_length])
        del raw[:5 + record_length]
        if len(handshake) >= 4:
            total = 4 + int.from_bytes(handshake[1:4], 'big')
            if len(handshake) >= total:
                return (bytes(handshake[:total]), bytes(wire))


def parse_sni(client_hello):
    """从 ClientHello 握手消息（不含 TLS 记录头，含 4 字节握手头）解析
    server_name；无则 None。"""
    body = client_hello
    try:
        if body[0] != 0x01:  # 不是 ClientHello
            return None
        pos = 4 + 2 + 32                      # 头 + client_version + random
        pos += 1 + body[pos]                  # session_id
        pos += 2 + int.from_bytes(body[pos:pos + 2], 'big')   # cipher suites
        pos += 1 + body[pos]                  # compression methods
        extensions_end = min(pos + 2
                             + int.from_bytes(body[pos:pos + 2], 'big'),
                             len(body))
        pos += 2
        while pos + 4 <= extensions_end:
            etype = int.from_bytes(body[pos:pos + 2], 'big')
            elen = int.from_bytes(body[pos + 2:pos + 4], 'big')
            data = body[pos + 4:pos + 4 + elen]
            pos += 4 + elen
            if etype != 0:  # server_name
                continue
            list_end = min(2 + int.from_bytes(data[:2], 'big'), len(data))
            cursor = 2
            while cursor + 3 <= list_end:
                name_type = data[cursor]
                name_len = int.from_bytes(data[cursor + 1:cursor + 3], 'big')
                if name_type == 0:
                    return data[cursor + 3:cursor + 3 + name_len].decode(
                        'ascii', 'ignore').lower()
                cursor += 3 + name_len
        return None
    except (IndexError, ValueError):
        return None


class ManualTls:
    """基于 MemoryBIO 的服务端 TLS：明文侧提供行读取/定长读取/写。

    wire 为已读到的原始线缆字节（含 TLS 记录头），需原样进入 inbio。
    """

    def __init__(self, reader, writer, context, wire):
        self.reader, self.writer = reader, writer
        self.inbio = ssl.MemoryBIO()
        self.outbio = ssl.MemoryBIO()
        self.inbio.write(wire)
        self.sslobj = context.wrap_bio(self.inbio, self.outbio,
                                       server_side=True)
        self.plain = bytearray()

    async def _flush(self):
        if self.outbio.pending:
            self.writer.write(self.outbio.read())
            await self.writer.drain()

    async def handshake(self, timeout=10):
        while True:
            try:
                self.sslobj.do_handshake()
                await self._flush()
                return
            except ssl.SSLWantReadError:
                await self._flush()
                chunk = await asyncio.wait_for(self.reader.read(16384), timeout)
                if not chunk:
                    raise ConnectionResetError('client closed mid-handshake')
                self.inbio.write(chunk)

    async def _read_plaintext(self, timeout):
        while True:
            chunk = self.sslobj.read(16384)
            if chunk:
                self.plain.extend(chunk)
                return
            await self._flush()
            data = await asyncio.wait_for(self.reader.read(16384), timeout)
            if not data:
                raise ConnectionResetError('client closed')
            self.inbio.write(data)

    async def readline(self, timeout=15):
        while b'\n' not in self.plain:
            await self._read_plaintext(timeout)
        index = self.plain.index(b'\n')
        line = bytes(self.plain[:index + 1])
        del self.plain[:index + 1]
        return line

    async def readexactly(self, count, timeout=15):
        while len(self.plain) < count:
            await self._read_plaintext(timeout)
        data = bytes(self.plain[:count])
        del self.plain[:count]
        return data

    async def write(self, data, timeout=15):
        self.sslobj.write(data)
        await self._flush()


# ---------------------------------------------------------------------------
# 管理器
# ---------------------------------------------------------------------------

class DnsLocationError(Exception):
    pass


class DnsLocationManager:
    def __init__(self, store_root=None, dns_port=53, tls_port=443,
                 upstreams=None, auth_guard=None):
        self.store = CertificateStore(store_root)
        self.dns_port = dns_port
        self.tls_port = tls_port
        self.lan_ip = self.detect_lan_ip()
        self.upstream_mgr = UpstreamManager(
            initial_upstreams=upstreams,
            lan_ip=self.lan_ip,
            local_port=self.dns_port)
        # 兼容性属性：对外暴露当前主上游列表（字符串表示）
        self.upstreams = tuple(str(u[0]) if u[1] == 53 else f'{u[0]}:{u[1]}'
                               for u in self.upstream_mgr.get_ordered_upstreams())
        self.auth_guard = auth_guard
        self.lock = asyncio.Lock()
        self.server = None
        self.target = None
        self.contexts = {}
        self.clients = set()
        self.mode = 'rewrite'
        self.sinkhole = None
        self.cache = DnsCache(max_entries=2048)
        self.upstream_client = None
        self.debug_log = os.getenv("LOCALWARP_DNS_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
        self._log_queue = asyncio.Queue(maxsize=2000) if self.debug_log else None
        self._log_task = None
        self.diagnostics = self._fresh_diagnostics()

    def _check_auth(self):
        if self.auth_guard is None:
            return True
        return self.auth_guard()

    @staticmethod
    def _fresh_diagnostics():
        return dict(dns_queries=0, dns_hijacked=0, dns_suppressed=0, dns_forwarded=0,
                    dns_failed=0, cache_hits=0, cache_misses=0, upstream_queries=0,
                    cache_size=0, tls_conn=0, sni_refused=0,
                    wloc_requests=0, strict=0, tolerant=0, empty=0,
                    errors=0, last_error_code=None, recent_queries=[])

    def _log_query(self, now_str: str, action: str, name: str, qtype: int):
        if not self.debug_log or self._log_queue is None:
            return
        line = f'{now_str} [{action.upper():10s}] {name:<45s} (qtype={qtype})\n'
        try:
            self._log_queue.put_nowait(line)
        except (asyncio.QueueFull, Exception):
            pass

    async def _log_flusher(self):
        log_path = Path('/tmp/localwarp-dns-queries.log')
        while True:
            try:
                line = await self._log_queue.get()
                batch = [line]
                while not self._log_queue.empty() and len(batch) < 50:
                    batch.append(self._log_queue.get_nowait())
                if log_path.exists() and log_path.stat().st_size > 5 * 1024 * 1024:
                    log_path.write_text('')
                with open(log_path, 'a', encoding='utf-8') as f:
                    f.writelines(batch)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.5)

    @property
    def running(self):
        return getattr(self, 'dns_tcp', None) is not None

    @property
    def active(self):
        return self.running and self.target is not None

    @staticmethod
    def detect_lan_ip():
        """返回一个非 link-local 的本机 IPv4（探测 UDP 路由，不实际发包，并回退网卡枚举）。"""
        for target in (('223.5.5.5', 53), ('1.1.1.1', 53), ('192.0.2.1', 9)):
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.connect(target)
                ip = probe.getsockname()[0]
                if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                    return ip
            except OSError:
                pass
            finally:
                probe.close()
        try:
            from .wloc_proxy import lan_ips
            ips = lan_ips()
            for ip in ips:
                if not ip.startswith('169.254.') and not ip.startswith('127.'):
                    return ip
            if ips:
                return ips[0]
        except Exception:
            pass
        return None

    def status(self):
        if not self.lan_ip:
            detected = self.detect_lan_ip()
            if detected:
                self.lan_ip = detected
                if hasattr(self, 'upstream_mgr') and self.upstream_mgr:
                    self.upstream_mgr.lan_ip = detected
        cert = getattr(self.store, 'cert', None) if self.mode == 'rewrite' else None
        diag = dict(self.diagnostics)
        diag['cache_hits'] = self.cache.hits
        diag['cache_misses'] = self.cache.misses
        diag['cache_size'] = len(self.cache)
        current_upstreams = [str(u[0]) if u[1] == 53 else f'{u[0]}:{u[1]}'
                             for u in self.upstream_mgr.get_ordered_upstreams()]
        return dict(running=self.running, active=self.active, mode=self.mode, sinkhole_ip=self.sinkhole,
                    tls_listening=self.server is not None, requires_ca=self.mode == 'rewrite',
                    ios27_hint='iOS >=27: accessory + DNS suppression is experimental; verify NMEA screening, IntegrityMonitor and the map during an active session.',
                    listen_dns_port=self.dns_port,
                    listen_tls_port=self.tls_port, lan_ip=self.lan_ip,
                    hijack_hosts=sorted(HIJACK_HOSTS),
                    suppressed_hosts=(sorted(SUPPRESS_HOSTS)
                                      if self.mode == 'suppress' else []),
                    upstreams=current_upstreams,
                    target=self.target, phone_location_verified=False,
                    phone_steps=SUPPRESS_STEPS if self.mode == 'suppress' else STEPS,
                    constraint=constraint_text(self.mode),
                    ca_fingerprint_sha256=(cert.fingerprint(
                        __import__('cryptography.hazmat.primitives.hashes',
                                   fromlist=['SHA256']).SHA256()).hex().upper()
                        if cert else None),
                    diagnostics=diag)

    async def prepare(self, mode='rewrite'):
        """Make DNS usable before phone setup, without applying a target policy."""
        async with self.lock:
            await self._prepare(mode)
            return self.status()

    async def _prepare(self, mode):
        # Caller holds the lifecycle lock. Re-entry must not reset active policy.
        if mode not in ('rewrite', 'suppress'):
            raise ValueError('mode must be rewrite or suppress')
        if self.running:
            if self.mode != mode:
                raise DnsLocationError('stop DNS before switching modes')
            return
        sinkhole = str(ipaddress.IPv4Address(os.getenv('LOCALWARP_DNS_SINKHOLE', '0.0.0.0'))) if mode == 'suppress' else None
        lan_ip = self.detect_lan_ip()
        if not lan_ip:
            raise DnsLocationError('no LAN IPv4 address found')
        self.lan_ip = lan_ip
        self.upstream_mgr.lan_ip = lan_ip
        self.mode = mode
        self.sinkhole = sinkhole
        self.target = None
        self.diagnostics = self._fresh_diagnostics()
        self.contexts = {}
        self.cache.clear()
        if mode == 'rewrite':
            await asyncio.to_thread(self.store.ensure)
            self.contexts = {host: await asyncio.to_thread(
                self.store.tls_context, host) for host in HIJACK_HOSTS}
        try:
            loop = asyncio.get_running_loop()
            # 启动长生命周期的上游复用 UDP 客户端
            if self.upstream_client is None:
                client = UpstreamUdpClient()
                try:
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: client, local_addr=('0.0.0.0', 0))
                    self.upstream_client = client
                except OSError:
                    self.upstream_client = None

            if self.debug_log and self._log_task is None and self._log_queue is not None:
                self._log_task = loop.create_task(self._log_flusher())

            self.udp_transport, _ = await loop.create_datagram_endpoint(
                self._udp_factory, local_addr=('0.0.0.0', self.dns_port))
            self.dns_tcp = await asyncio.start_server(
                self._accept_tcp_dns, '0.0.0.0', self.dns_port)
            if mode == 'rewrite':
                self.server = await asyncio.start_server(
                    self._accept_tls, '0.0.0.0', self.tls_port)
        except OSError as error:
            await self._close_listeners()
            raise DnsLocationError(
                f'cannot bind required ports for {mode} (DNS {self.dns_port}, TLS {self.tls_port}): '
                f'{error}') from error

    async def start(self, latitude, longitude, mode='rewrite'):
        if not (math.isfinite(latitude) and math.isfinite(longitude)
                and -90 <= latitude <= 90 and -180 <= longitude <= 180):
            raise ValueError('invalid coordinates')
        async with self.lock:
            await self._prepare(mode)
            self.target = dict(latitude=latitude, longitude=longitude)
            return self.status()

    async def deactivate(self):
        """Remove target policy while keeping the phone's DNS resolver usable."""
        async with self.lock:
            self.target = None
            self.cache.clear()
            return self.status()

    async def stop(self):
        async with self.lock:
            self.target = None
            await self._close_listeners()
            return self.status()

    async def shutdown(self):
        await self.stop()

    async def _close_listeners(self):
        servers = []
        for name in ('dns_tcp', 'server'):
            entry = getattr(self, name, None)
            if entry:
                entry.close()
                servers.append(entry)
                setattr(self, name, None)
        transport = getattr(self, 'udp_transport', None)
        if transport:
            transport.close()
            self.udp_transport = None

        if self.upstream_client:
            self.upstream_client.close()
            self.upstream_client = None

        if self._log_task:
            self._log_task.cancel()
            self._log_task = None

        self.cache.clear()

        # Close accepted streams before waiting for the servers to drain.
        for writer in list(self.clients):
            writer.close()
        for entry in servers:
            await entry.wait_closed()

    # -- DNS ---------------------------------------------------------------
    def _udp_factory(self):
        manager = self

        class UdpDns(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                def _safe_send(reply):
                    if self.transport and not self.transport.is_closing():
                        try:
                            self.transport.sendto(reply, addr)
                        except (OSError, AttributeError):
                            pass

                asyncio.get_running_loop().create_task(
                    manager._answer_dns(data, _safe_send))

        return UdpDns()

    def _accept_stream(self, handler, reader, writer):
        # Register synchronously: stop may run before an async handler is scheduled.
        if not self.running:
            writer.close()
            return
        self.clients.add(writer)
        asyncio.get_running_loop().create_task(handler(reader, writer))

    def _accept_tcp_dns(self, reader, writer):
        self._accept_stream(self._handle_tcp_dns, reader, writer)

    def _accept_tls(self, reader, writer):
        self._accept_stream(self._handle_tls, reader, writer)

    async def _handle_tcp_dns(self, reader, writer):
        self.clients.add(writer)
        try:
            while True:
                prefix = await asyncio.wait_for(reader.readexactly(2), 20)
                (length,) = struct.unpack('>H', prefix)
                query = await asyncio.wait_for(reader.readexactly(length), 10)
                await self._answer_dns(
                    query,
                    lambda reply: writer.write(
                        struct.pack('>H', len(reply)) + reply))
                await writer.drain()
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError,
                ValueError):
            pass
        finally:
            self.clients.discard(writer)
            writer.close()

    async def _answer_dns(self, query, send):
        try:
            parsed = parse_question(query)
            if not parsed:
                return
            name, qtype, qclass, qend = parsed
            self.diagnostics['dns_queries'] += 1
            if self.active and not self._check_auth():
                self.target = None
            is_target = self.active and (is_suppressed_domain(name) if self.mode == 'suppress'
                                        else name in HIJACK_HOSTS)
            action = 'suppressed' if is_target else 'forwarded'
            now_str = time.strftime('%H:%M:%S')

            # 诊断与实时日志留存（保留最近 100 条汇总，不落敏感数据）
            recent = self.diagnostics.setdefault('recent_queries', [])
            recent.append(dict(time=now_str, name=name, qtype=qtype, action=action))
            if len(recent) > 100:
                del recent[:len(recent) - 100]

            # 仅在开启 LOCALWARP_DNS_DEBUG 时异步写入文件
            if self.debug_log:
                self._log_query(now_str, action, name, qtype)

            # 红线防守：定位目标绝对不走外部上游，绝对不进缓存
            if is_target:
                if qclass == 1:
                    self.diagnostics['dns_hijacked'] += 1
                    if self.mode == 'suppress':
                        self.diagnostics['dns_suppressed'] += 1
                    answer_ip = self.sinkhole if self.mode == 'suppress' else self.lan_ip
                    send(hijack_answer(query, qend, qtype, answer_ip))
                else:
                    send(servfail(query, qend))
                return

            # 普通域名查询：首先检查内存 TTL 缓存
            cached_reply = self.cache.get(query, name, qtype, qclass)
            if cached_reply is not None:
                self.diagnostics['cache_hits'] = self.diagnostics.get('cache_hits', 0) + 1
                self.diagnostics['dns_forwarded'] += 1
                send(cached_reply)
                return

            self.diagnostics['cache_misses'] = self.diagnostics.get('cache_misses', 0) + 1
            self.diagnostics['upstream_queries'] = self.diagnostics.get('upstream_queries', 0) + 1

            # 向上游转发查询（优先系统 DNS 与复用 Socket，带快速故障转移）
            effective_upstreams = (
                self.upstream_mgr.get_ordered_upstreams()
                if hasattr(self, 'upstream_mgr') else self.upstreams)
            upstream = await forward_udp(
                query,
                effective_upstreams,
                client=self.upstream_client,
                upstream_mgr=getattr(self, 'upstream_mgr', None))

            if upstream is not None:
                self.diagnostics['dns_forwarded'] += 1
                self.cache.set(name, qtype, qclass, upstream, qend)
                send(upstream)
            else:
                self.diagnostics['dns_failed'] += 1
                send(servfail(query, qend))
        except (ValueError, OSError) as error:
            self.diagnostics['errors'] += 1
            self.diagnostics['last_error_code'] = type(error).__name__

    # -- TLS ----------------------------------------------------------------
    async def _handle_tls(self, reader, writer):
        self.clients.add(writer)
        try:
            handshake, wire = await read_client_hello(reader)
            sni = parse_sni(handshake)
            context = self.contexts.get(sni) if sni else None
            if context is None:
                self.diagnostics['sni_refused'] += 1
                writer.close()
                return
            tls = ManualTls(reader, writer, context, wire)
            await tls.handshake()
            self.diagnostics['tls_conn'] += 1
            request = await tls.readline(20)
            parts = request.decode('latin1').split()
            headers = {}
            while True:
                line = await tls.readline(10)
                if line in (b'\r\n', b'\n', b''):
                    break
                key, _, value = line.decode('latin1').partition(':')
                headers[key.strip().lower()] = value.strip()
            method = parts[0] if parts else ''
            path = parts[1] if len(parts) > 1 else ''
            length = int(headers.get('content-length', '0') or 0)
            if (method != 'POST' or path.split('?')[0] != '/clls/wloc'
                    or headers.get('host', '').split(':')[0] != sni
                    or not 0 < length <= MAX_BODY):
                await tls.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0'
                                b'\r\nConnection: close\r\n\r\n')
                return
            body = await tls.readexactly(length, 15)
            # 实时核验授权守卫：到期或撤销立即清空目标策略并拒绝服务，防止 DNS 缓存绕过
            if self.active and not self._check_auth():
                self.target = None
            # Read policy after all request awaits: deactivation may have happened
            # during the handshake/body read. No yield before writing this response.
            target = self.target if self.active and self.mode == 'rewrite' else None
            if target is None:
                await tls.write(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0'
                                b'\r\nConnection: close\r\n\r\n')
                return
            self.diagnostics['wloc_requests'] += 1
            response, mode = tolerant_response(
                body, target['latitude'], target['longitude'])
            self.diagnostics[mode] += 1
            await tls.write(b'HTTP/1.1 200 OK\r\nContent-Type: '
                            b'application/octet-stream\r\nContent-Length: '
                            + str(len(response)).encode()
                            + b'\r\nConnection: close\r\n\r\n' + response)
        except (ValueError, OSError, asyncio.TimeoutError,
                asyncio.IncompleteReadError, ConnectionResetError,
                ssl.SSLError) as error:
            self.diagnostics['errors'] += 1
            self.diagnostics['last_error_code'] = (
                f'tls:{type(error).__name__}')
        finally:
            self.clients.discard(writer)
            try:
                writer.close()
            except Exception:
                pass
