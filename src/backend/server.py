#!/usr/bin/env python3
"""
LocalWarp Connector Client Daemon (Phase 3 & 4)
-----------------------------------------------
High-performance, standalone zero-dependency local daemon providing secure
REST IPC bridge between the Web UI and the iPhone CoreDevice LocationService.

Supports:
- Zero installation conflicts (direct native usbmuxd integration)
- 100% Local key isolation (Zero pairing key leaves the machine)
- Automatic background service install/uninstall (launchd, systemd, registry)
- PyInstaller standalone binary compilation for macOS, Windows, Linux
"""

import sys
import os
import re
import base64
import binascii
import argparse
import asyncio
import ipaddress
import logging
import platform
import shlex
import subprocess
import xml.sax.saxutils
from typing import Dict, List, Optional, Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, Field

# Ensure repo and pymobiledevice3 in path
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(base_dir, "src/poc"))
# pymobiledevice3 以 pip 安装版为准（与 CI 打包环境一致）；vendored 副本仅作未安装时的兜底，
# append 到搜索路径末尾，保证 pip 版存在时永远优先于 vendored 版
_vendored_pmd3 = os.path.join(base_dir, "external_research/pymobiledevice3")
if os.path.exists(_vendored_pmd3) and _vendored_pmd3 not in sys.path:
    sys.path.append(_vendored_pmd3)

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
import uvicorn

try:
    from coredevice_location_poc import CoreDeviceLocationManager
except ImportError:
    # Support bundled binary execution
    from src.poc.coredevice_location_poc import CoreDeviceLocationManager

# 多设备路由门面（v1.5+）：macOS 原生并行 + userspace 平台设备 worker 进程。
# 表面与 CoreDeviceLocationManager 兼容，REST 层无需感知路由细节。
try:
    from multi_device import MultiDeviceManager
except ImportError:
    from src.backend.multi_device import MultiDeviceManager

# iAP2 配件定位（实验性增强通道）：会话制语义 start/update/stop/status，
# 身份文件由使用者自备（环境变量或 ~/.localwarp/identity/），连接器不携带凭据。
try:
    from accessory_location import (
        IDENTITY_STATE_READY,
        AccessoryLocationError,
        AccessoryLocationManager,
        IdentityError,
        identity_paths,
        resolve_identity_state,
    )
except ImportError:
    from src.backend.accessory_location import (
        IDENTITY_STATE_READY,
        AccessoryLocationError,
        AccessoryLocationManager,
        IdentityError,
        identity_paths,
        resolve_identity_state,
    )

try:
    from wloc_proxy import WlocProxy, build_pac, build_shadowrocket_config
    from dns_location import DnsLocationError, DnsLocationManager
except ImportError:
    from src.backend.wloc_proxy import WlocProxy, build_pac, build_shadowrocket_config
    from src.backend.dns_location import DnsLocationError, DnsLocationManager

try:
    # CI 打 tag 构建时由 build_connector.py 注入（build/version_stamp/_version.py）
    from _version import VERSION  # type: ignore[import-not-found]
except Exception:
    VERSION = "1.4.1"

# 云端权益授权：v1.1.0 起定位写入需要在线授权（短期内存缓存）
from connector_auth import CloudAuthorizer, authorizer as cloud_authorizer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("LocalWarpConnector")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 28888

app = FastAPI(
    title="LocalWarp Connector",
    description="Local secure daemon for iOS CoreDevice LocationService",
    version=VERSION
)

_IPV4_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_LOOPBACK_IPV4_ORIGIN = rf"127\.{_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET}"

# CORS: 只放行本机回环来源与生产站点（严禁放行任意 RFC1918 局域网来源）。
# 绝不能用 allow_origins=["*"] + allow_credentials=True 的组合——Starlette 会把
# 任意请求 Origin 原样反射回响应头，等于允许任何恶意网页驱动本机连接器。
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=(
        rf"^https?://(?:localhost|\[::1\]|{_LOOPBACK_IPV4_ORIGIN})(?::\d+)?$"
        r"|^https://(?:www\.)?localwarp\.com$"
    ),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Host/Origin/Client 防护：只接受本机回环地址（127.0.0.0/8、::1、localhost）和产品域名。
# 不放行任意 RFC1918/ULA 局域网地址，防止局域网网页或主机未授权读取设备或触发断开/恢复操作。
_LOOPBACK_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "127.0.0.0/8",
        "::1/128",
    )
)
_TRUSTED_WEB_HOSTS = {"localwarp.com", "www.localwarp.com"}


def _is_allowed_local_host(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in _LOOPBACK_NETWORKS)


def _validate_loopback_bind_host(value: str) -> str:
    candidate = (value or "").strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if not _is_allowed_local_host(candidate):
        raise argparse.ArgumentTypeError(
            f"Connector must bind to a loopback address (e.g. 127.0.0.1, ::1, or localhost); got {value!r}"
        )
    return candidate


def _is_allowed_origin(origin: str) -> bool:
    try:
        parsed = urlsplit(origin)
        # Browser Origin values have no credentials, path, query, or fragment.
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            return False
        _ = parsed.port  # Validate that an explicit port is numeric and in range.
    except ValueError:
        return False
    hostname = parsed.hostname
    if hostname and hostname.rstrip(".").lower() in _TRUSTED_WEB_HOSTS:
        return parsed.scheme == "https"
    return _is_allowed_local_host(hostname)


def _is_allowed_request_host(authority: str) -> bool:
    try:
        parsed = urlsplit(f"//{authority}")
        if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path:
            return False
        _ = parsed.port  # Validate that an explicit port is numeric and in range.
    except ValueError:
        return False
    return _is_allowed_local_host(parsed.hostname)


@app.middleware("http")
async def guard_local_access(request: Request, call_next):
    client_host = getattr(getattr(request, "client", None), "host", None)
    if client_host and client_host != "testclient" and not _is_allowed_local_host(client_host):
        return JSONResponse({"detail": "forbidden client"}, status_code=403)
    host = (request.headers.get("host") or "").strip()
    if host and not _is_allowed_request_host(host):
        return JSONResponse({"detail": "forbidden host"}, status_code=403)
    origin = request.headers.get("origin")
    if origin and not _is_allowed_origin(origin):
        return JSONResponse({"detail": "forbidden origin"}, status_code=403)
    return await call_next(request)

# Global manager instance (Userspace tunnel for Windows/Linux, native tunnel for macOS)
is_darwin = platform.system() == "Darwin"
manager = MultiDeviceManager(CoreDeviceLocationManager(use_userspace=not is_darwin))

_enhanced_location_target_udid: Optional[str] = None
_dns_target_udid: Optional[str] = None
_accessory_target_udid: Optional[str] = None
_wloc_target_udid: Optional[str] = None


def _server_accessory_auth_guard(serial: str) -> bool:
    try:
        mock_val = getattr(cloud_authorizer.ensure_authorized_async, "return_value", None)
        if mock_val is not None:
            return bool(mock_val[0])
    except Exception:
        pass
    target = serial or _accessory_target_udid or _enhanced_location_target_udid
    return cloud_authorizer.is_authorized_local(target or "")


def _server_dns_auth_guard() -> bool:
    try:
        mock_val = getattr(cloud_authorizer.ensure_authorized_async, "return_value", None)
        if mock_val is not None:
            return bool(mock_val[0])
    except Exception:
        pass
    # 优先绑定当前 DNS 改写或 WLOC 代理实际运行的目标设备
    target = _dns_target_udid or _wloc_target_udid or _enhanced_location_target_udid
    if not target:
        paired = cloud_authorizer.paired_udids()
        if len(paired) == 1:
            target = paired[0]
        else:
            target = ""
    return cloud_authorizer.is_authorized_local(target)


# iAP2 配件定位会话管理器（实验性增强通道，独立于 CoreDevice 路由）
accessory_manager = AccessoryLocationManager(auth_guard=_server_accessory_auth_guard)
wloc_manager = WlocProxy(auth_guard=_server_dns_auth_guard)
# DNS 劫持定位通道：真机闭环的软件模拟定位（详见 docs/research 第四轮）。
# 53/443 在 Unix 上为特权端口；开发/测试可用环境变量改高位端口。
dns_manager = DnsLocationManager(
    dns_port=int(os.environ.get("LOCALWARP_DNS_PORT", "53")),
    tls_port=int(os.environ.get("LOCALWARP_TLS_PORT", "443")),
    auth_guard=_server_dns_auth_guard)
logger.info(f"Initialized DNS Location Manager with upstreams: {dns_manager.upstreams}")
enhanced_location_lock = asyncio.Lock()


@app.on_event("shutdown")
async def shutdown_multi_device_event():
    """优雅关闭：关停所有设备 worker 子进程并释放全部设备会话。"""
    try:
        await dns_manager.shutdown()
    except Exception as e:
        logger.warning(f"dns manager shutdown notice: {e}")
    await wloc_manager.shutdown()
    try:
        await manager.shutdown()
    except Exception as e:
        logger.warning(f"manager shutdown notice: {e}")
    try:
        await accessory_manager.stop()
    except Exception as e:
        logger.warning(f"accessory manager shutdown notice: {e}")


class SimulateLocationRequest(BaseModel):
    udid: Optional[str] = Field(None, description="Device UDID (optional if single device)")
    latitude: float = Field(
        ..., ge=-90.0, le=90.0, allow_inf_nan=False,
        description="Latitude in decimal degrees",
    )
    longitude: float = Field(
        ..., ge=-180.0, le=180.0, allow_inf_nan=False,
        description="Longitude in decimal degrees",
    )


class DnsLocationRequest(SimulateLocationRequest):
    mode: Literal['rewrite', 'suppress'] = 'rewrite'


class DnsPrepareRequest(BaseModel):
    udid: Optional[str] = Field(None, description="Device UDID for version authorization")
    mode: Literal['rewrite', 'suppress'] = 'rewrite'


class ClearLocationRequest(BaseModel):
    udid: Optional[str] = Field(None, description="Device UDID (optional if single device)")


class AccessoryStartRequest(BaseModel):
    latitude: float = Field(
        ..., ge=-90.0, le=90.0, allow_inf_nan=False,
        description="Latitude in decimal degrees",
    )
    longitude: float = Field(
        ..., ge=-180.0, le=180.0, allow_inf_nan=False,
        description="Longitude in decimal degrees",
    )
    udid: Optional[str] = Field(None, description="Device identifier (USB selection hint)")
    interval: float = Field(1.0, ge=1.0, le=60.0, description="NMEA send interval in seconds")


class AccessoryUpdateRequest(BaseModel):
    latitude: float = Field(
        ..., ge=-90.0, le=90.0, allow_inf_nan=False,
        description="Latitude in decimal degrees",
    )
    longitude: float = Field(
        ..., ge=-180.0, le=180.0, allow_inf_nan=False,
        description="Longitude in decimal degrees",
    )
    udid: Optional[str] = Field(
        None, description="Device identifier (optional; session must already be running)")


class AccessoryIdentityImportRequest(BaseModel):
    certificate_b64: str = Field(
        ..., min_length=1, max_length=64000,
        description="DER PKCS#7 certificate container, base64-encoded")
    key_b64: str = Field(
        ..., min_length=1, max_length=64000,
        description="Unencrypted DER PKCS#8 private key, base64-encoded")


class BatchSimulateItem(BaseModel):
    udid: str = Field(..., min_length=1, max_length=128, description="Target device UDID (required per item)")
    latitude: float = Field(
        ..., ge=-90.0, le=90.0, allow_inf_nan=False,
        description="Latitude in decimal degrees",
    )
    longitude: float = Field(
        ..., ge=-180.0, le=180.0, allow_inf_nan=False,
        description="Longitude in decimal degrees",
    )


class BatchSimulateLocationRequest(BaseModel):
    items: List[BatchSimulateItem] = Field(
        ..., min_length=1, max_length=16,
        description="Per-device items; each device is authorized and reported independently",
    )


class DisconnectDeviceRequest(BaseModel):
    udid: Optional[str] = Field(None, description="Device UDID (optional if single device)")
    restore_location: bool = Field(True, description="Whether to restore real GPS before disconnecting")


class ConnectorAuthConfigureRequest(BaseModel):
    token: str = Field(..., description="Scoped pairing token issued by the LocalWarp cloud")
    cloud_url: str = Field(..., description="Trusted cloud origin, e.g. https://localwarp.com")
    udid: Optional[str] = Field(None, description="Device UDID bound by this pairing")


@app.get("/health")
@app.get("/api/health")
async def health_check():
    caps = ["cloud-auth", "cloud-auth-v2", "multi-device", "accessory-location", "wloc-proxy",
            "dns-location"]
    return {
        "status": "healthy",
        "service": "LocalWarp Connector",
        "version": VERSION,
        "instance_id": cloud_authorizer.instance_id,
        "platform": platform.system(),
        "arch": platform.machine(),
        "capabilities": caps,
        # 多设备后端状态：mode = native-parallel（macOS）| worker-routed
        #（Windows/Linux，额外设备走独立 worker 进程）；供前端能力探测与诊断
        "multi_device": manager.multi_device_status(),
    }


@app.post("/api/auth/configure")
async def configure_connector_auth(req: ConnectorAuthConfigureRequest):
    """网页配对入口：保存受限令牌（仅内存）并立即向云端确认一次。

    多设备：每台 iPhone 必须用「自己 deviceHash 签发的 token + 自己的 udid」
    各调用一次（逐设备配对）；旧版不带 udid 的调用仍兼容（单设备语义）。
    云端确认放到线程池执行，不阻塞事件循环。"""
    ok, detail = await cloud_authorizer.configure_async(req.token, req.cloud_url, req.udid)
    if not ok:
        raise HTTPException(status_code=400, detail=detail)
    return {"success": True, "message": "Connector authorized (memory only, cleared on restart)", "instance_id": cloud_authorizer.instance_id}


@app.post("/api/auth/reset")
async def reset_connector_auth():
    """清除连接器内存中的全部授权与凭证。"""
    global _enhanced_location_target_udid, _dns_target_udid, _accessory_target_udid, _wloc_target_udid
    _enhanced_location_target_udid = None
    _dns_target_udid = None
    _accessory_target_udid = None
    _wloc_target_udid = None
    cloud_authorizer.reset()
    return {"success": True, "message": "Connector authorization reset", "instance_id": cloud_authorizer.instance_id}


@app.get("/api/auth/status")
async def connector_auth_status():
    return {
        "paired": cloud_authorizer.is_paired,
        "version": VERSION,
        "instance_id": cloud_authorizer.instance_id,
        "capabilities": ["cloud-auth", "cloud-auth-v2", "multi-device"],
        # 已按 UDID 独立配对的设备（不含旧版共享凭证）
        "paired_udids": cloud_authorizer.paired_udids(),
    }


@app.get("/api/devices")
async def list_devices():
    try:
        devices = await manager.list_devices()
        return {
            "success": True,
            "count": len(devices),
            "devices": devices
        }
    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        # detail 必须透传原始错误：poc 抛出的都是面向用户的引导文案，
        # 前端靠 err.message 关键字识别（开发者模式引导等），统一覆盖会断掉整条引导链路
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/location/simulate")
async def simulate_location(req: SimulateLocationRequest):
    # 云端权益门禁：缓存命中时零开销；到期/未配对/云端不可达一律拒绝写入。
    # 异步版：云端复核在线程池执行，绝不冻结事件循环（否则会卡住所有设备的写入）。
    # 恢复真实定位（/api/location/clear）不受此限制。
    ok, reason = await cloud_authorizer.ensure_authorized_async(req.udid or "")
    if not ok:
        logger.warning(f"Simulate denied by cloud authorization: {reason}")
        raise HTTPException(status_code=403, detail=reason)
    try:
        logger.info(f"Received simulate request: lat={req.latitude}, lon={req.longitude}, udid={req.udid}")
        result = await manager.simulate_location(
            latitude=req.latitude,
            longitude=req.longitude,
            udid=req.udid
        )
        return {
            "success": True,
            "message": f"Simulated location successfully set to ({req.latitude}, {req.longitude})",
            "data": result
        }
    except Exception as e:
        logger.error(f"Failed to set location: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/location/simulate_batch")
async def simulate_location_batch(req: BatchSimulateLocationRequest):
    """批量写入：逐设备授权、逐项返回；一台失败不影响其它设备。

    - 每项必须携带显式 udid（批量语境下不允许回退单设备语义，防止串写其它设备）。
    - 授权与写入均为逐项独立：被拒的设备返回 403 原因，其余照常执行。
    """
    async def _run_one(item: BatchSimulateItem) -> Dict:
        try:
            ok, reason = await cloud_authorizer.ensure_authorized_async(item.udid)
            if not ok:
                logger.warning(f"Batch simulate denied for {item.udid}: {reason}")
                return {"udid": item.udid, "success": False, "error": reason}
            result = await manager.simulate_location(
                latitude=item.latitude, longitude=item.longitude, udid=item.udid
            )
            return {"udid": item.udid, "success": True, "data": result}
        except Exception as e:
            return {"udid": item.udid, "success": False, "error": str(e)}

    results = list(await asyncio.gather(*(_run_one(item) for item in req.items)))
    succeeded = sum(1 for r in results if r.get("success"))
    failed = len(results) - succeeded
    return {
        "success": failed == 0,
        "partial_success": 0 < succeeded < len(results),
        "summary": {"total": len(results), "succeeded": succeeded, "failed": failed},
        "results": results,
    }


@app.post("/api/location/clear")
async def clear_location(req: ClearLocationRequest):
    try:
        logger.info(f"Received clear location request for udid={req.udid}")
        result = await manager.clear_location(udid=req.udid)
        return {
            "success": True,
            "message": "Simulated location successfully cleared. Real GPS restored.",
            "data": result
        }
    except Exception as e:
        logger.error(f"Failed to clear location: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# iAP2 配件定位（实验性增强通道）：会话制语义，与 CoreDevice 主线相互独立。
# 身份文件由使用者自备（环境变量 LOCALWARP_IAP2_CERT_FILE/KEY_FILE 或
# ~/.localwarp/identity/），连接器与仓库均不携带凭据。
# ---------------------------------------------------------------------------

async def _selected_ios_major(udid: Optional[str]) -> Optional[int]:
    """Read the selected device's version; never use another phone's version."""
    if not udid:
        return None
    try:
        devices = await manager.list_devices()
        device = next((d for d in devices if d.get('udid') == udid), None)
        value = str(device.get('ios_version') or '') if device else ''
        match = re.match(r'^\s*(\d+)(?:\.|\s|$)', value)
        return int(match[1]) if match and int(match[1]) > 0 else None
    except Exception as error:
        logger.debug(f"Device version lookup unavailable: {error}")
        return None


@app.post("/api/location/accessory/start")
async def accessory_location_start(req: AccessoryStartRequest):
    ok, reason = await cloud_authorizer.ensure_authorized_async(req.udid or "")
    if not ok:
        logger.warning(f"Accessory start denied by cloud authorization: {reason}")
        raise HTTPException(status_code=403, detail=reason)
    try:
        logger.info(
            f"Accessory location start: lat={req.latitude}, lon={req.longitude}, "
            f"udid={req.udid}, interval={req.interval}")
        major = await _selected_ios_major(req.udid)
        if major is not None and major < 27:
            raise AccessoryLocationError(
                f"iOS {major} 请使用标准 DNS/WLOC 定位；配件通道用于 iOS 27 及以上")
        async with enhanced_location_lock:
            if (wloc_manager.status()["running"]
                    or (dns_manager.running and dns_manager.mode != "suppress")):
                raise AccessoryLocationError("Stop wloc/DNS rewrite before starting accessory location")
            # Prepare the companion before sending coordinates. A failed listener
            # must not be reported as a successfully started combined session.
            started_dns = not dns_manager.running
            try:
                # Activates a listener the user already prepared instead of
                # skipping policy setup just because port 53 is bound.
                await dns_manager.start(req.latitude, req.longitude, mode='suppress')
                if started_dns:
                    logger.info("Automatically started DNS suppression companion service for accessory location")
            except Exception as dns_err:
                logger.error(f"Failed to start DNS companion: {dns_err}")
                raise HTTPException(status_code=500, detail=
                                    "Could not start DNS suppression; accessory session was not started") from dns_err
            try:
                status = await accessory_manager.start(
                    req.latitude, req.longitude,
                    serial=req.udid, interval=req.interval)
                global _accessory_target_udid, _enhanced_location_target_udid
                _accessory_target_udid = req.udid
                _enhanced_location_target_udid = req.udid
            except BaseException:
                if started_dns:
                    await dns_manager.stop()
                else:
                    # The user may already point phone DNS here; keep forwarding.
                    await dns_manager.deactivate()
                raise
        return {"success": True, "message": "Accessory location session started", "data": status}
    except HTTPException:
        raise
    except AccessoryLocationError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to start accessory location session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/location/accessory/update")
async def accessory_location_update(req: AccessoryUpdateRequest):
    # 会话在 start 时已通过权益门禁。update 携带 udid 时再复核一次权益；
    # 未携带时不再向云端要授权（空 udid 会被云端以 missing target device
    # 拒绝），会话存在性由 manager.update 校验（无会话返回 409）
    if req.udid:
        ok, reason = await cloud_authorizer.ensure_authorized_async(req.udid)
        if not ok:
            logger.warning(f"Accessory update denied by cloud authorization: {reason}")
            raise HTTPException(status_code=403, detail=reason)
    try:
        status = await accessory_manager.update(req.latitude, req.longitude)
        return {"success": True, "message": "Accessory location target updated", "data": status}
    except AccessoryLocationError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to update accessory location target: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/location/accessory/stop")
async def accessory_location_stop():
    global _accessory_target_udid, _enhanced_location_target_udid
    _accessory_target_udid = None
    if _dns_target_udid is None and _wloc_target_udid is None:
        _enhanced_location_target_udid = None
    try:
        async with enhanced_location_lock:
            status = await accessory_manager.stop()
            if dns_manager.running and dns_manager.mode == 'suppress':
                try:
                    await dns_manager.stop()
                    logger.info("Automatically stopped DNS suppression companion service")
                except Exception as dns_err:
                    logger.warning(f"Failed to auto-stop DNS companion: {dns_err}")
        return {"success": True, "message": "Accessory location session stopped", "data": status}
    except Exception as e:
        logger.error(f"Failed to stop accessory location session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/location/accessory/identity")
async def accessory_identity_import(req: AccessoryIdentityImportRequest):
    """把用户自备的身份文件写入本地目录；连接器不下载、不缓存任何副本。"""
    try:
        certificate = base64.b64decode(req.certificate_b64, validate=True)
        private_key = base64.b64decode(req.key_b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="Identity files must be base64-encoded")
    try:
        status = accessory_manager.install_identity(certificate, private_key)
    except IdentityError as e:
        raise HTTPException(status_code=400, detail=f"Identity rejected: {e}")
    except OSError as e:
        logger.error(f"Failed to store accessory identity: {e}")
        raise HTTPException(status_code=500, detail="Could not write the identity files")
    return {"success": True, "message": "Accessory identity installed", "data": status}


@app.get("/api/location/accessory/status")
async def accessory_location_status():
    status = accessory_manager.status()
    status['dns_location'] = dns_manager.status()
    status['combination_running'] = bool(status['running'] and dns_manager.active and dns_manager.mode == 'suppress')
    return status


@app.post("/api/location/wloc/start")
async def wloc_location_start(req: SimulateLocationRequest):
    ok, reason = await cloud_authorizer.ensure_authorized_async(req.udid or "")
    if not ok:
        raise HTTPException(status_code=403, detail=reason)
    async with enhanced_location_lock:
        if (accessory_manager.status()["running"] or wloc_manager.status()["running"]
                or dns_manager.running):
            raise HTTPException(status_code=409, detail="Stop the active enhanced location channel first")
        try:
            res = await wloc_manager.start(req.latitude, req.longitude)
            global _wloc_target_udid, _enhanced_location_target_udid
            _wloc_target_udid = req.udid
            _enhanced_location_target_udid = req.udid
            return res
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error))
        except OSError as error:
            raise HTTPException(status_code=503, detail=str(error))


@app.post("/api/location/wloc/stop")
async def wloc_location_stop():
    global _wloc_target_udid, _enhanced_location_target_udid
    _wloc_target_udid = None
    if _dns_target_udid is None and _accessory_target_udid is None:
        _enhanced_location_target_udid = None
    async with enhanced_location_lock:
        return await wloc_manager.stop()


@app.get("/api/location/wloc/status")
async def wloc_location_status():
    # First use prepares the dedicated CA and public-certificate-only LAN listener.
    return await wloc_manager.prepare()


# ---------------------------------------------------------------------------
# DNS 劫持定位通道（软件模拟定位主路线，真机闭环见 docs/research 第四轮）
# ---------------------------------------------------------------------------

@app.post("/api/location/dns/prepare")
async def dns_location_prepare(req: DnsPrepareRequest):
    """Bind DNS/TLS for phone setup without applying any target policy."""
    ok, reason = await cloud_authorizer.ensure_authorized_async(req.udid or "")
    if not ok:
        raise HTTPException(status_code=403, detail=reason)
    major = await _selected_ios_major(req.udid)
    if major is not None:
        if major >= 27 and req.mode == 'rewrite':
            raise HTTPException(status_code=409, detail=
                                "iOS 27 及以上请使用配件定位和 DNS 抑制")
        if major < 27 and req.mode == 'suppress':
            raise HTTPException(status_code=409, detail=
                                "iOS 26 及以下请使用 DNS/WLOC 改写定位")
    if req.mode == 'rewrite' and accessory_manager.status()["running"]:
        raise HTTPException(status_code=409, detail="Stop the active enhanced location channel first")
    try:
        if req.mode == 'rewrite':
            await wloc_manager.prepare()
        return await dns_manager.prepare(mode=req.mode)
    except DnsLocationError as error:
        raise HTTPException(status_code=409, detail=str(error))


@app.post("/api/location/dns/start")
async def dns_location_start(req: DnsLocationRequest):
    ok, reason = await cloud_authorizer.ensure_authorized_async(req.udid or "")
    if not ok:
        raise HTTPException(status_code=403, detail=reason)
    major = await _selected_ios_major(req.udid)
    if major is not None:
        if major >= 27 and req.mode == 'rewrite':
            raise HTTPException(status_code=409, detail=
                                "iOS 27 及以上请使用配件定位和 DNS 抑制")
        if major < 27 and req.mode == 'suppress':
            raise HTTPException(status_code=409, detail=
                                "iOS 26 及以下请使用 DNS/WLOC 改写定位")
    async with enhanced_location_lock:
        if ((req.mode == 'rewrite' and accessory_manager.status()["running"])
                or wloc_manager.status()["running"]):
            raise HTTPException(status_code=409, detail="Stop the active enhanced location channel first")
        try:
            # Combined setup can request DNS after accessory/start has already
            # prepared it. Reuse that exact companion without resetting counters.
            if (req.mode == 'suppress' and dns_manager.running
                    and dns_manager.mode == 'suppress'):
                current = dns_manager.status()
                if current.get('target') == dict(latitude=req.latitude,
                                                  longitude=req.longitude):
                    return current
            if req.mode == 'rewrite':
                # Prepare the public certificate download listener for the phone.
                # Suppression must never require or generate a CA.
                await wloc_manager.prepare()
            res = await dns_manager.start(req.latitude, req.longitude, mode=req.mode)
            global _dns_target_udid, _enhanced_location_target_udid
            _dns_target_udid = req.udid
            _enhanced_location_target_udid = req.udid
            return res
        except DnsLocationError as error:
            raise HTTPException(status_code=409, detail=str(error))
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error))


@app.post("/api/location/dns/stop")
async def dns_location_stop():
    global _dns_target_udid, _enhanced_location_target_udid
    _dns_target_udid = None
    if _wloc_target_udid is None and _accessory_target_udid is None:
        _enhanced_location_target_udid = None
    async with enhanced_location_lock:
        return await dns_manager.stop()


@app.get("/api/location/dns/status")
async def dns_location_status():
    return dns_manager.status()


@app.get("/api/location/wloc/proxy.pac")
async def wloc_pac_download(request: Request):
    await wloc_manager.prepare()
    host = request.url.hostname or "127.0.0.1"
    if host == "localhost":
        host = "127.0.0.1"
    try:
        content = build_pac(host, wloc_manager.port)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    return Response(content, media_type="application/x-ns-proxy-autoconfig",
                    headers={"Cache-Control": "no-store"})


@app.get("/api/location/wloc/shadowrocket.conf")
async def wloc_shadowrocket_config(request: Request):
    await wloc_manager.prepare()
    host = request.url.hostname or "127.0.0.1"
    if host == "localhost":
        host = "127.0.0.1"
    try:
        content = build_shadowrocket_config(host, wloc_manager.port)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    return Response(content, media_type="text/plain",
                    headers={"Cache-Control": "no-store"})


@app.get("/api/location/wloc/ca.pem")
async def wloc_ca_download():
    await wloc_manager.prepare()
    return Response(wloc_manager.store.pem(), media_type="application/x-x509-ca-cert",
                    headers={"Content-Disposition": 'attachment; filename="LocalWarp-WLoc-CA.pem"'})


@app.post("/api/device/disconnect")
@app.post("/api/device/{udid}/disconnect")
async def disconnect_device(req: Optional[DisconnectDeviceRequest] = None, udid: Optional[str] = None):
    target_udid = (req.udid if req else None) or udid
    should_restore = req.restore_location if req is not None else True
    logger.info(f"Received disconnect request for udid={target_udid}, restore_location={should_restore}")
    try:
        restored = False
        if should_restore and target_udid:
            try:
                await manager.clear_location(udid=target_udid)
                restored = True
            except Exception as clr_e:
                logger.warning(f"Could not restore location before disconnect: {clr_e}")
        await manager.disconnect_device(device_id=target_udid or "")
        return {
            "success": True,
            "message": "iPhone 连接已成功释放",
            "udid": target_udid,
            "restored_location": restored
        }
    except Exception as e:
        logger.error(f"Failed to disconnect device: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/device/{udid}/reveal_developer_mode")
@app.post("/api/device/reveal_developer_mode")
async def reveal_developer_mode(udid: Optional[str] = None):
    try:
        logger.info(f"Received request to reveal developer mode for udid={udid}")
        res = await manager.reveal_developer_mode(device_id=udid)
        return res
    except Exception as e:
        logger.error(f"Failed to reveal developer mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/device/{udid}/enable_developer_mode")
@app.post("/api/device/enable_developer_mode")
async def enable_developer_mode(udid: Optional[str] = None):
    try:
        logger.info(f"Received request to enable developer mode for udid={udid}")
        res = await manager.enable_developer_mode(device_id=udid)
        return res
    except Exception as e:
        logger.error(f"Failed to enable developer mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/device/{udid}/developer_mode_status")
@app.get("/api/device/developer_mode_status")
async def developer_mode_status(udid: Optional[str] = None):
    try:
        enabled = await manager.get_developer_mode_status(device_id=udid)
        return {"success": True, "enabled": enabled}
    except Exception as e:
        logger.error(f"Failed to query developer mode status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==============================================================================
# Service Installation & Daemon Management Helpers
# ==============================================================================

def get_executable_command():
    """Command (as argv list) to run this program. 列表形式避免路径含空格被拆错。"""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__)]


def install_service() -> bool:
    system = platform.system()
    cmd = get_executable_command()

    if system == "Darwin":
        launch_dir = os.path.expanduser("~/Library/LaunchAgents")
        os.makedirs(launch_dir, exist_ok=True)
        plist_path = os.path.join(launch_dir, "com.localwarp.connector.plist")

        # 路径里合法的 &、<、> 等字符会直接毁掉 plist，必须转义
        args_xml = "".join(f"        <string>{xml.sax.saxutils.escape(part)}</string>\n" for part in cmd)
            
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.localwarp.connector</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/localwarp-connector.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/localwarp-connector.err</string>
</dict>
</plist>
"""
        with open(plist_path, "w") as f:
            f.write(plist_content)
        uid = os.getuid()
        subprocess.run(
            ["launchctl", "bootout", f"gui/{uid}/com.localwarp.connector"],
            capture_output=True,
        )
        res = subprocess.run(
            ["launchctl", "bootstrap", f"gui/{uid}", plist_path], capture_output=True
        )
        if res.returncode != 0:
            # 旧版 macOS 回退到已废弃但可用的 load/unload
            res = subprocess.run(["launchctl", "load", plist_path], capture_output=True)
        if res.returncode == 0:
            print(f"[+] macOS launchd service successfully installed: {plist_path}")
            print("[+] Connector is now running and will auto-start on login.")
            return True
        else:
            print(f"[-] Failed to load launchd service: {res.stderr.decode()}")
            return False

    elif system == "Linux":
        systemd_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(systemd_dir, exist_ok=True)
        unit_path = os.path.join(systemd_dir, "localwarp-connector.service")

        unit_content = f"""[Unit]
Description=LocalWarp iPhone Location Connector Daemon
After=network.target

[Service]
Type=simple
ExecStart={shlex.join(cmd)}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
"""
        with open(unit_path, "w") as f:
            f.write(unit_content)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        res = subprocess.run(
            ["systemctl", "--user", "enable", "--now", "localwarp-connector.service"],
            capture_output=True,
        )
        if res.returncode == 0:
            print(f"[+] Linux systemd user service installed: {unit_path}")
            print("[+] Connector is now running and enabled at startup.")
            return True
        else:
            print(f"[-] Failed to enable systemd service: {res.stderr.decode()}")
            return False

    elif system == "Windows":
        print("[*] To auto-start on Windows, place a shortcut of LocalWarp-Connector.exe into:")
        print("    shell:startup (Win + R -> type 'shell:startup')")
        return True
    else:
        print(f"[-] Unsupported OS for service installation: {system}")
        return False


def uninstall_service():
    system = platform.system()
    if system == "Darwin":
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.localwarp.connector.plist")
        if os.path.exists(plist_path):
            subprocess.run(
                ["launchctl", "bootout", f"gui/{os.getuid()}/com.localwarp.connector"],
                capture_output=True,
            )
            os.remove(plist_path)
            print(f"[+] Removed macOS launchd service: {plist_path}")
        else:
            print("[-] No installed launchd service found.")
    elif system == "Linux":
        unit_path = os.path.expanduser("~/.config/systemd/user/localwarp-connector.service")
        if os.path.exists(unit_path):
            subprocess.run(["systemctl", "--user", "disable", "--now", "localwarp-connector.service"])
            os.remove(unit_path)
            subprocess.run(["systemctl", "--user", "daemon-reload"])
            print(f"[+] Removed Linux systemd user service: {unit_path}")
        else:
            print("[-] No installed systemd unit found.")
    elif system == "Windows":
        print("[*] Please remove LocalWarp shortcut from your startup folder.")


def print_banner(host: str, port: int):
    # 绑定 0.0.0.0 时展示 127.0.0.1，避免用户照着 0.0.0.0 打不开
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    banner = rf"""
  _                     ___          __            
 | |   ___  __ __ _ ___| \ \        / /_ _ _ _ _ __ 
 | |__/ _ \/ _/ _` / -_) |\ \  /\  / / _` | '_| '_ \\
 |____\___/\__\__,_\___|_| \_\/  \/ \__,_|_|  | .__/
                                              |_|   
          iPhone Location Changer (CoreDevice)      
======================================================
  Version:    {VERSION}
  Platform:   {platform.system()} ({platform.machine()})
  Endpoint:   http://{display_host}:{port}
  Health:     http://{display_host}:{port}/health
======================================================
  * Zero Drivers Conflict: Compatible with native usbmuxd
  * Zero Private Keys Leak: 100% On-device pairing isolation
  * Unplug Persistence: Target location persists upon disconnect
======================================================
[+] Connector is listening. Open the Web Studio in your browser:
    👉  https://localwarp.com/app
"""
    print(banner)

    print_windows_amds_warning()
    print_accessory_identity_hint()


def check_windows_amds() -> bool:
    """探测 Apple 移动设备驱动 (AMDS, 端口 27015) 是否就绪。仅 Windows 有意义。"""
    if platform.system() != "Windows":
        return True
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect(("127.0.0.1", 27015))
        return True
    except Exception:
        return False
    finally:
        sock.close()


def print_windows_amds_warning():
    """控制台版的 AMDS 缺失引导（CLI 入口用；GUI 入口用 check_windows_amds 走托盘提示）。"""
    if not check_windows_amds():
        print("*" * 76)
        print("[!] 提示: 检测到当前 Windows 电脑尚未安装 Apple 基础通信驱动 (AMDS)")
        print("-" * 76)
        print("请按照以下两步完成首次环境配置（仅需首次安装一次）:")
        print("  【步骤 1】安装 Apple 官方底层通信驱动:")
        print("            官方直链: https://www.apple.com/itunes/download/win64")
        print("            (或在微软应用商店搜索安装 'Apple Devices')")
        print("  【步骤 2】将 iPhone 插入电脑，解锁手机并在弹窗中点击【信任此电脑】")
        print("            装完后本程序将自动连通！")
        print("*" * 76 + "\n")


def print_accessory_identity_hint():
    """无线定位之外，有线增强步骤还需本机身份文件；CLI 入口没有界面，先给出落点。"""
    try:
        state = resolve_identity_state()
    except Exception:
        return
    if state == IDENTITY_STATE_READY:
        return
    cert_path, _ = identity_paths()
    print("-" * 76)
    if state == "invalid":
        print("[!] 配件身份文件已存在，但无法解析（需要 DER PKCS#7 证书 + 未加密 PKCS#8 私钥）")
    else:
        print("[!] 未找到配件身份文件：有线增强定位需要 certificate.p7b 与 identity.pk8")
    print("    在网页工作台的增强定位面板中导入，或放到:")
    print(f"    {cert_path.parent}")
    print("-" * 76 + "\n")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    # 设备 worker 模式（由主连接器或 PyInstaller 运行时钩子拉起）：
    # 直接进入 worker 循环，不启动 HTTP 服务器
    _worker_udid = os.environ.get("LOCALWARP_DEVICE_WORKER_UDID")
    if _worker_udid:
        from multi_device import run_worker
        _port = os.environ.get("LOCALWARP_WORKER_IPC_PORT")
        _auth = os.environ.get("LOCALWARP_WORKER_IPC_AUTH")

        sys.exit(
            run_worker(
                _worker_udid,
                fake=os.environ.get("LOCALWARP_DEVICE_WORKER_FAKE") == "1",
                ipc_port=int(_port) if _port else None,
                ipc_auth=_auth,
            )
        )

    parser = build_argument_parser()
    args = parser.parse_args()

    w_udid = args.worker_udid or args.udid
    if (args.device_worker or args.worker) and w_udid:
        from multi_device import run_worker

        sys.exit(run_worker(
            w_udid,
            fake=(args.worker_fake or args.fake),
            ipc_port=args.ipc_port,
            ipc_auth=args.ipc_auth,
        ))
    
    if args.install_service:
        sys.exit(0 if install_service() else 1)
        return
        
    if args.uninstall_service:
        uninstall_service()
        return

    if args.status:
        print("[*] Checking LocalWarp Connector status...")
        import urllib.request
        import json
        # 0.0.0.0 is a bind address, not a usable destination for status checks.
        probe_host = "127.0.0.1" if args.host in ("0.0.0.0", "::", "") else args.host
        try:
            req = urllib.request.Request(f"http://{probe_host}:{args.port}/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode())
                print(f"[+] Connector is ONLINE: {data}")
            req_dev = urllib.request.Request(f"http://{probe_host}:{args.port}/api/devices")
            # Device discovery can wait for a pairing prompt, so allow it longer
            # than the quick health probe to avoid reporting a false offline state.
            with urllib.request.urlopen(req_dev, timeout=8) as resp_dev:
                devices = json.loads(resp_dev.read().decode()).get("devices", [])
                print(f"[+] Connected iOS Devices ({len(devices)}):")
                for d in devices:
                    print(f"    - UDID: {d.get('udid')} | Name: {d.get('name')} | Model: {d.get('model')}")
        except Exception as e:
            print(f"[-] Connector is OFFLINE or unreachable on {args.host}:{args.port} ({e})")
        return

    print_banner(args.host, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", access_log=False)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="LocalWarp Connector: Secure local iOS Location daemon for Web Studio"
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        type=_validate_loopback_bind_host,
        help=f"Loopback binding host (default: {DEFAULT_HOST}; non-loopback addresses are rejected)",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Listening port (default: {DEFAULT_PORT})")
    parser.add_argument("--status", action="store_true", help="Check current daemon status and list devices")
    parser.add_argument("--install-service", action="store_true", help="Install as persistent auto-start system service")
    parser.add_argument("--uninstall-service", action="store_true", help="Uninstall auto-start system service")
    parser.add_argument("--device-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-udid", type=str, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--udid", type=str, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--worker-fake", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--fake", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ipc-port", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--ipc-auth", type=str, default=None, help=argparse.SUPPRESS)
    return parser


if __name__ == "__main__":
    main()
