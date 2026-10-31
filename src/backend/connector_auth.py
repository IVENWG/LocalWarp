#!/usr/bin/env python3
"""
LocalWarp Connector — Cloud Entitlement Authorization Guard
-----------------------------------------------------------
在线确认 + 短期内存缓存的定位写入门禁。

- 令牌由网页端配对后推送到 /api/auth/configure，只存内存；重启即失效，
  网页加载时会自动重新配对。
- 云端地址限制为可信白名单（生产域名 + 本机/局域网开发地址），防止任意
  验证地址与凭证泄露。
- 每次定位写入前检查本地授权是否仍有效；缓存用单调时钟，最长 5 分钟，
  且绝不超过云端返回的剩余有效时长。
- 缓存到期且云端不可用时暂停新增定位操作（恢复真实定位不受影响）。
- 不接受浏览器发来的 isPaid / expiresAt / userId 作为授权依据；授权结论
  只来自受信云端的 /api/connector/authorize 应答。

多设备（v1.5+）：
- 云端 connector token 绑定单台设备（deviceHash），凭证按 UDID 独立登记——
  给设备 B 配对/重新配对不影响设备 A 的凭证与缓存结论。
- 旧版「不带 udid 配置」作为共享凭证保留（向后兼容），但它不构成任意设备
  的本地授权：用它校验任何 UDID 时，是否放行仍由云端按 deviceHash 判定
  （不匹配即 device_mismatch 拒绝）。
- 撤销安全（epoch 防复活）：reset()/重新配对会推进凭证纪元；在此之前的
  在途云端请求即使稍后返回 allowed=True，也不得写入缓存、不得被当前操作
  当成有效允许。
"""

import asyncio
import base64
import json
import os
import re
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional, Tuple

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# 云端返回的 cacheMs 与本地缓存上限（毫秒）
CLOUD_CACHE_CAP_MS = 5 * 60 * 1000
# 拒绝结论的短缓存：避免到期后每次写入都打云端
DENIAL_CACHE_MS = 60 * 1000
# 云端请求超时（秒）：超时视为不可达，拒绝本次写入
CLOUD_TIMEOUT_S = 5.0

# 资源保护上限（纯工程护栏，防任意 UDID 探测撑爆内存；非商业设备数限制）
MAX_PAIRED_UDIDS = 64
_MAX_CACHE_ENTRIES = 256

# Ed25519 验证公钥配置（连接器仅持公钥，私钥留在云端，零数据库查密钥）
# 轮换为 v2，废弃已在旧源码中出现过的 v1 密钥与公钥
AUTH_KID = "lw-ed25519-v2"
DEFAULT_PUBLIC_KEY_HEX = os.getenv("WORKER_AUTH_PUBLIC_KEY") or (
    "523c70f14ee0bed30f478543450c56b3fb93b0d30236040d50cf09bd027b33dd"
)

_default_authorizer: Optional["CloudAuthorizer"] = None


def get_default_authorizer() -> Optional["CloudAuthorizer"]:
    return _default_authorizer


def set_default_authorizer(authorizer: Optional["CloudAuthorizer"]) -> None:
    global _default_authorizer
    _default_authorizer = authorizer


def _base64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def verify_lease_token(
    token: str, trusted_keys: Optional[Dict[str, bytes]] = None
) -> Optional[dict]:
    """验证紧凑型 JWS (header.payload.signature) 格式的连接器本地租约凭证。

    连接器本地持验证公钥，验证云端签名、kid、iss、aud、scope、有效期与目标设备。
    验证通过返回 payload 字典；任何篡改、伪造、过期、超长或字段不匹配返回 None。
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_base64url_decode(header_b64).decode("utf-8"))
        if header.get("alg") != "Ed25519":
            return None
        kid = header.get("kid")
        keys = trusted_keys or {AUTH_KID: bytes.fromhex(DEFAULT_PUBLIC_KEY_HEX)}
        pub_bytes = keys.get(kid)
        if not pub_bytes:
            return None

        sig = _base64url_decode(sig_b64)
        data = f"{header_b64}.{payload_b64}".encode("ascii")

        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig, data)

        payload = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
        if payload.get("iss") != "localwarp-cloud":
            return None
        if payload.get("aud") != "localwarp-connector":
            return None
        if payload.get("scope") != "location:write":
            return None

        sub = payload.get("sub")
        if not sub or not isinstance(sub, str):
            return None

        now_ts = time.time()
        iat = payload.get("iat")
        exp = payload.get("exp")
        if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
            return None

        # 防未来签发：允许最多 60 秒时钟微小偏差，超过则拒绝
        if iat > now_ts + 60.0 or iat <= 0:
            return None

        # 防过期凭证与超长有效时间（连接器租约硬限制最长 360 秒）
        if exp <= now_ts:
            return None
        if exp <= iat or (exp - iat) > 360.0:
            return None

        return payload
    except Exception:
        return None

# 生产固定受信任云端地址白名单（仅固定生产 HTTPS 域名）：
#  - https://localwarp.com / https://www.localwarp.com（生产）
PROD_TRUSTED_CLOUD_ORIGIN = re.compile(
    r"^https://(www\.)?localwarp\.com$",
    re.IGNORECASE,
)

# 仅供本机开发测试隔离环境（未包含在生产发行物信任集合中；仅限回环地址）
DEV_TRUSTED_CLOUD_ORIGIN = re.compile(
    r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$",
    re.IGNORECASE,
)


def is_trusted_cloud_url(url: str, allow_dev: bool = False) -> bool:
    """云端地址必须精确匹配白名单 origin（无路径、无查询、无碎片）。生产发行物仅信任生产 HTTPS 授权服务。"""
    if not url:
        return False
    trimmed = url.strip()
    if PROD_TRUSTED_CLOUD_ORIGIN.match(trimmed):
        return True
    if allow_dev and DEV_TRUSTED_CLOUD_ORIGIN.match(trimmed):
        return True
    return False


# 凭证快照：请求发起时刻的 (token, cloud_url, source_key, cred_epoch)
_CredentialSnapshot = Tuple[str, str, str, int]
# 缓存条目：(allowed, deadline_monotonic_s, reason, source_key, cred_epoch)
_CacheEntry = Tuple[bool, float, Optional[str], str, int]


class CloudAuthorizer:
    """在线授权 + 单调时钟内存缓存。线程安全。"""

    _LEGACY_SOURCE = "legacy"

    def __init__(
        self,
        post_json: Optional[Callable[[str, dict], Tuple[int, dict]]] = None,
        monotonic: Callable[[], float] = time.monotonic,
        allow_dev: bool = False,
        trusted_public_keys: Optional[Dict[str, bytes]] = None,
    ):
        # post_json(url, payload) -> (status_code, parsed_json)；生产使用
        # requests，测试注入假云端应答，不发起真实网络请求
        self._post_json = post_json or self._real_post_json
        self._monotonic = monotonic
        self._allow_dev = allow_dev
        self._trusted_public_keys = trusted_public_keys or {
            AUTH_KID: bytes.fromhex(DEFAULT_PUBLIC_KEY_HEX)
        }
        self._lock = threading.Lock()
        self._reset_timestamp = 0.0
        self._instance_id = uuid.uuid4().hex
        self._revoked_tokens: Set[str] = set()
        set_default_authorizer(self)
        # 本地 Ed25519 签名租约字典：udid -> (token, payload, deadline_monotonic_s)。
        # 本地持有公钥核验，无需向云端发送网络请求，D1 读写为 0。
        self._leases: Dict[str, Tuple[str, dict, float]] = {}
        # 按 UDID 独立的凭证注册表：udid -> (token, cloud_url, cred_epoch)。
        # 每台设备用自己 deviceHash 签发的 token 配对，互不覆盖；重新配对推进
        # 纪元，作废该设备此前一切在途云端结论（防撤销后复活）。
        self._pairings: Dict[str, Tuple[str, str, int]] = {}
        # 旧版单设备凭证 (token, cloud_url, cred_epoch)：对任意 UDID 的校验请求
        # 生效，但是否放行仍由云端按 deviceHash 判定，不会本地放行
        self._legacy: Tuple[Optional[str], Optional[str], int] = (None, None, 0)
        # 全局单调递增的凭证纪元计数（reset / 任何 configure 都推进）
        self._epoch_counter = 0
        self._cache: Dict[str, _CacheEntry] = {}
        # 异步路径的按 UDID 单飞任务（只在事件循环内访问，无需线程锁）：
        # 同设备缓存过期时 N 个并发写入共享一次云端请求
        self._inflight: Dict[str, "asyncio.Task[Tuple[bool, str]]"] = {}

    # ------------------------------------------------------------------
    # 凭证快照 / 缓存辅助（须持 self._lock 调用）
    # ------------------------------------------------------------------
    def _snapshot_locked(self, udid: str) -> Optional[_CredentialSnapshot]:
        """该 UDID 当前应使用的凭证；无任何配对时返回 None。"""
        pairing = self._pairings.get(udid)
        if pairing is not None:
            token, url, epoch = pairing
            return token, url, f"udid:{udid}", epoch
        token, url, epoch = self._legacy
        if token and url:
            return token, url, self._LEGACY_SOURCE, epoch
        return None

    def _cache_valid_locked(self, udid: str, snap: Optional[_CredentialSnapshot]) -> bool:
        """缓存结论只在「凭证未变」时有效：纪元不匹配一律作废。"""
        entry = self._cache.get(udid)
        if entry is None or snap is None:
            return False
        return entry[3] == snap[2] and entry[4] == snap[3]

    def _prune_cache_locked(self) -> None:
        """缓存条目数超界时优先清掉已过期项（资源护栏，条目按 UDID 有界）。"""
        if len(self._cache) <= _MAX_CACHE_ENTRIES:
            return
        now = self._monotonic()
        expired = [u for u, e in self._cache.items() if e[1] <= now]
        for u in expired:
            del self._cache[u]

    # ------------------------------------------------------------------
    # 配对（网页调用）
    # ------------------------------------------------------------------
    def configure(
        self, token: str, cloud_url: str, udid: Optional[str] = None
    ) -> Tuple[bool, str]:
        """保存配对凭证并立即确认。

        - 若 token 为 Ed25519 签名租约 (v2 紧凑 JWS)：
          本地直接通过内置公钥核查签名、目标设备与有效期，放行后存入内存。
          完全不发起网络请求，不读写 D1，零数据库消耗。
        - 若 token 为旧版配对令牌 (v1.x)：
          保留在线确认流程（写入云端/确认后缓存 5 分钟），保证向后兼容。
        """
        if not token or not isinstance(token, str):
            return False, "missing token"
        if not is_trusted_cloud_url(cloud_url, allow_dev=self._allow_dev):
            return False, "untrusted cloud url"
        normalized = cloud_url.rstrip("/")

        # 优先检测与核验 Ed25519 签名租约 (v2 协议)
        parts = token.strip().split(".")
        if len(parts) == 3:
            payload = verify_lease_token(token, self._trusted_public_keys)
            if payload is None:
                return False, "invalid lease token: signature verification failed"

            target_udid = udid or payload.get("udid")
            if not target_udid:
                return False, "missing target device"

            token_udid = payload.get("udid")
            if token_udid and token_udid != target_udid:
                return False, "device mismatch: lease bound to another device"

            # 连接器会话/实例挑战核验 (CID)：对于 v2 签名租约，强制核验 cid 与当前连接器 instance_id 严格一致
            # 彻底隔离 reset 和重启后的重放
            iat = payload.get("iat", 0)
            cid = payload.get("cid")
            if not cid or cid != self._instance_id:
                return False, "connector session mismatch: lease token was issued for another connector session (replay rejected)"

            exp = payload.get("exp", 0)
            now_ts = time.time()
            if exp <= now_ts:
                return False, "lease token already expired"

            remaining_s = exp - now_ts
            lease_deadline = self._monotonic() + min(
                remaining_s, CLOUD_CACHE_CAP_MS / 1000.0
            )

            with self._lock:
                self._epoch_counter += 1
                self._leases[target_udid] = (token, payload, lease_deadline)
                self._cache.pop(target_udid, None)

            return True, f"authorized (local lease for {target_udid})"

        # 旧版配对协议流程（向后兼容）
        if udid:
            with self._lock:
                if udid not in self._pairings and len(self._pairings) >= MAX_PAIRED_UDIDS:
                    self._prune_cache_locked()
                    return False, (
                        f"too many paired devices on this connector (resource limit {MAX_PAIRED_UDIDS})"
                    )
                self._epoch_counter += 1
                self._pairings[udid] = (token, normalized, self._epoch_counter)
                self._cache.pop(udid, None)
            ok, reason = self.ensure_authorized(udid)
            if not ok:
                return False, reason
            return True, f"paired for device {udid}"
        with self._lock:
            self._epoch_counter += 1
            self._legacy = (token, normalized, self._epoch_counter)
            for u in [u for u, e in self._cache.items() if e[3] == self._LEGACY_SOURCE]:
                del self._cache[u]
        return True, "paired"

    async def configure_async(
        self, token: str, cloud_url: str, udid: Optional[str] = None
    ) -> Tuple[bool, str]:
        """configure 的异步版：同步云端确认放到线程池执行，绝不阻塞事件循环。

        预算 = 云端请求超时 + 3s 余量。超时按失败上报（线程内的 configure 稍后
        可能完成，幂等可重试；其结论受纪元保护，不会复活已撤销的授权）。
        """
        if not token or not isinstance(token, str):
            return False, "missing token"
        if not is_trusted_cloud_url(cloud_url, allow_dev=self._allow_dev):
            return False, "untrusted cloud url"
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self.configure, token, cloud_url, udid),
                timeout=CLOUD_TIMEOUT_S + 3.0,
            )
        except asyncio.TimeoutError:
            return False, "cloud unreachable: pairing confirmation timed out, retry shortly"

    @property
    def is_paired(self) -> bool:
        with self._lock:
            return (
                bool(self._leases)
                or bool(self._pairings)
                or self._legacy[0] is not None
            )

    def paired_udids(self) -> List[str]:
        """已按 UDID 独立配对或持有签名租约的设备列表。"""
        with self._lock:
            all_udids = set(self._pairings.keys()) | set(self._leases.keys())
            return sorted(all_udids)

    @property
    def instance_id(self) -> str:
        with self._lock:
            return self._instance_id

    def reset(self) -> None:
        """清除内存中的全部凭证、本地租约与缓存，并作废一切在途云端结论（测试与显式解绑用）。"""
        with self._lock:
            for tok, _, _ in self._leases.values():
                self._revoked_tokens.add(tok)
            for tok, _, _ in self._pairings.values():
                self._revoked_tokens.add(tok)
            if self._legacy[0]:
                self._revoked_tokens.add(self._legacy[0])
            self._leases.clear()
            self._pairings.clear()
            self._legacy = (None, None, 0)
            self._cache.clear()
            self._epoch_counter += 1
            self._reset_timestamp = time.time()
            self._instance_id = uuid.uuid4().hex

    def is_authorized_local(self, udid: str) -> bool:
        """纯本地单调时钟检查当前设备是否仍处于有效授权期内（不打网络）。供后台持续服务轮询。"""
        if not udid:
            return False
        with self._lock:
            lease = self._leases.get(udid)
            if lease is not None:
                token, payload, deadline = lease
                return self._monotonic() < deadline and time.time() < payload.get("exp", 0)
            cached = self._cache.get(udid)
            if cached is not None:
                allowed, deadline, _, _, _ = cached
                now = self._monotonic()
                # T-F5 修复：对于旧协议（基于云端配对的单设备/多设备缓存），
                # 当缓存距离到期不足 60 秒或已刚过期（给最多 60 秒宽限期）时，
                # 在后台异步单飞触发云端续核，绝不阻塞当前守卫，亦不让持续定位服务因无人主动写入而误停。
                if allowed and (deadline - now < 60.0):
                    self._trigger_background_legacy_refresh(udid)
                return allowed and (now < deadline + 30.0)
            return False

    def _trigger_background_legacy_refresh(self, udid: str) -> None:
        """非阻塞后台调度异步刷新任务（仅限旧协议缓存路径）"""
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running() and udid not in self._inflight:
                task = loop.create_task(self._refresh_authorized_task(udid, force=True))
                self._inflight[udid] = task
                task.add_done_callback(lambda _t, u=udid: self._inflight.pop(u, None))
        except RuntimeError:
            pass

    # ------------------------------------------------------------------
    # 写入前检查
    # ------------------------------------------------------------------
    def ensure_authorized(self, udid: str) -> Tuple[bool, str]:
        """
        定位写入前的强制检查。返回 (allowed, reason)。

        - v2 签名租约优先：本地验签且未过期时，直接放行，不请求云端，0 D1 读写。
        - 租约过期：明确拒绝并要求刷新工作台续租，不盲目打云端。
        - v1 旧版配对：缓存命中直接返回，未命中则在线复核云端。
        """
        if not udid:
            return False, "missing target device"
        with self._lock:
            # 优先使用本地 Ed25519 签名租约 (v2 协议：0 云端 HTTP，0 D1 读写)
            lease = self._leases.get(udid)
            if lease is not None:
                token, payload, deadline = lease
                now_mono = self._monotonic()
                now_ts = time.time()
                if now_mono < deadline and now_ts < payload.get("exp", 0):
                    return True, "authorized"
                return False, "lease expired: refresh workbench to renew authorization"

            snap = self._snapshot_locked(udid)
            cached = self._cache.get(udid)
            if cached is not None and self._cache_valid_locked(udid, snap):
                allowed, deadline, reason = cached[0], cached[1], cached[2]
                if self._monotonic() < deadline:
                    return allowed, reason or ("not authorized" if not allowed else "authorized")
        return self._query_cloud_and_update_cache(udid)

    def _query_cloud_and_update_cache(self, udid: str) -> Tuple[bool, str]:
        """强制向云端复核授权状态并原子写入缓存（受纪元保护）"""
        with self._lock:
            snap = self._snapshot_locked(udid)
            if snap is None:
                return False, (
                    "not paired: open the LocalWarp web studio to authorize this connector"
                )
        token, cloud_url, source_key, cred_epoch = snap

        try:
            status, data = self._post_json(
                f"{cloud_url}/api/connector/authorize",
                {"token": token, "udid": udid},
            )
        except Exception:
            # 云端不可达：暂停新增定位操作；恢复真实定位不受影响
            return False, "cloud unreachable: location writes paused, retry shortly"

        allowed, detail = self._interpret_cloud_response(status, data)
        deadline = self._monotonic() + (
            self._allow_cache_ms(data) if allowed else DENIAL_CACHE_MS
        ) / 1000.0
        with self._lock:
            cur = self._snapshot_locked(udid)
            if cur is None or cur[3] != cred_epoch:
                # 请求在途期间凭证被撤销/替换：过晚结论作废，绝不落缓存
                return False, "authorization state changed: retry the request"
            self._cache[udid] = (allowed, deadline, detail if not allowed else None, source_key, cred_epoch)
            self._prune_cache_locked()
        return allowed, detail

    def _allow_cache_ms(self, data: dict) -> int:
        cache_ms = data.get("cacheMs") if isinstance(data, dict) else None
        cache_ms = cache_ms or CLOUD_CACHE_CAP_MS
        return max(1000, min(int(cache_ms), CLOUD_CACHE_CAP_MS))

    @staticmethod
    def _interpret_cloud_response(status: int, data: dict) -> Tuple[bool, str]:
        if status == 200 and isinstance(data, dict) and data.get("allowed") is True:
            return True, "authorized"
        reason = data.get("reason") if isinstance(data, dict) else None
        if reason in ("free", "trial_expired", "paid_expired"):
            detail = (
                "plan expired: upgrade at https://localwarp.com/pricing to continue. "
                "Restoring your real GPS always works."
            )
        elif reason == "device_mismatch":
            detail = (
                "device mismatch: this connector is paired with a different iPhone"
            )
        elif reason == "invalid_or_expired_pairing":
            detail = (
                "pairing expired: reopen the LocalWarp web studio to re-authorize"
            )
        else:
            detail = f"not authorized by cloud ({reason or status})"
        return False, detail

    # ------------------------------------------------------------------
    # 异步入口（FastAPI 事件循环内使用，绝不阻塞其它设备的会话）
    # ------------------------------------------------------------------
    def _cached_decision(self, udid: str) -> Optional[Tuple[bool, str]]:
        """缓存命中时的即时结论；未命中/过期/凭证已变返回 None（零开销快路径）。"""
        if not udid:
            return False, "missing target device"
        with self._lock:
            # 优先检查本地 Ed25519 签名租约
            lease = self._leases.get(udid)
            if lease is not None:
                token, payload, deadline = lease
                now_mono = self._monotonic()
                now_ts = time.time()
                if now_mono < deadline and now_ts < payload.get("exp", 0):
                    return True, "authorized"
                return False, "lease expired: refresh workbench to renew authorization"

            snap = self._snapshot_locked(udid)
            if snap is None:
                return None
            entry = self._cache.get(udid)
            if entry is not None and self._cache_valid_locked(udid, snap):
                allowed, deadline, reason = entry[0], entry[1], entry[2]
                if self._monotonic() < deadline:
                    return allowed, reason or ("not authorized" if not allowed else "authorized")
        return None

    async def ensure_authorized_async(self, udid: str) -> Tuple[bool, str]:
        """ensure_authorized 的异步版。

        - 缓存命中（10Hz 写入的常态）：直接返回，不占线程、不让出循环，
          开销与同步版一致。
        - 缓存过期：云端请求放到线程池执行（requests 是阻塞 IO，直接 await
          会冻结事件循环、卡住所有设备的写入）。
        - 单飞去重：同设备的并发写入共享一个独立的刷新任务；任一等待者被
          取消（asyncio.shield）既不会取消共享任务，也不会破坏其它等待者。
        - 预算 = 云端超时 + 3s：超时/异常都收敛为「拒绝本次写入」的结论，
          线程内结果受纪元保护，稍后返回也无法复活已撤销的授权。
        """
        cached = self._cached_decision(udid)
        if cached is not None:
            return cached
        if not udid:
            return False, "missing target device"
        task = self._inflight.get(udid)
        if task is None or task.done():
            task = asyncio.create_task(self._refresh_authorized_task(udid))
            self._inflight[udid] = task

            def _drop_when_done(_t, udid=udid):
                if self._inflight.get(udid) is _t:
                    self._inflight.pop(udid, None)

            task.add_done_callback(_drop_when_done)
        # shield：本等待者被取消时，共享刷新任务与其它等待者不受影响
        return await asyncio.shield(task)

    async def _refresh_authorized_task(self, udid: str, force: bool = False) -> Tuple[bool, str]:
        """独立的刷新任务：无论超时/取消/异常都收敛为 (allowed, reason) 元组，
        绝不向等待者抛异常（避免 UnboundLocal/未决 Future 类问题）。"""
        target_fn = self._query_cloud_and_update_cache if force else self.ensure_authorized
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(target_fn, udid),
                timeout=CLOUD_TIMEOUT_S + 3.0,
            )
        except asyncio.TimeoutError:
            return False, "cloud check timed out: location writes paused, retry shortly"
        except asyncio.CancelledError:
            # 仅事件循环关停等场景会走到这里：拒绝而非放行，等待者可重试
            return False, "authorization check cancelled: retry shortly"
        except Exception as e:
            return False, f"authorization check failed: {e}"

    # ------------------------------------------------------------------
    # 真实网络实现
    # ------------------------------------------------------------------
    @staticmethod
    def _real_post_json(url: str, payload: dict) -> Tuple[int, dict]:
        resp = requests.post(
            url,
            json=payload,
            timeout=CLOUD_TIMEOUT_S,
            headers={"Content-Type": "application/json"},
            allow_redirects=False,
        )
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            return 400, {"error": "redirect not allowed for cloud authorization"}
        try:
            data = resp.json()
        except ValueError:
            data = {}
        return resp.status_code, data


# 模块级单例：server.py 直接使用
authorizer = CloudAuthorizer(
    allow_dev=os.getenv("LOCALWARP_ALLOW_DEV") == "1"
)
