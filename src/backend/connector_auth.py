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
"""

import re
import threading
import time
from typing import Callable, Dict, Optional, Tuple

import requests

# 云端返回的 cacheMs 与本地缓存上限（毫秒）
CLOUD_CACHE_CAP_MS = 5 * 60 * 1000
# 拒绝结论的短缓存：避免到期后每次写入都打云端
DENIAL_CACHE_MS = 60 * 1000
# 云端请求超时（秒）：超时视为不可达，拒绝本次写入
CLOUD_TIMEOUT_S = 5.0

# 生产固定受信任云端地址白名单（仅固定生产 HTTPS 域名）：
#  - https://localwarp.com / https://www.localwarp.com（生产）
PROD_TRUSTED_CLOUD_ORIGIN = re.compile(
    r"^https://(www\.)?localwarp\.com$",
    re.IGNORECASE,
)

# 仅供开发测试隔离环境（未包含在生产发行物信任集合中）
DEV_TRUSTED_CLOUD_ORIGIN = re.compile(
    r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$"
    r"|^http://(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(:\d+)?$",
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



class CloudAuthorizer:
    """在线授权 + 单调时钟内存缓存。线程安全。"""

    def __init__(
        self,
        post_json: Optional[Callable[[str, dict], Tuple[int, dict]]] = None,
        monotonic: Callable[[], float] = time.monotonic,
        allow_dev: bool = False,
    ):
        # post_json(url, payload) -> (status_code, parsed_json)；生产使用
        # requests，测试注入假云端应答，不发起真实网络请求
        self._post_json = post_json or self._real_post_json
        self._monotonic = monotonic
        self._allow_dev = allow_dev
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._cloud_url: Optional[str] = None
        # udid -> (allowed, deadline_monotonic_s, reason)
        self._cache: Dict[str, Tuple[bool, float, Optional[str]]] = {}

    # ------------------------------------------------------------------
    # 配对（网页调用）
    # ------------------------------------------------------------------
    def configure(
        self, token: str, cloud_url: str, udid: Optional[str] = None
    ) -> Tuple[bool, str]:
        """保存配对凭证并立即与云端确认一次。"""
        if not token or not isinstance(token, str):
            return False, "missing token"
        if not is_trusted_cloud_url(cloud_url, allow_dev=self._allow_dev):
            return False, "untrusted cloud url"
        with self._lock:
            self._token = token
            self._cloud_url = cloud_url.rstrip("/")
            self._cache.clear()
        if udid:
            ok, reason = self.ensure_authorized(udid)
            if not ok:
                return False, reason
        return True, "paired"

    @property
    def is_paired(self) -> bool:
        with self._lock:
            return self._token is not None

    def reset(self) -> None:
        """清除内存中的凭证与缓存（测试与显式解绑用）。"""
        with self._lock:
            self._token = None
            self._cloud_url = None
            self._cache.clear()

    # ------------------------------------------------------------------
    # 写入前检查
    # ------------------------------------------------------------------
    def ensure_authorized(self, udid: str) -> Tuple[bool, str]:
        """
        定位写入前的强制检查。返回 (allowed, reason)。

        缓存命中（含拒绝短缓存）直接返回；未命中或过期则在线复核：
        - allowed=True  -> 缓存 min(cloud cacheMs, 5min) 的单调时钟截止
        - allowed=False -> 缓存 60s 的拒绝结论
        - 云端不可达    -> 拒绝且不缓存（下次写入重试）
        """
        if not udid:
            return False, "missing target device"
        with self._lock:
            token = self._token
            cloud_url = self._cloud_url
            cached = self._cache.get(udid)
            now = self._monotonic()
            if cached is not None:
                allowed, deadline, reason = cached
                if now < deadline:
                    return allowed, reason or ("not authorized" if not allowed else "authorized")

            if not token or not cloud_url:
                return False, (
                    "not paired: open the LocalWarp web studio to authorize this connector"
                )

        try:
            status, data = self._post_json(
                f"{cloud_url}/api/connector/authorize",
                {"token": token, "udid": udid},
            )
        except Exception:
            # 云端不可达：暂停新增定位操作；恢复真实定位不受影响
            return False, "cloud unreachable: location writes paused, retry shortly"

        if status == 200 and data.get("allowed") is True:
            cache_ms = data.get("cacheMs") or CLOUD_CACHE_CAP_MS
            cache_ms = max(1000, min(int(cache_ms), CLOUD_CACHE_CAP_MS))
            deadline = self._monotonic() + cache_ms / 1000.0
            with self._lock:
                self._cache[udid] = (True, deadline, None)
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
        deadline = self._monotonic() + DENIAL_CACHE_MS / 1000.0
        with self._lock:
            self._cache[udid] = (False, deadline, detail)
        return False, detail

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
authorizer = CloudAuthorizer()
