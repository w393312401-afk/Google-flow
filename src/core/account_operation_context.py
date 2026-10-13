"""Request provenance for account operation logs, without credential data."""

from contextvars import ContextVar
import re


account_operation_source: ContextVar[str] = ContextVar(
    "account_operation_source", default="system"
)


def operation_source(default: str = "system") -> str:
    source = account_operation_source.get()
    return default if source == "system" else source


def account_error_reason(error) -> str:
    """Map an exception to a fixed category; never return its contents."""
    detail = getattr(error, "detail", error)
    text = str(detail or "").lower()
    status = getattr(error, "status_code", None)
    if any(marker in text for marker in (
        "credentials rejected", "unauthenticated", "google cookies 不完整",
        "页面已跳转到 google 登录", "cookie 被拒绝", "登录态已失效",
    )) or status == 401:
        return "credentials_rejected"
    if any(marker in text for marker in (
        "public_error_unusual_activity", "traffic restriction", "上游流量限制", "上游限制流量",
    )):
        return "traffic_restriction"
    if any(marker in text for marker in (
        "network or proxy", "connection", "connect", "timeout", "timed out",
        "curl", "proxy", "network", "dns", "ssl", "tls",
        "网络或代理", "代理/网络", "网络暂时不可用",
    )):
        return "network_or_proxy_unavailable"
    if "metadata" in text:
        return "frontend_metadata_unavailable"
    if re.search(r"\bupstream unavailable \(http [45]\d{2}\)", text):
        return "upstream_unavailable"
    if status is not None and 500 <= status <= 599:
        return "upstream_unavailable"
    return "operation_failed"
