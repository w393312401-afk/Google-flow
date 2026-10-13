"""Audit authenticated account-management calls without inspecting secrets."""

import asyncio
import inspect
import time
from functools import wraps

from fastapi import Request

from ..core.account_audit import audit_account_operation
from ..core.account_operation_context import (
    account_error_reason,
    account_operation_source,
)


_INTERNAL_SOURCES = {"cookie_sync", "login_host", "login_worker", "plugin"}
_SUCCESS_REASONS = {
    "create": "account_created", "update": "account_updated",
    "delete": "account_deleted", "enable": "manual_enable",
    "disable": "manual_disable", "import": "settings_updated",
    "refresh_at": "credentials_validated", "refresh_credits": "balance_refreshed",
    "batch_refresh": "batch_complete", "config_update": "settings_updated",
    "binding": "settings_updated",
}


def audit_account_api(operation: str, *, source: str = "admin", setting: str = ""):
    """Keep the handler's signature while injecting request provenance."""
    def decorate(handler):
        signature = inspect.signature(handler)

        @wraps(handler)
        async def wrapped(*args, **kwargs):
            request = kwargs.pop("_account_audit_request", None)
            bound = signature.bind_partial(*args, **kwargs)
            token_id = bound.arguments.get("token_id")
            body = bound.arguments.get("request")
            database = handler.__globals__.get("db")
            if source == "plugin":
                await handler.__globals__["_verify_plugin_connection_token"](
                    bound.arguments.get("authorization")
                )
            snapshot = None
            if token_id is not None and database is not None:
                try:
                    snapshot = await database.get_token(token_id)
                except Exception:
                    pass
            elif getattr(body, "login_account", None):
                snapshot = {
                    "email": body.login_account,
                    "adspower_serial": getattr(body, "adspower_serial", None),
                }
            current_source = source
            if request is not None:
                requested_source = request.headers.get("X-Account-Operation-Source")
                if requested_source in _INTERNAL_SOURCES:
                    current_source = requested_source
            context = account_operation_source.set(current_source)
            started = time.monotonic()
            try:
                await audit_account_operation(
                    database, token_id, operation=operation, status="started",
                    stage="request", source=current_source, token=snapshot,
                    details={"setting": setting} if setting else None,
                )
                try:
                    result = await handler(*args, **kwargs)
                except asyncio.CancelledError:
                    await audit_account_operation(
                        database, token_id, operation=operation, status="failed",
                        reason="operation_cancelled", stage="request",
                        source=current_source, token=snapshot,
                    )
                    raise
                except Exception as error:
                    details = {"duration_ms": round((time.monotonic() - started) * 1000)}
                    status_code = getattr(error, "status_code", None)
                    if isinstance(status_code, int):
                        details["http_status"] = status_code
                    await audit_account_operation(
                        database, token_id, operation=operation, status="failed",
                        reason=account_error_reason(error), stage="request",
                        source=current_source, token=snapshot, details=details,
                    )
                    raise
                if token_id is None and isinstance(result, dict):
                    created = result.get("token")
                    if isinstance(created, dict) and isinstance(created.get("id"), int):
                        token_id = created["id"]
                details = {"duration_ms": round((time.monotonic() - started) * 1000)}
                if setting:
                    details["setting"] = setting
                if isinstance(result, dict):
                    for original, target in (
                        ("total", "total"), ("success_count", "success_count"),
                        ("failed_count", "failed_count"), ("imported_count", "count"),
                        ("succeeded", "success_count"), ("failed", "failed_count"),
                        ("added", "created"), ("updated", "updated"),
                    ):
                        value = result.get(original)
                        if isinstance(value, int):
                            details[target] = value
                    if operation == "import" and isinstance(result.get("errors"), list):
                        details["failed_count"] = len(result["errors"])
                failed = isinstance(result, dict) and result.get("success") is False
                partial_failed = details.get("failed_count", 0) > 0
                success_reason = "low_balance_disabled" if current_source == "cookie_sync" and operation == "disable" else _SUCCESS_REASONS.get(operation, "settings_updated")
                await audit_account_operation(
                    database, token_id, operation=operation,
                    status="failed" if failed or partial_failed else "success",
                    reason="operation_failed" if failed else "batch_partial_failed" if partial_failed else success_reason,
                    stage="request", source=current_source,
                    token=snapshot, details=details,
                )
                return result
            finally:
                account_operation_source.reset(context)

        wrapped.__signature__ = signature.replace(parameters=[
            *signature.parameters.values(),
            inspect.Parameter(
                "_account_audit_request", inspect.Parameter.KEYWORD_ONLY,
                default=None, annotation=Request,
            ),
        ])
        return wrapped
    return decorate
