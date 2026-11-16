"""Small, credential-free account audit events; usable by stdlib-only workers.

This is a best-effort audit trail, never a second credential store. Every writer
uses the same allowlists, and failures deliberately return None without logging
exception text or interfering with the account operation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import closing
import hashlib
import json
import math
import os
import re
import sqlite3


OPERATIONS = frozenset("""unknown create update delete enable disable import export
config_update refresh_at refresh_st refresh_credits protocol_refresh cookie_sync
auto_login health_check exit_rotation generation batch_refresh binding
account_selection project""".split())
STATUSES = frozenset("""unknown started success failed deferred skipped unchanged
disabled enabled cooldown info""".split())
SOURCES = frozenset("""unknown admin system scheduler cookie_sync login_worker
login_host protocol_refresh generation exit_rotation import plugin history""".split())
STAGES = frozenset("""unknown AT_CHECK AT_REFRESH AT_VERIFY ST_REFRESH
PROTOCOL_REFRESH TOKEN_VALIDATION sync login verify auth network config balance
source credentials preflight lease browser_start worker config_recheck
state_recheck binding_recheck identity_verify final_recheck outcome recover
recovery_failed validation selection submitted completed prepare rotation
request result create update delete enable disable import export batch
health probe credits binding login_recovery cookie_read proxy_check browser_close""".split()) | {""}
STAGES |= frozenset("""validation recovery page_probe account_state settings
project routing protocol verification history""".split())
STAGES |= frozenset("""navigation page_loaded editor_readiness editor_wait
editor_input submit_button page_warmup recaptcha_readiness native_page_prepare
native_page_prepare_retry native_editor_input native_submit_prepare native_submit
native_generation_setup native_frame_upload native_submit_control exit_rotation""".split())
REASONS = frozenset("""unknown account_created account_updated account_deleted
manual_enable manual_disable credentials_updated credentials_validated
authentication_failed credentials_rejected credential_recovery_required network_or_proxy_unavailable
traffic_restriction upstream_unavailable frontend_metadata_unavailable
validation_failed consecutive_errors threshold_reached rate_limit cooldown_elapsed
frontend_probe_passed protocol_refresh_failed protocol_refreshed balance_refreshed
project_created project_selected account_selected rotation_due rotation_complete
rotation_failed batch_started batch_complete settings_updated imported_disabled
imported_expired export_complete operation_failed cookie_sync_requested
pool_sync_requested login_requested low_balance_disable_requested pool_complete
pool_partial_failed pool_failed_safe pool_already_running history_snapshot
unknown_result account_binding_mismatch account_changed_during_sync
account_flags_changed account_identity_ambiguous account_inventory_invalid
account_proxy_invalid account_proxy_mismatch account_write_unconfirmed
already_logged_in already_running authentication_backoff
authentication_cookies_missing authentication_required breaker_open
browser_context_unavailable busy_state_unknown canceled cancelled captcha_required
completed config_binding_changed configuration_or_lock_unavailable
cookie_structure_invalid cookies_unavailable created credential_identity_mismatch
credits_unverifiable deferred disabled failed field_not_found flow_admin_login_failed
flow_busy_check_unavailable flow_credentials_unavailable flow_entry_unavailable
generation_busy google_credit_validation_failed google_identity_mismatch
google_session_requires_attention identity_mismatch identity_unconfirmed
identity_unverifiable identity_validated identity_validation_unavailable
identity_validator_unavailable invalid_cookie_source_option invalid_create_flags
invalid_disable_credit_threshold invalid_expected_email invalid_inactive_staging
invalid_login_request invalid_loopback_endpoint invalid_pool_login_option
invalid_private_json invalid_profile_id invalid_remote_dns invalid_request
invalid_token_id local_api_authentication_failed local_api_invalid_response
local_api_unavailable local_transport_failed login_already_authenticated
login_backoff login_binding_mismatch login_browser_unavailable login_cancelled
login_captcha_required login_challenge_unsupported login_completed
login_credentials_blocked login_credentials_missing login_credits_unverifiable
login_dependency_unavailable login_device_confirmation login_exception
login_host_unavailable login_identity_mismatch login_identity_unverifiable
login_internal_error login_not_configured login_proxy_mismatch login_timeout
login_verified login_worker_failed login_wrong_email login_wrong_password
login_wrong_totp low_balance_already_disabled low_balance_disabled
low_balance_unbound method_picker_click_failed network_backoff
no_account no_credentials no_authenticator_option not_needed paused
private_file_unavailable processing_paused profile_changed_during_sync
profile_cookie_source_invalid profile_identity_ambiguous profile_inactive
profile_inventory_unknown profile_proxy_changed profile_proxy_invalid
profile_proxy_unknown profile_proxy_unsupported profile_state_unknown
provider_submit_failed queue_paused saved_cookies_unavailable saved_source_unchanged
spark_lease_inventory_invalid spark_task_state_unknown status_unknown submit_failed
sync_complete sync_failed_safe timeout token_binding_changed totp_not_configured
totp_unavailable unchanged unknown_page unsafe_login_page updated video_status_unknown
wrong_email wrong_password wrong_totp bound_account_missing chooser_stuck
provider_stuck method_picker_stuck account_rejected logged_in security_check
verification_required device_confirm_required totp_missing login_cancelled
browser_gone source_unchanged token_deleted token_not_found""".split()) | {""}
REASONS |= frozenset("""operation_cancelled credential_refreshed
validation_recovered validation_backoff native_browser_restart runtime_prepared
refresh_started refresh_complete health_cleared project_creation_failed
account_selection_failed schema_migrated""".split())
REASONS |= frozenset("""upstream_traffic_restricted network_unavailable
historical_health_failure historical_refresh_failed binding_verified login_step""".split())
REASONS |= frozenset("""imported_enabled batch_partial_failed unavailable
browser_operation_failed navigation_failed flow_editor_unavailable
flow_page_unavailable prompt_input_mismatch prompt_changed_during_upload
submit_unavailable proxy_connection_failed editor_missing network_empty_response
network_connection_failed navigation_interrupted submit_control_missing
submit_control_not_ready frame_slots_failed initial_slots_not_empty
other_slot_changed uploaded_asset_mismatch frame_binding_changed""".split())
REASONS |= frozenset("""browser_session_refreshed session_token_unchanged
session_token_unavailable invalid_config_path config_outside_local
config_symlink_rejected private_file_permissions invalid_pool_manifest
duplicate_or_manifest_config pool_lock_unavailable pool_interrupted""".split())
REASONS |= frozenset("""browser_context_ambiguous local_api_rejected browser_closed browser_close_deferred browser_shutdown_pending
spark_inventory_incomplete invalid_sync_result validated_recently cookie_source_observed""".split())
REASONS |= frozenset("""automatic_login_disabled automatic_login_at_unexpired automatic_login_policy_unknown""".split())
REASONS |= frozenset(f"{phase}_failed" for phase in (
    "open", "summary_find", "summary_click", "panel_wait", "mode", "model",
    "duration", "submode", "resolution", "ratio", "count", "save",
    "verify_mode", "verify_model", "verify_duration", "verify_ratio", "verify_count",
))
REASONS |= frozenset(f"frame_{slot}_{phase}_failed" for slot in (1, 2)
                    for phase in ("open", "chooser", "binding", "bound"))

NUMERIC_DETAILS = frozenset("""credits threshold count total success_count
failed_count deferred_count duration_ms attempt attempts cooldown_seconds
http_status field_count updated unchanged deferred failed disabled created
enabled skipped interval_minutes refresh_interval_minutes error_count
consecutive_error_count token_count max_requests requests_since_rotation
pool_size page_count image_count video_count retry_after_seconds""".split())
NUMERIC_DETAILS |= frozenset("""previous_credits duration_seconds retry_count
succeeded status_code image_concurrency video_concurrency token_id""".split())
NUMERIC_DETAILS |= {"retry_after"}
BOOLEAN_DETAILS = frozenset("""credential_changed credentials_changed busy
is_active auto_refresh_enabled image_enabled video_enabled proxy_changed
cookie_changed identity_verified was_active low_balance retryable expired
auto_enable_on_update remote_dns enabled disabled has_credentials""".split())
BOOLEAN_DETAILS |= frozenset("active cookies_changed submission_pending upstream_accepted".split())
CATEGORY_DETAILS = {
    "setting": frozenset("proxy generation call_logic error_threshold token_refresh captcha plugin ads_serial".split()),
    "category": frozenset("""auth network config balance source credentials
        protocol_probe validation login cookie_sync generation rotation binding
        manual scheduled history_snapshot unknown""".split()),
    "decision": frozenset("""unavailable recover recovery_failed disabled enabled
        success failed deferred skipped unchanged cooldown unknown""".split()),
    "auth_evidence": frozenset("""none http_401 unauthenticated missing_cookie
        login_redirect unknown""".split()),
    "cookie_source": frozenset("live saved browser database unknown".split()),
    "error_code": frozenset("""UNAUTHENTICATED PUBLIC_ERROR_UNUSUAL_ACTIVITY
        PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC unknown""".split()),
    "retry_reason": REASONS,
    "ban_reason": frozenset({"429_rate_limit", "consecutive_errors", "none"}),
}
SCHEMA_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS account_operation_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_id INTEGER,
        token_email TEXT NOT NULL DEFAULT '',
        token_serial TEXT NOT NULL DEFAULT '',
        operation TEXT NOT NULL,
        stage TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        details TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        event_key TEXT UNIQUE
    )""",
    "CREATE INDEX IF NOT EXISTS idx_account_logs_created ON account_operation_logs(created_at DESC, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_account_logs_token ON account_operation_logs(token_id, created_at DESC, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_account_logs_filters ON account_operation_logs(operation, status, source)",
)
INSERT_SQL = """INSERT INTO account_operation_logs
    (token_id,token_email,token_serial,operation,stage,source,status,reason,details,created_at,event_key)
    VALUES (:token_id,:token_email,:token_serial,:operation,:stage,:source,:status,:reason,:details,:created_at,:event_key)
    ON CONFLICT(event_key) DO NOTHING"""


def _choice(value, choices, fallback="unknown"):
    return value if isinstance(value, str) and value in choices else fallback


def sanitize_details(details):
    result = {}
    if not isinstance(details, dict):
        return result
    for key, value in details.items():
        if not isinstance(key, str):
            continue
        if key in BOOLEAN_DETAILS and type(value) is bool:
            result[key] = value
        elif (key in NUMERIC_DETAILS and type(value) in (int, float)
              and abs(value) <= 10**15 and math.isfinite(value)):
            result[key] = value
        elif key in CATEGORY_DETAILS and isinstance(value, str) and value in CATEGORY_DETAILS[key]:
            result[key] = value
    return result


def sanitize_email(value):
    if not isinstance(value, str) or len(value) > 254:
        return ""
    return value if re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", value) else ""


def sanitize_serial(value):
    if type(value) is int and 0 < value < 10**12:
        return str(value)
    return value if isinstance(value, str) and re.fullmatch(r"[0-9]{1,12}", value) else ""


def _token_value(token, key):
    return token.get(key) if isinstance(token, dict) else getattr(token, key, None)


def _timestamp(value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            value = None
    if not isinstance(value, datetime):
        value = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def normalize_event(token_id=None, *, operation, status, reason="", stage="",
                    source="system", details=None, token=None, event_key=None,
                    created_at=None, token_email=None, token_serial=None):
    if type(token_id) is not int or token_id <= 0:
        token_id = None
    status = {"error": "failed"}.get(status, status) if isinstance(status, str) else status
    source = {"adspower_sync": "cookie_sync", "login_recovery": "login_host"}.get(source, source) if isinstance(source, str) else source
    email = token_email if token_email is not None else (_token_value(token, "email") or _token_value(token, "login_account"))
    serial = token_serial if token_serial is not None else _token_value(token, "adspower_serial")
    # Opaque deduplication keys must never become another free-text log field.
    key = hashlib.sha256(event_key.encode()).hexdigest() if isinstance(event_key, str) and 0 < len(event_key) <= 4096 else None
    return {"token_id": token_id, "token_email": sanitize_email(email),
            "token_serial": sanitize_serial(serial), "operation": _choice(operation, OPERATIONS),
            "status": _choice(status, STATUSES), "source": _choice(source, SOURCES),
            "stage": _choice(stage, STAGES), "reason": _choice(reason, REASONS),
            "details": json.dumps(sanitize_details(details), ensure_ascii=False, separators=(",", ":")),
            "created_at": _timestamp(created_at), "event_key": key}


def decode_event(row):
    """Apply the same boundary to reads, including manually damaged legacy rows."""
    data = dict(row)
    try:
        details = json.loads(data.get("details") or "{}")
    except (TypeError, ValueError):
        details = {}
    data.update(token_email=sanitize_email(data.get("token_email")),
                token_serial=sanitize_serial(data.get("token_serial")),
                operation=_choice(data.get("operation"), OPERATIONS),
                status=_choice(data.get("status"), STATUSES),
                source=_choice(data.get("source"), SOURCES),
                stage=_choice(data.get("stage"), STAGES),
                reason=_choice(data.get("reason"), REASONS),
                details=sanitize_details(details),
                token_id=data.get("token_id") if type(data.get("token_id")) is int and data["token_id"] > 0 else None,
                created_at=_timestamp(data.get("created_at")),
                event_key=data.get("event_key") if isinstance(data.get("event_key"), str) and re.fullmatch(r"[0-9a-f]{64}", data["event_key"]) else None)
    # Early runtime writers used the historical-snapshot reason for this
    # live source observation. Keep genuine history snapshots unchanged.
    if (data["operation"] == "cookie_sync" and data["status"] == "info"
            and data["stage"] == "source" and data["reason"] == "history_snapshot"
            and data["source"] in {"cookie_sync", "login_host", "login_worker"}
            and data["details"].get("category") == "source"):
        data["reason"] = "cookie_source_observed"
    return data


def normalize_stored_event(event):
    data = decode_event(event)
    data.pop("id", None)
    data["details"] = json.dumps(data["details"], ensure_ascii=False, separators=(",", ":"))
    return data


async def audit_account_operation(db, token_id=None, *, operation, status,
                                  reason="", stage="", source="system", details=None,
                                  token=None, event_key=None, created_at=None):
    try:
        event = normalize_event(token_id, operation=operation, status=status, reason=reason,
                                stage=stage, source=source, details=details, token=token,
                                event_key=event_key, created_at=created_at)
        return await db.append_account_operation_log(event)
    except Exception:
        return None


def audit_account_operation_sync(db_path, token_id=None, *, operation, status,
                                 reason="", stage="", source="system", details=None,
                                 token=None, event_key=None, created_at=None,
                                 token_email=None, token_serial=None):
    try:
        event = normalize_event(token_id, operation=operation, status=status, reason=reason,
                                stage=stage, source=source, details=details, token=token,
                                event_key=event_key, created_at=created_at,
                                token_email=token_email, token_serial=token_serial)
        # Separate short-lived connections avoid sharing an event loop or a
        # service connection with the external worker. Bound lock contention.
        with closing(sqlite3.connect(os.fspath(db_path), timeout=1.0)) as connection, connection:
            connection.execute("PRAGMA busy_timeout = 1000")
            for statement in SCHEMA_STATEMENTS:
                connection.execute(statement)
            if event["token_id"] and (not event["token_email"] or not event["token_serial"]):
                exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='tokens'").fetchone()
                if exists:
                    row = connection.execute("SELECT email, login_account, adspower_serial FROM tokens WHERE id=?", (event["token_id"],)).fetchone()
                    if row:
                        event["token_email"] = event["token_email"] or sanitize_email(row[0] or row[1])
                        event["token_serial"] = event["token_serial"] or sanitize_serial(row[2])
            cursor = connection.execute(INSERT_SQL, event)
            if cursor.rowcount:
                return cursor.lastrowid
            row = connection.execute("SELECT id FROM account_operation_logs WHERE event_key=?", (event["event_key"],)).fetchone()
            return row[0] if row else None
    except Exception:
        return None
