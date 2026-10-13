"""Import dated account snapshots and write audit events without runtime deps.

External SPARK workers load this file directly.  Keep imports stdlib-only and
never copy raw diagnostics, credentials, session hashes or transport addresses.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import importlib.util
import json
import math
from pathlib import Path
import re
import sqlite3
import sys


ROOT = Path(__file__).resolve().parents[2]
_WRITERS = {}
_EXECUTOR = None
_STATUSES = {
    'created': 'success', 'updated': 'success', 'unchanged': 'unchanged',
    'disabled': 'disabled', 'deferred': 'deferred', 'error': 'failed',
}
_SYNC_REASONS = frozenset('''
sync_complete validated_recently identity_validated generation_busy saved_source_unchanged
network_backoff authentication_backoff already_running profile_inactive
local_transport_failed local_api_unavailable identity_validation_unavailable sync_failed_safe
google_session_requires_attention google_identity_mismatch google_credit_validation_failed
cookies_unavailable authentication_cookies_missing saved_cookies_unavailable
bound_account_missing account_binding_mismatch token_binding_changed profile_proxy_changed
account_proxy_mismatch account_changed_during_sync profile_changed_during_sync
low_balance_disabled low_balance_already_disabled low_balance_unbound
login_backoff login_verified login_host_unavailable login_binding_mismatch
login_proxy_mismatch login_credentials_missing login_credentials_blocked
login_captcha_required login_device_confirmation login_identity_unverifiable
login_wrong_password login_wrong_totp login_wrong_email login_challenge_unsupported
login_worker_failed login_identity_mismatch login_credits_unverifiable
login_browser_unavailable login_internal_error login_timeout login_cancelled
login_not_configured queue_paused busy_state_unknown
'''.split())


def audit_local_operation(root, db_path, token_id=None, **event):
    """Best effort audit writer shared by standalone, stdlib-only host loaders."""
    try:
        root, db_path = Path(root).resolve(), Path(db_path).resolve()
        # An audit must not create a new database when a config/path is wrong.
        if not db_path.is_file():
            return None
        path = root / 'src/core/account_audit.py'
        key = (str(path), path.stat().st_mtime_ns)
        writer = _WRITERS.get(key)
        if writer is None:
            name = '_flow2api_account_audit_' + str(abs(hash(key)))
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                sys.modules.pop(name, None)
                return None
            writer = module.audit_account_operation_sync
            _WRITERS.clear()
            _WRITERS[key] = writer
        return writer(str(db_path), token_id, **event)
    except Exception:
        # Logging cannot change an account operation's result or retry policy.
        return None


def queue_local_operation(root, db_path, token_id=None, **event):
    """Queue runtime events so SQLite waits cannot consume a browser deadline.

    Executor workers are joined by Python at process exit, including one-shot
    sync processes. History import uses the synchronous writer for dedup counts.
    """
    global _EXECUTOR
    try:
        if _EXECUTOR is None:
            _EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix='account-audit')
        event.setdefault('created_at', datetime.now(timezone.utc))
        return _EXECUTOR.submit(audit_local_operation, root, db_path, token_id, **event)
    except Exception:
        return None


def _time(value):
    """Only use timestamps actually stored by the original operation."""
    try:
        if type(value) in (int, float):
            if not math.isfinite(value) or value <= 0:
                return None
            return datetime.fromtimestamp(value, timezone.utc)
        if isinstance(value, str) and value.strip():
            value = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
        if isinstance(value, datetime):
            return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    return None


def _health(reason):
    """Translate the legacy fixed diagnostic sentence to safe categories."""
    text = reason if isinstance(reason, str) else ''
    prefix, _, detail = text.partition(': ')
    stage = prefix if prefix in {'AT_CHECK', 'AT_VERIFY', 'AT_REFRESH', 'ST_REFRESH', 'PROTOCOL_REFRESH'} else ''
    if 'credentials rejected (UNAUTHENTICATED)' in text:
        return stage, 'credentials_rejected'
    if 'upstream traffic restriction (' in text:
        return stage, 'upstream_traffic_restricted'
    if re.fullmatch(r'upstream unavailable \(HTTP [45]\d{2}\)', detail):
        return stage, 'upstream_unavailable'
    if 'frontend bootstrap metadata unavailable' in text:
        return stage, 'frontend_metadata_unavailable'
    if 'network or proxy unavailable' in text:
        return stage, 'network_unavailable'
    return stage, 'historical_health_failure'


def _read_rows(connection, table):
    if table not in {'tokens', 'token_health'}:
        return []
    try:
        available = {row[1] for row in connection.execute('PRAGMA table_info(' + table + ')')}
        wanted = ('id', 'email', 'login_account', 'remark', 'protocol_mode', 'last_st_refresh_at',
                  'last_st_refresh_result', 'adspower_serial') if table == 'tokens' else (
                      'token_id', 'reason', 'checked_at')
        fields = [field for field in wanted if field in available]
        if not fields:
            return []
        return [dict(row) for row in connection.execute('SELECT ' + ','.join(fields) + ' FROM ' + table)]
    except sqlite3.Error:
        return []


def _import_history(db_path, local_dir, root):
    imported = 0
    try:
        path = Path(db_path).resolve()
        if not path.is_file():
            return 0
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2) as connection:
            connection.row_factory = sqlite3.Row
            tokens = {row['id']: row for row in _read_rows(connection, 'tokens')
                      if type(row.get('id')) is int and row['id'] > 0}
            health = _read_rows(connection, 'token_health')
            try:
                seen_ids = {row[0] for row in connection.execute('SELECT id FROM account_operation_logs')}
            except sqlite3.Error:
                seen_ids = set()

        def emit(token_id, at, operation, status, reason, stage='', details=None):
            nonlocal imported
            when = _time(at)
            if token_id not in tokens or when is None:
                return
            key = ':'.join(('history', str(token_id), operation, when.isoformat(), reason, stage))
            result = audit_local_operation(root, path, token_id, operation=operation,
                status=status, reason=reason, stage=stage, source='history', details=details,
                event_key=key, created_at=when)
            if result is not None and result not in seen_ids:
                imported += 1
                seen_ids.add(result)

        for row in health:
            stage, reason = _health(row.get('reason'))
            emit(row.get('token_id'), row.get('checked_at'), 'health_check', 'failed', reason, stage)

        for token_id, token in tokens.items():
            result = token.get('last_st_refresh_result')
            if result == 'success':
                # Legacy success only proves the old page probe passed. It does
                # not establish that fresh Google cookies or a working RPC exist.
                emit(token_id, token.get('last_st_refresh_at'), 'refresh_st', 'info',
                     'frontend_probe_passed', 'PROTOCOL_REFRESH', {'category': 'protocol_probe'})
            elif result:
                emit(token_id, token.get('last_st_refresh_at'), 'refresh_st', 'failed',
                     'historical_refresh_failed', 'ST_REFRESH')

        local = Path(local_dir).resolve()
        if not local.is_dir():
            return imported
        # A state belongs to an account only when its paired fixed config and
        # current database marker agree. Never guess from a legacy log line.
        for state_path in sorted(local.glob('adspower-cookie-sync-*.state.json')):
            try:
                if state_path.is_symlink():
                    continue
                config_path = state_path.with_name(state_path.name.replace('.state.json', '.json'))
                if config_path.is_symlink():
                    continue
                state = json.loads(state_path.read_text(encoding='utf-8'))
                config = json.loads(config_path.read_text(encoding='utf-8'))
                token_id = config.get('token_id')
                token = tokens.get(token_id)
                if (not token or type(token_id) is not int or state.get('token_id', token_id) != token_id
                        or token.get('remark') != 'adspower-sync:' + str(config.get('profile_id', ''))
                        or str(token.get('email') or token.get('login_account') or '').lower()
                        != str(config.get('expected_email', '')).lower()):
                    continue
                result = state.get('last_result', {})
                if isinstance(result, dict) and result.get('token_id', token_id) == token_id:
                    raw_reason = result.get('reason')
                    reason = raw_reason if isinstance(raw_reason, str) and raw_reason in _SYNC_REASONS else 'unknown_result'
                    operation = 'auto_login' if reason.startswith('login_') else 'cookie_sync'
                    status = _STATUSES.get(result.get('status'), 'unknown')
                    details = {'category': 'history_snapshot'}
                    for key in ('credits', 'retry_after'):
                        value = result.get(key)
                        if type(value) in (int, float) and math.isfinite(value) and value >= 0:
                            details[key] = value
                    emit(token_id, state.get('last_run_at'), operation, status, reason,
                         'login' if operation == 'auto_login' else 'sync', details)
                emit(token_id, state.get('synced_at'), 'cookie_sync', 'success', 'sync_complete', 'sync')
                emit(token_id, state.get('login_attempted_at'), 'auto_login', 'started', 'login_requested', 'login')
            except (OSError, ValueError, TypeError, AttributeError):
                continue
        return imported
    except Exception:
        return imported


async def import_account_log_history(db, *, local_dir=None):
    """Backfill only dated, explicitly owned account snapshots, idempotently."""
    try:
        return await asyncio.to_thread(_import_history, db.db_path,
                                       local_dir or ROOT / 'local', ROOT)
    except Exception:
        return 0
