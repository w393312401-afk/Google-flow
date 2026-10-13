"""Account-scoped exit rotation without replaying generation requests.

Only explicit registrations in a private local policy enable this service.
Generation callers keep an account lease until submission and polling finish;
rotation is applied before a later lease, never by a send/error callback.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
from pathlib import Path
import tempfile
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote, unquote, urlsplit

from curl_cffi.requests import AsyncSession

from .captcha_errors import BrowserCaptchaError
from ..core.account_audit import audit_account_operation


_ROOT = Path(__file__).resolve().parents[2]
_LOGGER = logging.getLogger("debug_logger")
_FIELDS = ("count", "current_proxy_id", "known_exit_ip", "due", "error")


def _unavailable() -> BrowserCaptchaError:
    error = BrowserCaptchaError("exit_rotation", "unavailable")
    error.submission_pending = False
    return error


def _proxy_identity(value: Any) -> tuple:
    if not str(value or "").strip():
        return ("direct",)
    parsed = urlsplit(str(value).strip())
    scheme = "socks5h" if parsed.scheme == "socks5" else parsed.scheme
    if (scheme not in {"http", "https", "socks5h"} or not parsed.hostname
            or not parsed.port or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        raise ValueError("invalid proxy")
    return (scheme, parsed.hostname.lower(), parsed.port,
            unquote(parsed.username or ""), unquote(parsed.password or ""))


def _pool_url(entry: dict) -> str:
    scheme = str(entry.get("proxy_type") or "http").lower()
    host = str(entry.get("host") or "").strip()
    if not host or any(char in host for char in "@/\\?#"):
        raise ValueError("invalid pool entry")
    port = int(entry.get("port") or 0)
    if not 0 < port <= 65535:
        raise ValueError("invalid pool entry")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    auth = ""
    if entry.get("user") or entry.get("password"):
        auth = (quote(str(entry.get("user") or ""), safe="") + ":"
                + quote(str(entry.get("password") or ""), safe="") + "@")
    value = f"{scheme}://{auth}{host}:{port}"
    _proxy_identity(value)
    return value


def _ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return ""


class ExitRotationManager:
    """Persist counters per account and serialize each account's lifecycle."""

    def __init__(self, db, token_manager=None, *, policy_path=None,
                 state_path=None, probe: Optional[Callable[[str], Awaitable[dict]]] = None):
        self.db = db
        self.token_manager = token_manager
        self.policy_path = Path(policy_path or _ROOT / "local/exit-ip-rotation.json")
        self.state_path = Path(state_path or _ROOT / "local/exit-ip-rotation.state.json")
        self._probe_override = probe
        self._account_locks: dict[int, asyncio.Lock] = {}
        self._owners: dict[int, str] = {}
        self._state_lock = asyncio.Lock()
        self._pool_lock = asyncio.Lock()
        # Request identities are kept only in memory, never in the private state.
        # The state contains route metadata, not prompts or request credentials.
        self._sent: set[tuple[int, str]] = set()

    def _policy(self) -> dict:
        try:
            raw = json.loads(self.policy_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"enabled": False, "token_ids": []}
        except Exception:
            raise _unavailable() from None
        if not isinstance(raw, dict) or raw.get("enabled") is not True:
            return {"enabled": False, "token_ids": []}
        try:
            ids = raw.get("token_ids", [])
            if not isinstance(ids, list):
                raise ValueError()
            registered = sorted({int(value) for value in ids if not isinstance(value, bool)})
            if any(value <= 0 for value in registered):
                raise ValueError()
            threshold = int(raw.get("threshold", 5))
            maximum = int(raw.get("max_candidates", 10))
            timeout = float(raw.get("probe_timeout_seconds", 12))
            pool = Path(str(raw["pool_path"])).expanduser()
            if not pool.is_absolute():
                pool = self.policy_path.parent / pool
            if not 1 <= threshold <= 10000 or not 1 <= maximum <= 100 or not 0 < timeout <= 15:
                raise ValueError()
            return {"enabled": True, "token_ids": registered, "threshold": threshold,
                    "max_candidates": maximum, "probe_timeout_seconds": timeout,
                    "pool_path": pool}
        except Exception:
            raise _unavailable() from None

    def enabled_for(self, token_id: int) -> bool:
        policy = self._policy()
        return policy["enabled"] and int(token_id) in policy["token_ids"]

    def _lock(self, token_id: int) -> asyncio.Lock:
        return self._account_locks.setdefault(int(token_id), asyncio.Lock())

    def _state(self) -> dict:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": 1, "accounts": {}}
        except Exception:
            raise _unavailable() from None
        if not isinstance(raw, dict) or not isinstance(raw.get("accounts"), dict):
            raise _unavailable()
        accounts = {}
        for key, value in raw["accounts"].items():
            if not isinstance(value, dict):
                raise _unavailable()
            try:
                account_id = str(int(key))
                count = max(0, int(value.get("count", 0)))
            except (TypeError, ValueError):
                raise _unavailable() from None
            accounts[account_id] = {
                "count": count,
                "current_proxy_id": str(value.get("current_proxy_id") or ""),
                "known_exit_ip": _ip(value.get("known_exit_ip")),
                "due": value.get("due") is True,
                "error": value.get("error") if value.get("error") in {
                    "threshold", "generation_error", "health_error", "unavailable"
                } else None,
            }
        return {"version": 1, "accounts": accounts}

    def _write(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            descriptor, temporary = tempfile.mkstemp(prefix=self.state_path.name + ".",
                                                       dir=self.state_path.parent)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(state, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.state_path)
            temporary = None
            directory = os.open(self.state_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            raise _unavailable() from None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    @staticmethod
    def _record(state: dict, token_id: int) -> dict:
        return state["accounts"].setdefault(str(token_id), {
            "count": 0, "current_proxy_id": "", "known_exit_ip": "",
            "due": False, "error": None,
        })

    @staticmethod
    def _pool(policy: dict) -> list[tuple[str, dict, str]]:
        try:
            raw = json.loads(policy["pool_path"].read_text(encoding="utf-8"))
            entries = raw["proxies"]
            if not isinstance(entries, dict):
                raise ValueError()
        except Exception:
            raise _unavailable() from None
        rows = []
        for proxy_id, entry in entries.items():
            if not isinstance(entry, dict) or entry.get("disabled"):
                continue
            try:
                url = _pool_url(entry)
            except (ValueError, TypeError):
                continue
            rows.append((str(proxy_id), entry, url))
        def priority(row):
            entry = row[1]
            airport = entry.get("source") == "airport"
            try:
                tier = max(0, int(entry.get("fallback_tier") or 0)) if airport else 0
            except (TypeError, ValueError):
                tier = 0
            return (int(airport), tier)
        # JSON insertion order provides a stable order within each priority tier.
        return sorted(rows, key=priority)

    async def _probe(self, route: str, timeout: float) -> dict:
        if self._probe_override is not None:
            return await asyncio.wait_for(self._probe_override(route), timeout=timeout * 2)
        result = {"ip": "", "flow_status": None}
        async with AsyncSession(trust_env=False) as session:
            # Persist the pool's declared scheme so the synchronizer can verify
            # its exact route. Resolve DNS remotely only for the HTTP probe.
            proxy = ("socks5h://" + route[len("socks5://"):]
                     if route.startswith("socks5://") else route) or None
            try:
                response = await session.get("https://ipinfo.io/json", proxy=proxy,
                                             timeout=timeout, impersonate="chrome120",
                                             allow_redirects=True)
                if response.status_code == 200:
                    result["ip"] = _ip(response.json().get("ip"))
            except Exception:
                pass
            try:
                response = await session.get("https://flow.google.com/", proxy=proxy,
                                             timeout=timeout, impersonate="chrome120",
                                             allow_redirects=True)
                result["flow_status"] = response.status_code
            except Exception:
                pass
        return result

    async def _rotate_if_due(self, token, policy: dict):
        token_id = int(token.id)
        async with self._state_lock:
            record = dict(self._record(self._state(), token_id))
        if not record["due"] and record["count"] < policy["threshold"]:
            return token
        await audit_account_operation(
            self.db, token_id, operation="exit_rotation", status="started", reason="rotation_due",
            stage="rotation", source="exit_rotation", token=token,
            details={"count": record["count"], "threshold": policy["threshold"]},
        )
        async with self._pool_lock:
            try:
                candidates = self._pool(policy)
                old_route = str(getattr(token, "proxy_url", "") or "").strip()
                old_identity = _proxy_identity(old_route)
                # Advance within the current source tier instead of alternating
                # the first two static routes indefinitely. Static candidates
                # still all precede every airport fallback tier.
                for index, (_, current_entry, current_route) in enumerate(candidates):
                    if _proxy_identity(current_route) != old_identity:
                        continue
                    airport = current_entry.get("source") == "airport"
                    try:
                        current_tier = int(current_entry.get("fallback_tier") or 0) if airport else 0
                    except (TypeError, ValueError):
                        current_tier = 0
                    def same_tier(row):
                        entry = row[1]
                        is_airport = entry.get("source") == "airport"
                        try:
                            tier = int(entry.get("fallback_tier") or 0) if is_airport else 0
                        except (TypeError, ValueError):
                            tier = 0
                        return is_airport == airport and tier == current_tier
                    positions = [i for i, row in enumerate(candidates) if same_tier(row)]
                    group = [candidates[i] for i in positions]
                    offset = positions.index(index) + 1
                    group = group[offset:] + group[:offset]
                    for position, row in zip(positions, group):
                        candidates[position] = row
                    break
                blocked_ips = {_ip(record["known_exit_ip"])} - {""}
                for _, entry, route in candidates:
                    if _proxy_identity(route) == old_identity:
                        historical_ip = _ip(entry.get("exit_ip"))
                        if historical_ip:
                            blocked_ips.add(historical_ip)
                # A dead current route must not prevent recovery to a new one.
                try:
                    old = await self._probe(old_route, policy["probe_timeout_seconds"])
                    old_ip = _ip(old.get("ip"))
                    if old_ip:
                        blocked_ips.add(old_ip)
                except Exception:
                    pass
                chosen = None
                checked = 0
                for proxy_id, entry, route in candidates:
                    if _proxy_identity(route) == old_identity or entry.get("last_check_status") == "failed":
                        continue
                    if checked >= policy["max_candidates"]:
                        break
                    checked += 1
                    try:
                        observed = await self._probe(route, policy["probe_timeout_seconds"])
                    except Exception as error:
                        _LOGGER.warning("[EXIT_ROTATION] account=%s candidate=%s probe=%s",
                                        token_id, proxy_id, type(error).__name__)
                        continue
                    exit_ip = _ip(observed.get("ip"))
                    if not exit_ip or observed.get("flow_status") != 200 or exit_ip in blocked_ips:
                        continue
                    chosen = (proxy_id, route, exit_ip)
                    break
                if chosen is None:
                    raise _unavailable()
                proxy_id, route, exit_ip = chosen
                # Write both account routes in one DB transaction. No credentials,
                # browser source profile or global proxy settings are involved.
                await self.db.update_token(token_id, proxy_url=route, captcha_proxy_url=route)
                if self.token_manager is not None:
                    self.token_manager._clear_at_validation_cache(token_id)
                try:
                    async with self._state_lock:
                        state = self._state()
                        self._record(state, token_id).update(
                            count=0, current_proxy_id=proxy_id, known_exit_ip=exit_ip,
                            due=False, error=None,
                        )
                        self._write(state)
                except BaseException:
                    # A route not recorded durably cannot be authorized by the
                    # Cookie synchronizer. Restore both old fields before exit.
                    await self.db.update_token(token_id, proxy_url=getattr(token, "proxy_url", None),
                                               captcha_proxy_url=getattr(token, "captcha_proxy_url", None))
                    raise
                _LOGGER.warning("[EXIT_ROTATION] account=%s proxy_id=%s exit_ip=%s rotated",
                                token_id, proxy_id, exit_ip)
                await audit_account_operation(
                    self.db, token_id, operation="exit_rotation", status="success", reason="rotation_complete",
                    stage="rotation", source="exit_rotation", token=token,
                    details={"count": checked, "proxy_changed": True},
                )
                return await self.db.get_token(token_id) or token
            except asyncio.CancelledError:
                await audit_account_operation(
                    self.db, token_id, operation="exit_rotation", status="failed", reason="operation_cancelled",
                    stage="rotation", source="exit_rotation", token=token,
                )
                raise
            except Exception:
                async with self._state_lock:
                    state = self._state()
                    self._record(state, token_id).update(due=True, error="unavailable")
                    self._write(state)
                _LOGGER.warning("[EXIT_ROTATION] account=%s unavailable; current route preserved", token_id)
                await audit_account_operation(
                    self.db, token_id, operation="exit_rotation", status="failed", reason="rotation_failed",
                    stage="rotation", source="exit_rotation", token=token,
                    details={"proxy_changed": False},
                )
                raise _unavailable() from None

    async def prepare_token(self, token):
        """Apply pending changes while idle; never wait behind an active lease."""
        if token is None or not self.enabled_for(token.id):
            return token
        lock = self._lock(token.id)
        if lock.locked():
            return token
        await lock.acquire()
        try:
            fresh = await self.db.get_token(int(token.id)) or token
            return await self._rotate_if_due(fresh, self._policy())
        finally:
            lock.release()

    async def acquire(self, token, request_id: str):
        """Lease one account until release, applying due rotation first."""
        if token is None or not self.enabled_for(token.id):
            return token
        token_id, request_id = int(token.id), str(request_id)
        if not request_id:
            raise _unavailable()
        lock = self._lock(token_id)
        await lock.acquire()
        try:
            fresh = await self.db.get_token(token_id) or token
            fresh = await self._rotate_if_due(fresh, self._policy())
            self._owners[token_id] = request_id
            return fresh
        except BaseException:
            lock.release()
            raise

    async def note_sent(self, token_id: int, request_id: str):
        """Count a generation send once; rotation waits for a future lease."""
        token_id, request_id = int(token_id), str(request_id)
        if not self.enabled_for(token_id):
            return
        identity = (token_id, request_id)
        if identity in self._sent:
            return
        if self._owners.get(token_id) != request_id:
            raise _unavailable()
        async with self._state_lock:
            if identity in self._sent:
                return
            state = self._state()
            record = self._record(state, token_id)
            was_due = record["due"]
            record["count"] += 1
            if record["count"] >= self._policy()["threshold"]:
                record["due"] = True
                record["error"] = record["error"] or "threshold"
            self._write(state)
            self._sent.add(identity)
        if record["due"] and not was_due:
            await audit_account_operation(
                self.db, token_id, operation="exit_rotation", status="info", reason="threshold_reached",
                stage="rotation", source="exit_rotation",
                details={"count": record["count"], "threshold": self._policy()["threshold"]},
            )

    async def note_error(self, token_id: int, request_id: str, error=None):
        """Schedule a future rotation, without repeating the failed request."""
        await self._mark_due(int(token_id), "generation_error")

    async def mark_health_error(self, token_id: int, error=None):
        await self._mark_due(int(token_id), "health_error")

    async def _mark_due(self, token_id: int, reason: str):
        if not self.enabled_for(token_id):
            return
        async with self._state_lock:
            state = self._state()
            record = self._record(state, token_id)
            was_due = record["due"]
            record.update(due=True, error=reason)
            self._write(state)
        if not was_due:
            await audit_account_operation(
                self.db, token_id, operation="exit_rotation", status="info", reason="rotation_due",
                stage="rotation", source="exit_rotation",
                details={"retry_reason": "validation_failed" if reason == "health_error" else "operation_failed"},
            )

    async def release(self, token_id: int, request_id: str):
        token_id = int(token_id)
        if self._owners.get(token_id) == str(request_id):
            self._owners.pop(token_id)
            self._lock(token_id).release()

    async def snapshot(self) -> dict:
        """Public status excludes paths, pool credentials and account identity."""
        policy = self._policy()
        async with self._state_lock:
            state = self._state()
        registered = set(policy["token_ids"])
        return {"enabled": policy["enabled"], "token_ids": policy["token_ids"],
                "threshold": policy.get("threshold", 5),
                "accounts": {key: {**{name: row[name] for name in _FIELDS},
                                    "busy": int(key) in self._owners}
                             for key, row in state["accounts"].items() if int(key) in registered}}
