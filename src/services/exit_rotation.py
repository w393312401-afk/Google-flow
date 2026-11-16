"""Account-scoped exit rotation without replaying generation requests.

Only explicit registrations in a private local policy enable this service.
Generation callers keep an account lease until submission and polling finish;
rotation is applied before a later lease, never by a send/error callback.
"""
from __future__ import annotations

import asyncio
from contextlib import nullcontext
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote, unquote, urlsplit

from curl_cffi.requests import AsyncSession

from .captcha_errors import BrowserCaptchaError
from .token_manager import TokenManager
from ..core.account_audit import audit_account_operation


_ROOT = Path(__file__).resolve().parents[2]
_LOGGER = logging.getLogger("debug_logger")
_FIELDS = ("count", "current_proxy_id", "known_exit_ip", "due", "error")
_HEALTH_CACHE_TTL_SECONDS = 60.0
_HEALTH_FAILURE_BACKOFF_SECONDS = (5.0, 30.0, 120.0, 300.0)
_PROBE_CONCURRENCY = 4
_RETRYABLE_HEALTH_HTTP = re.compile(r"\bHTTP\s*(?:502|503|504)\b", re.IGNORECASE)
_RETRYABLE_HEALTH_TEXT = (
    "network or proxy unavailable",
    "upstream transport unavailable",
    "network unavailable",
    "proxy unavailable",
    "proxy error",
    "proxyerror",
    "proxy connection failed",
    "network connection failed",
    "connection error",
    "connection failed",
    "connection timed out",
    "connection timeout",
    "timeout",
    "timed out",
    "tls error",
    "tls failure",
    "tls handshake",
    "ssl error",
    "ssl failure",
)


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

    accepts_health_error_reason = True
    accepts_health_error_identity = True

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
        # Probe health is deliberately process-local. The external pool's
        # last_check fields can be days old and must not authorize a route.
        self._health_cache: dict[tuple, tuple[float, dict]] = {}
        self._health_backoff: dict[tuple, tuple[int, float]] = {}
        # Every account shares one probe budget and one in-flight observation
        # for a route. A simultaneous outage must count as one failed probe,
        # not one failure (and backoff increment) per account.
        self._probe_semaphore = asyncio.Semaphore(_PROBE_CONCURRENCY)
        self._probe_tasks: dict[tuple, asyncio.Task] = {}
        self._probe_waiters: dict[tuple, int] = {}
        self._admission_leases: dict[int, Any] = {}
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
                # Private evidence binding only; never expose it in snapshot.
                "health_error_identity": (
                    value["health_error_identity"]
                    if isinstance(value.get("health_error_identity"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", value["health_error_identity"])
                    else ""
                ),
                # Identity can stay unchanged across two independent failures.
                # Keep their ordering private and durable across restarts.
                "health_error_revision": (
                    value["health_error_revision"]
                    if type(value.get("health_error_revision")) is int
                    and value["health_error_revision"] >= 0
                    else 0
                ),
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
            "due": False, "error": None, "health_error_identity": "",
            "health_error_revision": 0,
        })

    @staticmethod
    def _discard_stale_health_evidence(record: dict, token, policy: dict) -> bool:
        if (record["due"] and record["error"] == "health_error"
                and record["count"] < policy["threshold"]
                and record["health_error_identity"] != TokenManager.health_identity(token)):
            record.update(due=False, error=None, health_error_identity="")
            return True
        return False

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

    @staticmethod
    def _tier(entry: dict) -> tuple[str, int]:
        if entry.get("source") != "airport":
            return ("static", 0)
        try:
            return ("airport", max(0, int(entry.get("fallback_tier") or 0)))
        except (TypeError, ValueError):
            return ("airport", 0)

    @staticmethod
    def _retryable_health_error(error: Any) -> bool:
        """Accept only fixed route/transport evidence, never auth or UI text."""
        if isinstance(error, (TimeoutError, ConnectionError)):
            return True
        status = getattr(error, "status_code", None)
        if status is None:
            status = getattr(getattr(error, "response", None), "status_code", None)
        try:
            if int(status) in {502, 503, 504}:
                return True
        except (TypeError, ValueError):
            pass
        text = str(error or "").strip().lower()
        if not text:
            return False
        return bool(_RETRYABLE_HEALTH_HTTP.search(text)) or any(
            marker in text for marker in _RETRYABLE_HEALTH_TEXT
        )

    @staticmethod
    def _healthy(observed: Any) -> bool:
        return (
            isinstance(observed, dict)
            and bool(_ip(observed.get("ip")))
            and observed.get("flow_status") == 200
        )

    async def _effective_route(self, token) -> tuple[str, bool]:
        """Resolve the route Flow requests actually use without exposing it."""
        account_route = str(getattr(token, "proxy_url", "") or "").strip()
        if account_route:
            try:
                _proxy_identity(account_route)
            except ValueError:
                return "", False
            return account_route, True
        try:
            flow_client = getattr(self.token_manager, "flow_client")
            proxy_manager = getattr(flow_client, "proxy_manager")
            getter = getattr(proxy_manager, "get_request_proxy_url")
            if not callable(getter):
                return "", False
            inherited = str(await getter() or "").strip()
            _proxy_identity(inherited)
            return inherited, True
        except asyncio.CancelledError:
            raise
        except Exception:
            # Unknown inheritance must never be interpreted as healthy direct
            # traffic. Keep the due state and evaluate verified pool routes.
            return "", False

    def _backed_off(self, route: str, *, now: Optional[float] = None) -> bool:
        key = _proxy_identity(route)
        failure = self._health_backoff.get(key)
        if failure is None:
            return False
        current = time.monotonic() if now is None else now
        return failure[1] > current

    async def _probe_health(self, route: str, timeout: float, *, force: bool = False) -> dict:
        """Probe one route with a short success cache and bounded failure isolation."""
        key = _proxy_identity(route)
        task = self._probe_tasks.get(key)
        if task is None:
            now = time.monotonic()
            if not force:
                cached = self._health_cache.get(key)
                if cached is not None and cached[0] > now:
                    return dict(cached[1])
            # Force bypasses a successful observation, never outage backoff.
            # Otherwise fast concurrent current-route checks can turn one
            # outage into a five-minute ban even with single-flight probing.
            if self._backed_off(route, now=now):
                return {"ip": "", "flow_status": None}
            task = asyncio.create_task(self._observe_route(route, timeout, key))
            self._probe_tasks[key] = task
            self._probe_waiters[key] = 0
        self._probe_waiters[key] += 1
        try:
            # One cancelled account must not abort the observation used by
            # another account. When the last waiter leaves, cancel the work
            # so abandoned probes do not occupy the shared budget.
            return dict(await asyncio.shield(task))
        finally:
            self._probe_waiters[key] -= 1
            if self._probe_waiters[key] == 0:
                self._probe_waiters.pop(key, None)
                self._probe_tasks.pop(key, None)
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

    async def _observe_route(self, route: str, timeout: float, key: tuple) -> dict:
        """Record exactly one result for one shared, globally bounded probe."""
        try:
            async with self._probe_semaphore:
                observed = await self._probe(route, timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            observed = {"ip": "", "flow_status": None}
        result = {
            "ip": _ip(observed.get("ip")) if isinstance(observed, dict) else "",
            "flow_status": observed.get("flow_status") if isinstance(observed, dict) else None,
        }
        completed = time.monotonic()
        if self._healthy(result):
            self._health_cache[key] = (completed + _HEALTH_CACHE_TTL_SECONDS, dict(result))
            self._health_backoff.pop(key, None)
        else:
            self._health_cache.pop(key, None)
            failures = self._health_backoff.get(key, (0, 0.0))[0] + 1
            failures = min(failures, len(_HEALTH_FAILURE_BACKOFF_SECONDS))
            self._health_backoff[key] = (
                failures,
                completed + _HEALTH_FAILURE_BACKOFF_SECONDS[failures - 1],
            )
        return result

    @classmethod
    def _advance_current_tier(cls, candidates: list[tuple[str, dict, str]],
                              old_identity: Optional[tuple]) -> list[tuple[str, dict, str]]:
        """Advance within the current tier while preserving cross-tier priority."""
        candidates = list(candidates)
        for index, (_, current_entry, current_route) in enumerate(candidates):
            if _proxy_identity(current_route) != old_identity:
                continue
            current_tier = cls._tier(current_entry)
            positions = [
                position for position, (_, entry, _) in enumerate(candidates)
                if cls._tier(entry) == current_tier
            ]
            group = [candidates[position] for position in positions]
            offset = positions.index(index) + 1
            group = group[offset:] + group[:offset]
            for position, row in zip(positions, group):
                candidates[position] = row
            break
        return candidates

    @classmethod
    def _spread_inherited_route(cls, candidates: list[tuple[str, dict, str]],
                                token_id: int) -> list[tuple[str, dict, str]]:
        """Stably fan first account-level routes out across every source tier."""
        candidates = list(candidates)
        tiers = []
        for _, entry, _ in candidates:
            tier = cls._tier(entry)
            if tier not in tiers:
                tiers.append(tier)
        for tier in tiers:
            positions = [
                position for position, (_, entry, _) in enumerate(candidates)
                if cls._tier(entry) == tier
            ]
            if len(positions) < 2:
                continue
            group = [candidates[position] for position in positions]
            offset = (max(1, int(token_id)) - 1) % len(group)
            group = group[offset:] + group[:offset]
            for position, row in zip(positions, group):
                candidates[position] = row
        return candidates

    def _candidate_window(self, candidates: list[tuple[str, dict, str]],
                          old_identity: Optional[tuple], maximum: int) -> list[tuple[str, dict, str]]:
        """Reserve coverage for static, airport tier 0 and tier 1 within the cap."""
        now = time.monotonic()
        eligible = []
        seen = set()
        for row in candidates:
            identity = _proxy_identity(row[2])
            if (identity == old_identity or identity in seen
                    or self._backed_off(row[2], now=now)):
                continue
            seen.add(identity)
            eligible.append(row)
        grouped: dict[tuple[str, int], list[tuple[str, dict, str]]] = {}
        for row in eligible:
            grouped.setdefault(self._tier(row[1]), []).append(row)

        selected: set[tuple] = set()
        coverage = (("static", 0), ("airport", 0), ("airport", 1))
        for tier in coverage:
            if len(selected) >= maximum:
                break
            rows = grouped.get(tier)
            if rows:
                selected.add(_proxy_identity(rows[0][2]))
        for row in eligible:
            if len(selected) >= maximum:
                break
            selected.add(_proxy_identity(row[2]))
        # Keep the original stable priority for deterministic winner selection;
        # coverage affects inclusion, not which healthy route wins.
        return [row for row in eligible if _proxy_identity(row[2]) in selected]

    async def _probe_candidates(self, candidates: list[tuple[str, dict, str]],
                                timeout: float) -> list[dict]:
        return await asyncio.gather(*(
            self._probe_health(route, timeout) for _, _, route in candidates
        ))

    async def _probe(self, route: str, timeout: float) -> dict:
        if self._probe_override is not None:
            return await asyncio.wait_for(self._probe_override(route), timeout=timeout * 2)
        async with AsyncSession(trust_env=False) as session:
            # Persist the pool's declared scheme so the synchronizer can verify
            # its exact route. Resolve DNS remotely only for the HTTP probe.
            proxy = ("socks5h://" + route[len("socks5://"):]
                     if route.startswith("socks5://") else route) or None

            async def public_ip() -> str:
                try:
                    response = await session.get(
                        "https://ipinfo.io/json", proxy=proxy, timeout=timeout,
                        impersonate="chrome120", allow_redirects=True,
                    )
                    if response.status_code == 200:
                        return _ip(response.json().get("ip"))
                except Exception:
                    pass
                return ""

            async def flow_status():
                try:
                    response = await session.get(
                        "https://flow.google.com/", proxy=proxy, timeout=timeout,
                        impersonate="chrome120", allow_redirects=True,
                    )
                    return response.status_code
                except Exception:
                    return None

            ip, status = await asyncio.gather(public_ip(), flow_status())
            return {"ip": ip, "flow_status": status}

    async def _recover_current_health(self, token, record: dict, policy: dict):
        """Recheck the authenticated endpoint before keeping an unavailable pool's route."""
        revalidate = getattr(self.token_manager, "revalidate_token_under_admission", None)
        consume = getattr(self.token_manager, "consume_validation_outcome", None)
        if not callable(revalidate) or not callable(consume):
            return None
        token_id = int(token.id)
        consume(token_id)
        # The caller already holds generation admission or a validated exclusive
        # maintenance lease. This bounded recheck must perform the real credits/
        # AT validation, never treat a successful public homepage as recovery.
        validated = await revalidate(token)
        outcome = consume(token_id)
        if (validated is None or getattr(outcome, "success", None) is not True
                or getattr(outcome, "token_id", None) != token_id
                or TokenManager.health_identity(validated) != getattr(outcome, "identity", None)):
            return None
        async with self._state_lock:
            latest = await self.db.get_token(token_id)
            if (latest is None or not latest.is_active
                    or TokenManager.health_identity(latest) != outcome.identity):
                return None
            state = self._state()
            current = self._record(state, token_id)
            if (not current["due"] or current["error"] != "health_error"
                    or current["count"] >= policy["threshold"]
                    or current["health_error_identity"] != record["health_error_identity"]
                    or current["health_error_revision"] != record["health_error_revision"]):
                return None
            current.update(due=False, error=None, health_error_identity="")
            self._write(state)
        await audit_account_operation(
            self.db, token_id, operation="exit_rotation", status="success",
            reason="validation_recovered", stage="rotation", source="exit_rotation",
            token=latest, details={"proxy_changed": False},
        )
        return latest

    async def _rotate_if_due(self, token, policy: dict):
        token_id = int(token.id)
        async with self._state_lock:
            state = self._state()
            current = self._record(state, token_id)
            if current["due"] and current["error"] == "health_error":
                token = await self.db.get_token(token_id) or token
            if self._discard_stale_health_evidence(current, token, policy):
                # Maintenance can replace a route/session after its failure was
                # recorded, including across restarts. Old or legacy unbound
                # health evidence cannot authorize changing that replacement.
                # Its next actual validation can establish fresh evidence.
                self._write(state)
            record = dict(current)
        if not record["due"] and record["count"] < policy["threshold"]:
            return token
        await audit_account_operation(
            self.db, token_id, operation="exit_rotation", status="started", reason="rotation_due",
            stage="rotation", source="exit_rotation", token=token,
            details={"count": record["count"], "threshold": policy["threshold"]},
        )
        threshold_due = record["count"] >= policy["threshold"] or record["error"] == "threshold"
        preserved_error = "threshold" if threshold_due else (record["error"] or "unavailable")
        try:
            has_account_route = bool(str(getattr(token, "proxy_url", "") or "").strip())
            old_route, old_route_known = await self._effective_route(token)
            old_identity = _proxy_identity(old_route) if old_route_known else None
            inherited_global = not has_account_route and old_route_known and bool(old_route)
            # The public homepage can recover while the authenticated credits
            # RPC still returns 502. It cannot disprove a health_error from
            # that RPC: such evidence requires one controlled route change.
            # Generic generation errors retain their existing network-only
            # recovery check; count thresholds always require rotation.
            old_observed = (
                await self._probe_health(
                    old_route, policy["probe_timeout_seconds"], force=True,
                )
                if old_route_known
                else {"ip": "", "flow_status": None}
            )
            if (old_route_known and not threshold_due
                    and record["error"] == "generation_error"
                    and self._healthy(old_observed)):
                recovered = False
                async with self._state_lock:
                    state = self._state()
                    current = self._record(state, token_id)
                    current_threshold = (
                        current["count"] >= policy["threshold"]
                        or current["error"] == "threshold"
                    )
                    if (current["due"] and not current_threshold
                            and current["error"] == "generation_error"):
                        current.update(
                            due=False, error=None, health_error_identity="",
                            known_exit_ip=_ip(old_observed.get("ip")),
                        )
                        self._write(state)
                        recovered = True
                if recovered:
                    _LOGGER.info("[EXIT_ROTATION] account=%s current route recovered", token_id)
                    await audit_account_operation(
                        self.db, token_id, operation="exit_rotation", status="success",
                        reason="validation_recovered", stage="rotation",
                        source="exit_rotation", token=token,
                        details={"count": record["count"], "proxy_changed": False},
                    )
                    return token

            # Network probes are account-independent and may be slow. Keep them
            # outside the cross-account commit lock so one bad route cannot
            # stall another account's recovery.
            candidates = self._pool(policy)
            candidates = (
                self._spread_inherited_route(candidates, token_id)
                if inherited_global
                else self._advance_current_tier(candidates, old_identity)
            )
            blocked_ips = {_ip(record["known_exit_ip"])} - {""}
            if old_identity is not None:
                for _, entry, route in candidates:
                    if _proxy_identity(route) == old_identity:
                        historical_ip = _ip(entry.get("exit_ip"))
                        if historical_ip:
                            blocked_ips.add(historical_ip)
            old_ip = _ip(old_observed.get("ip"))
            if old_ip:
                blocked_ips.add(old_ip)

            window = self._candidate_window(
                candidates, old_identity, policy["max_candidates"],
            )
            observations = await self._probe_candidates(
                window, policy["probe_timeout_seconds"],
            )
            chosen = None
            for (proxy_id, _, route), observed in zip(window, observations):
                exit_ip = _ip(observed.get("ip"))
                if not self._healthy(observed) or exit_ip in blocked_ips:
                    continue
                chosen = (proxy_id, route, exit_ip)
                break
            if chosen is None:
                if record["error"] == "health_error" and not threshold_due:
                    recovered = await self._recover_current_health(token, record, policy)
                    if recovered is not None:
                        return recovered
                raise _unavailable()
            proxy_id, route, exit_ip = chosen

            async with self._pool_lock:
                # Write both account routes in one DB transaction. No credentials,
                # browser source profile or global proxy settings are involved.
                # Only this short commit/rollback sequence is shared globally.
                # A failed validation may finish while the new route commits.
                # Its identity check and due-state write share this lock with
                # the entire route/state transition, not just the JSON write.
                async with self._state_lock:
                    state = self._state()
                    current = self._record(state, token_id)
                    latest = await self.db.get_token(token_id) or token
                    # A direct AT refresh can change credentials during the
                    # network probes while sharing generation admission. Recheck
                    # the persisted evidence at the final route mutation boundary.
                    if self._discard_stale_health_evidence(current, latest, policy):
                        self._write(state)
                        return latest
                    if not current["due"] and current["count"] < policy["threshold"]:
                        return latest
                    current_threshold = (current["count"] >= policy["threshold"]
                                         or current["error"] == "threshold")
                    conditional_update = getattr(self.db, "update_token_routes_if_health_matches", None)
                    if (current["error"] == "health_error" and not current_threshold
                            and callable(conditional_update)):
                        changed = await conditional_update(
                            latest, proxy_url=route, captcha_proxy_url=route,
                        )
                        if not changed:
                            # The identity can change even after the final read
                            # while SQLite schedules this write. The conditional
                            # update is the authority for applying health evidence.
                            fresh = await self.db.get_token(token_id) or latest
                            if self._discard_stale_health_evidence(current, fresh, policy):
                                self._write(state)
                            return fresh
                    else:
                        await self.db.update_token(token_id, proxy_url=route, captcha_proxy_url=route)
                    if self.token_manager is not None:
                        self.token_manager._clear_at_validation_cache(token_id)
                    try:
                        current.update(
                            count=0, current_proxy_id=proxy_id, known_exit_ip=exit_ip,
                            due=False, error=None, health_error_identity="",
                        )
                        self._write(state)
                    except BaseException:
                        # A route not recorded durably cannot be authorized by the
                        # Cookie synchronizer. Restore both old fields before exit.
                        await self.db.update_token(token_id, proxy_url=getattr(latest, "proxy_url", None),
                                                   captcha_proxy_url=getattr(latest, "captcha_proxy_url", None))
                        raise
            _LOGGER.warning("[EXIT_ROTATION] account=%s verified route rotated", token_id)
            await audit_account_operation(
                self.db, token_id, operation="exit_rotation", status="success", reason="rotation_complete",
                stage="rotation", source="exit_rotation", token=token,
                details={"count": len(window), "proxy_changed": True},
            )
            return await self.db.get_token(token_id) or token
        except asyncio.CancelledError:
            await audit_account_operation(
                self.db, token_id, operation="exit_rotation", status="failed", reason="operation_cancelled",
                stage="rotation", source="exit_rotation", token=token,
            )
            raise
        except Exception:
            try:
                async with self._state_lock:
                    state = self._state()
                    current = self._record(state, token_id)
                    current_threshold = (
                        current["count"] >= policy["threshold"]
                        or current["error"] == "threshold"
                        or preserved_error == "threshold"
                    )
                    current.update(
                        due=True,
                        error="threshold" if current_threshold else (current["error"] or preserved_error),
                    )
                    self._write(state)
            except Exception:
                pass
            _LOGGER.warning("[EXIT_ROTATION] account=%s unavailable; current route preserved", token_id)
            await audit_account_operation(
                self.db, token_id, operation="exit_rotation", status="failed", reason="rotation_failed",
                stage="rotation", source="exit_rotation", token=token,
                details={"proxy_changed": False},
            )
            raise _unavailable() from None

    async def prepare_token(self, token):
        """Apply pending changes while idle; never wait behind an active lease."""
        admission = getattr(self.token_manager, "account_admission", None)
        return await self._prepare_token(token, admission=admission)

    async def prepare_token_under_maintenance(self, token, lease):
        """Reuse the caller's validated exclusive lease instead of self-locking."""
        admission = getattr(self.token_manager, "account_admission", None)
        if admission is None:
            raise _unavailable()
        admission.validate_maintenance_lease(lease, int(token.id))
        return await self._prepare_token(token, admission=None)

    async def _prepare_token(self, token, *, admission):
        if token is None or not self.enabled_for(token.id):
            return token
        lock = self._lock(token.id)
        if lock.locked():
            return token
        await lock.acquire()
        try:
            # Hold the shared file lock through both the probe and commit.
            # A preflight maintenance_active check alone leaves a TOCTOU gap.
            with (admission.generation(int(token.id)) if admission is not None else nullcontext()):
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
        admission_lease = None
        try:
            admission = getattr(self.token_manager, "account_admission", None)
            if admission is not None:
                admission_lease = admission.generation(token_id)
            fresh = await self.db.get_token(token_id) or token
            fresh = await self._rotate_if_due(fresh, self._policy())
            self._owners[token_id] = request_id
            if admission_lease is not None:
                self._admission_leases[token_id] = admission_lease
            return fresh
        except BaseException:
            if admission_lease is not None:
                admission_lease.close()
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

    async def mark_health_error(self, token_id: int, error=None, *, failed_identity=None):
        """Schedule rotation only for sanitized, retryable route failures."""
        if not self._retryable_health_error(error):
            return False
        return await self._mark_due(int(token_id), "health_error", failed_identity=failed_identity)

    async def _mark_due(self, token_id: int, reason: str, *, failed_identity=None):
        if not self.enabled_for(token_id):
            return False
        async with self._state_lock:
            health_identity = ""
            if reason == "health_error":
                latest = await self.db.get_token(token_id)
                if (latest is None or not latest.is_active
                        or (failed_identity is not None
                            and TokenManager.health_identity(latest) != failed_identity)):
                    return False
                health_identity = TokenManager.health_identity(latest)
            state = self._state()
            record = self._record(state, token_id)
            was_due = record["due"]
            if reason == "health_error":
                # Increment even for the same identity or an already-due
                # account. An earlier success cannot consume this new evidence.
                record["health_error_revision"] += 1
            # Generic generation failures cannot erase stronger evidence that
            # the authenticated validation endpoint failed on this route.
            if record["due"] and record["error"] == "threshold":
                record["health_error_identity"] = ""
            elif reason == "health_error":
                # A fresh failure on a replacement supersedes the old route's
                # health evidence; generic generation errors cannot do so.
                record.update(error=reason, health_error_identity=health_identity)
            elif not (record["due"] and record["error"] == "health_error"):
                record["error"] = reason
                record["health_error_identity"] = ""
            record["due"] = True
            self._write(state)
        if not was_due:
            await audit_account_operation(
                self.db, token_id, operation="exit_rotation", status="info", reason="rotation_due",
                stage="rotation", source="exit_rotation",
                details={"retry_reason": "validation_failed" if reason == "health_error" else "operation_failed"},
            )
        return True

    async def release(self, token_id: int, request_id: str):
        token_id = int(token_id)
        if self._owners.get(token_id) == str(request_id):
            self._owners.pop(token_id)
            lease = self._admission_leases.pop(token_id, None)
            if lease is not None:
                lease.close()
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
