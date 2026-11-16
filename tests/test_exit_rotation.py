"""Offline rotation invariants: accounting, leases and no paid request replay."""
import asyncio
import json
import logging
from pathlib import Path
import stat
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from src.core.models import Token
from src.core.account_admission import AccountAdmission, AccountAdmissionBusy
from src.services.captcha_errors import BrowserCaptchaError
from src.services.exit_rotation import ExitRotationManager, _proxy_identity
from src.services.token_manager import TokenManager


OLD = "http://old:private-old@old.example.test:8000"
NEW = "http://new:private-new@new.example.test:8001"
OTHER = "http://other:private-other@other.example.test:8002"
NETWORK_ERROR = "AT_CHECK: network or proxy unavailable"


class FakeDB:
    def __init__(self):
        self.tokens = {
            2: Token(id=2, st="private-session", email="private@example.test",
                     google_cookies="private-cookies", current_project_id="project",
                     proxy_url=OLD, captcha_proxy_url=OLD),
            3: Token(id=3, st="another-session", email="other@example.test",
                     proxy_url=OLD, captcha_proxy_url=OLD),
        }
        self.writes = []

    async def get_token(self, token_id):
        return self.tokens[token_id].model_copy(deep=True)

    async def update_token(self, token_id, **changes):
        self.writes.append((token_id, dict(changes)))
        self.tokens[token_id] = self.tokens[token_id].model_copy(update=changes)


class ExitRotationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.policy_path = self.root / "exit-ip-rotation.json"
        self.state_path = self.root / "exit-ip-rotation.state.json"
        self.pool_path = self.root / "pool.json"
        self.policy = {"enabled": True, "token_ids": [2, 3], "threshold": 5,
                       "pool_path": str(self.pool_path), "max_candidates": 10,
                       "probe_timeout_seconds": 1}
        self.pool = {"proxies": {
            "old": {"proxy_type": "http", "host": "old.example.test", "port": 8000,
                    "user": "old", "password": "private-old", "exit_ip": "192.0.2.1"},
            "new": {"proxy_type": "http", "host": "new.example.test", "port": 8001,
                    "user": "new", "password": "private-new", "exit_ip": "192.0.2.2"},
            "other": {"proxy_type": "http", "host": "other.example.test", "port": 8002,
                      "user": "other", "password": "private-other"},
        }}
        self.save_policy()
        self.pool_path.write_text(json.dumps(self.pool))
        self.db = FakeDB()
        self.token_manager = SimpleNamespace(_clear_at_validation_cache=Mock())
        self.probes = []
        self.failures = set()

        async def probe(route):
            self.probes.append(route)
            if route in self.failures:
                raise RuntimeError("private failure URL=" + route)
            return {"ip": {OLD: "192.0.2.1", NEW: "192.0.2.2", OTHER: "192.0.2.3"}[route],
                    "flow_status": 200}
        self.probe = AsyncMock(side_effect=probe)
        self.manager = self.make_manager()

    def save_policy(self):
        self.policy_path.write_text(json.dumps(self.policy))
        self.policy_path.chmod(0o600)

    def make_manager(self):
        return ExitRotationManager(self.db, self.token_manager,
                                   policy_path=self.policy_path, state_path=self.state_path,
                                   probe=self.probe)

    def state(self):
        return json.loads(self.state_path.read_text())

    async def request(self, number, token_id=2, *, error=False):
        request_id = f"request-{token_id}-{number}"
        token = await self.manager.acquire(await self.db.get_token(token_id), request_id)
        await self.manager.note_sent(token_id, request_id)
        if error:
            await self.manager.note_error(token_id, request_id)
        await self.manager.release(token_id, request_id)
        return token

    async def mark_health_error(self, token_id=2, *, fail_current=False):
        if fail_current:
            self.failures.add((await self.db.get_token(token_id)).proxy_url)
        return await self.manager.mark_health_error(token_id, NETWORK_ERROR)

    async def test_fifth_send_schedules_sixth_without_changing_live_lease(self):
        for number in range(1, 5):
            self.assertEqual((await self.request(number)).proxy_url, OLD)
        token = await self.manager.acquire(await self.db.get_token(2), "fifth")
        await self.manager.note_sent(2, "fifth")
        self.assertEqual(token.proxy_url, OLD)
        self.assertEqual(self.db.writes, [])
        self.assertTrue(self.state()["accounts"]["2"]["due"])
        self.assertEqual(self.state()["accounts"]["2"]["count"], 5)
        self.assertEqual((await self.manager.prepare_token(token)).proxy_url, OLD)
        self.probe.assert_not_awaited()
        await self.manager.release(2, "fifth")
        token = await self.manager.acquire(token, "sixth")
        self.assertEqual(token.proxy_url, NEW)
        self.assertEqual(token.captcha_proxy_url, NEW)
        record = self.state()["accounts"]["2"]
        self.assertEqual(record["count"], 0)
        self.assertEqual(record["current_proxy_id"], "new")
        self.assertFalse(record["due"])
        await self.manager.note_sent(2, "sixth")
        self.assertEqual(self.state()["accounts"]["2"]["count"], 1)
        await self.manager.release(2, "sixth")

    async def test_generation_error_rechecks_and_preserves_recovered_current_route(self):
        await self.request(1, error=True)
        self.assertEqual(self.db.writes, [])
        self.assertEqual(self.state()["accounts"]["2"]["error"], "generation_error")
        token = await self.manager.acquire(await self.db.get_token(2), "next")
        self.assertEqual(token.proxy_url, OLD)
        self.assertEqual(self.probe.await_count, 1)
        self.assertFalse(self.state()["accounts"]["2"]["due"])
        await self.manager.release(2, "next")

    async def test_health_rotation_requires_sanitized_route_failure_evidence(self):
        accepted = (
            NETWORK_ERROR,
            "AT_REFRESH: upstream transport unavailable",
            "AT_CHECK: upstream unavailable (HTTP 502)",
            "AT_CHECK: upstream unavailable (HTTP 503)",
            "AT_CHECK: upstream unavailable (HTTP 504)",
            "TLS handshake failed",
            TimeoutError(),
            ConnectionError(),
            SimpleNamespace(status_code=503),
        )
        rejected = (
            None,
            "AT_CHECK: upstream unavailable (HTTP 500)",
            "AT_CHECK: upstream unavailable (HTTP 401)",
            "AT_CHECK: upstream unavailable (HTTP 403)",
            "AT_CHECK: upstream unavailable (HTTP 429)",
            "authentication rejected",
            "project_not_found",
            "upstream validation unavailable (unclassified error)",
        )
        for error in accepted:
            with self.subTest(accepted=type(error).__name__, value=str(error)):
                self.state_path.unlink(missing_ok=True)
                self.assertTrue(await self.manager.mark_health_error(2, error))
                self.assertEqual(self.state()["accounts"]["2"]["error"], "health_error")
        for error in rejected:
            with self.subTest(rejected=type(error).__name__, value=str(error)):
                self.state_path.unlink(missing_ok=True)
                self.assertFalse(await self.manager.mark_health_error(2, error))
                self.assertFalse(self.state_path.exists())

    async def test_probe_success_cache_and_failure_backoff_avoid_repeat_calls(self):
        first = await self.manager._probe_health(NEW, 1)
        second = await self.manager._probe_health(NEW, 1)
        self.assertEqual((first, second), (
            {"ip": "192.0.2.2", "flow_status": 200},
            {"ip": "192.0.2.2", "flow_status": 200},
        ))
        self.assertEqual(self.probes.count(NEW), 1)

        self.failures.add(OTHER)
        self.assertFalse(self.manager._healthy(await self.manager._probe_health(OTHER, 1)))
        self.assertFalse(self.manager._healthy(await self.manager._probe_health(OTHER, 1)))
        self.assertEqual(self.probes.count(OTHER), 1)

    async def test_health_failure_identity_must_match_current_route(self):
        token = await self.db.get_token(2)
        old_identity = TokenManager.health_identity(token)
        await self.db.update_token(2, proxy_url=NEW, captcha_proxy_url=NEW)
        self.assertFalse(await self.manager.mark_health_error(
            2, NETWORK_ERROR, failed_identity=old_identity,
        ))
        self.assertFalse(self.state_path.exists())
        current_identity = TokenManager.health_identity(await self.db.get_token(2))
        self.assertTrue(await self.manager.mark_health_error(
            2, NETWORK_ERROR, failed_identity=current_identity,
        ))
        self.assertEqual(self.state()["accounts"]["2"]["error"], "health_error")

    async def test_health_failure_identity_is_persisted_privately_and_survives_reload(self):
        token = await self.db.get_token(2)
        identity = TokenManager.health_identity(token)
        # Older callers without an explicit identity bind the current DB token.
        self.assertTrue(await self.manager.mark_health_error(2, NETWORK_ERROR))
        self.assertEqual(self.state()["accounts"]["2"]["health_error_identity"], identity)
        public = await self.manager.snapshot()
        self.assertNotIn("health_error_identity", public["accounts"]["2"])
        self.assertNotIn(identity, json.dumps(public))
        restarted = self.make_manager()
        self.assertEqual(restarted._state()["accounts"]["2"]["health_error_identity"], identity)
        self.assertEqual((await restarted.prepare_token(token)).proxy_url, NEW)
        self.assertEqual(self.state()["accounts"]["2"]["health_error_identity"], "")

    async def test_legacy_unbound_health_error_waits_for_fresh_evidence(self):
        self.state_path.write_text(json.dumps({"version": 1, "accounts": {"2": {
            "count": 2, "due": True, "error": "health_error",
        }}}))
        token = await self.db.get_token(2)
        self.assertEqual((await self.manager.prepare_token(token)).proxy_url, OLD)
        record = self.state()["accounts"]["2"]
        self.assertFalse(record["due"])
        self.assertIsNone(record["error"])
        self.assertEqual(record["count"], 2)
        self.probe.assert_not_awaited()
        self.assertEqual(self.db.writes, [])
        await self.manager.mark_health_error(2, NETWORK_ERROR)
        self.assertEqual((await self.manager.prepare_token(token)).proxy_url, NEW)

    async def test_legacy_or_stale_health_identity_does_not_remove_threshold_due(self):
        for count, reason in ((5, "health_error"), (0, "threshold")):
            for identity in (None, "f" * 64):
                with self.subTest(count=count, reason=reason, identity=identity):
                    await self.db.update_token(2, proxy_url=OLD, captcha_proxy_url=OLD)
                    record = {"count": count, "due": True, "error": reason}
                    if identity is not None:
                        record["health_error_identity"] = identity
                    self.state_path.write_text(json.dumps({"version": 1, "accounts": {"2": record}}))
                    token = await self.manager.prepare_token(await self.db.get_token(2))
                    self.assertEqual(token.proxy_url, NEW)
                    self.assertFalse(self.state()["accounts"]["2"]["due"])

    async def test_generic_error_retains_bound_health_evidence_until_new_health_failure(self):
        old_identity = TokenManager.health_identity(await self.db.get_token(2))
        await self.manager.mark_health_error(2, NETWORK_ERROR, failed_identity=old_identity)
        await self.db.update_token(2, proxy_url=NEW, captcha_proxy_url=NEW)
        await self.manager.note_error(2, "unrelated-generation")
        self.assertEqual(self.state()["accounts"]["2"]["health_error_identity"], old_identity)
        self.assertEqual(self.state()["accounts"]["2"]["error"], "health_error")
        current = await self.db.get_token(2)
        current_identity = TokenManager.health_identity(current)
        await self.manager.mark_health_error(2, NETWORK_ERROR, failed_identity=current_identity)
        self.assertEqual(self.state()["accounts"]["2"]["health_error_identity"], current_identity)
        await self.manager.note_error(2, "another-generation")
        self.assertEqual(self.state()["accounts"]["2"]["health_error_identity"], current_identity)
        self.assertEqual((await self.manager.prepare_token(current)).proxy_url, OTHER)

    async def test_health_identity_check_and_due_write_precede_rotation_atomically(self):
        await self.mark_health_error()
        token = await self.db.get_token(2)
        old_identity = TokenManager.health_identity(token)
        entered, resume = asyncio.Event(), asyncio.Event()
        original_get = self.db.get_token

        async def paused_get(token_id):
            snapshot = await original_get(token_id)
            if asyncio.current_task().get_name() == "mark-old-health":
                entered.set()
                await resume.wait()
            return snapshot

        self.db.get_token = paused_get
        mark = asyncio.create_task(self.manager.mark_health_error(
            2, NETWORK_ERROR, failed_identity=old_identity,
        ), name="mark-old-health")
        await asyncio.wait_for(entered.wait(), 1)
        rotate = asyncio.create_task(self.manager.prepare_token(token))
        await asyncio.sleep(0)
        self.assertEqual(self.db.writes, [])
        self.assertFalse(rotate.done())
        resume.set()
        self.assertTrue(await asyncio.wait_for(mark, 1))
        self.assertEqual((await asyncio.wait_for(rotate, 1)).proxy_url, NEW)
        self.assertFalse(self.state()["accounts"]["2"]["due"])

    async def test_new_route_health_failure_waits_for_commit_and_is_not_erased(self):
        await self.mark_health_error()
        token = await self.db.get_token(2)
        new_identity = TokenManager.health_identity(token.model_copy(update={
            "proxy_url": NEW, "captcha_proxy_url": NEW,
        }))
        entered, resume = asyncio.Event(), asyncio.Event()
        original_update = self.db.update_token

        async def paused_update(token_id, **changes):
            await original_update(token_id, **changes)
            if changes.get("proxy_url") == NEW:
                entered.set()
                await resume.wait()

        self.db.update_token = paused_update
        rotate = asyncio.create_task(self.manager.prepare_token(token))
        await asyncio.wait_for(entered.wait(), 1)
        mark = asyncio.create_task(self.manager.mark_health_error(
            2, NETWORK_ERROR, failed_identity=new_identity,
        ))
        await asyncio.sleep(0)
        self.assertFalse(mark.done())
        resume.set()
        self.assertEqual((await asyncio.wait_for(rotate, 1)).proxy_url, NEW)
        self.assertTrue(await asyncio.wait_for(mark, 1))
        self.assertTrue(self.state()["accounts"]["2"]["due"])
        self.assertEqual(self.state()["accounts"]["2"]["error"], "health_error")

    async def test_healthy_homepage_cannot_clear_failed_credits_health_evidence(self):
        # The simulated homepage succeeds on every route. The application RPC
        # is known to fail on OLD, so preparation must actually change it.
        await self.manager.mark_health_error(2, "AT_CHECK: upstream unavailable (HTTP 502)")
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(token.proxy_url, NEW)
        self.assertEqual(len(self.db.writes), 1)
        self.assertFalse(self.state()["accounts"]["2"]["due"])

    async def test_healthy_homepage_without_replacement_preserves_health_error_due(self):
        self.failures.update((NEW, OTHER))
        await self.mark_health_error()
        with self.assertRaises(BrowserCaptchaError):
            await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(self.db.writes, [])
        record = self.state()["accounts"]["2"]
        self.assertTrue(record["due"])
        self.assertEqual(record["error"], "health_error")

    async def test_generation_error_cannot_overwrite_pending_health_error(self):
        await self.mark_health_error()
        await self.manager.note_error(2, "generation-failed")
        self.assertEqual(self.state()["accounts"]["2"]["error"], "health_error")
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(token.proxy_url, NEW)

    async def test_fourteen_account_outage_has_one_failure_per_route_and_global_probe_cap(self):
        self.policy["token_ids"] = list(range(1, 15))
        self.save_policy()
        template = self.db.tokens[2]
        self.db.tokens = {
            token_id: template.model_copy(update={"id": token_id})
            for token_id in self.policy["token_ids"]
        }
        self.pool["proxies"] = {
            f"route-{index}": {"host": f"route-{index}.test", "port": 8100 + index}
            for index in range(10)
        }
        self.pool_path.write_text(json.dumps(self.pool))
        active = 0
        peak = 0
        calls = {}
        four_started = asyncio.Event()
        resume = asyncio.Event()

        async def probe(route):
            nonlocal active, peak
            calls[route] = calls.get(route, 0) + 1
            active += 1
            peak = max(peak, active)
            try:
                if route != OLD:
                    if active == 4:
                        four_started.set()
                    await resume.wait()
                return {"ip": "", "flow_status": None}
            finally:
                active -= 1

        self.manager._probe_override = probe
        tokens = []
        for token_id in self.policy["token_ids"]:
            await self.mark_health_error(token_id)
            tokens.append(await self.db.get_token(token_id))
        pending = asyncio.gather(*(
            self.manager.prepare_token(token) for token in tokens
        ), return_exceptions=True)
        await asyncio.wait_for(four_started.wait(), timeout=1)
        await asyncio.sleep(0)
        self.assertEqual(peak, 4)
        resume.set()
        results = await asyncio.wait_for(pending, timeout=2)
        self.assertTrue(all(isinstance(result, BrowserCaptchaError) for result in results))
        self.assertEqual(peak, 4)
        self.assertEqual(len(calls), 11)
        self.assertTrue(all(count == 1 for count in calls.values()))
        for failures, deadline in self.manager._health_backoff.values():
            self.assertEqual(failures, 1)
            self.assertLessEqual(deadline - time.monotonic(), 5)
        self.assertEqual(self.manager._probe_tasks, {})
        self.assertEqual(self.manager._probe_waiters, {})

        # A forced current-route check cannot bypass the same outage interval.
        await self.manager._probe_health(OLD, 1, force=True)
        self.assertEqual(calls[OLD], 1)
        key = _proxy_identity(OLD)
        failures, _ = self.manager._health_backoff[key]
        self.manager._health_backoff[key] = (failures, time.monotonic() - 1)
        await self.manager._probe_health(OLD, 1, force=True)
        self.assertEqual(calls[OLD], 2)
        self.assertEqual(self.manager._health_backoff[key][0], 2)

    async def test_cancelling_one_shared_probe_waiter_preserves_other_waiter(self):
        entered, resume = asyncio.Event(), asyncio.Event()
        calls = 0

        async def probe(route):
            nonlocal calls
            calls += 1
            entered.set()
            await resume.wait()
            return {"ip": "192.0.2.2", "flow_status": 200}

        self.manager._probe_override = probe
        first = asyncio.create_task(self.manager._probe_health(NEW, 1))
        await asyncio.wait_for(entered.wait(), timeout=1)
        second = asyncio.create_task(self.manager._probe_health(NEW, 1))
        await asyncio.sleep(0)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        self.assertEqual(calls, 1)
        self.assertFalse(second.done())
        resume.set()
        self.assertTrue(self.manager._healthy(await asyncio.wait_for(second, timeout=1)))
        self.assertEqual(self.manager._probe_tasks, {})
        self.assertEqual(self.manager._probe_waiters, {})
        self.assertEqual(self.manager._health_backoff, {})

    async def test_cancelling_last_probe_waiter_releases_budget_without_failure(self):
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def probe(route):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        self.manager._probe_override = probe
        pending = asyncio.create_task(self.manager._probe_health(NEW, 1))
        await asyncio.wait_for(entered.wait(), timeout=1)
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertTrue(cancelled.is_set())
        self.assertEqual(self.manager._probe_tasks, {})
        self.assertEqual(self.manager._probe_waiters, {})
        self.assertEqual(self.manager._health_backoff, {})
        self.manager._probe_override = self.probe
        self.assertTrue(self.manager._healthy(await self.manager._probe_health(NEW, 1)))

    async def test_existing_maintenance_blocks_prepare_before_probing_or_writing(self):
        admission = AccountAdmission(self.root / "database.db")
        self.token_manager.account_admission = admission
        await self.mark_health_error()
        with admission.maintenance(2):
            with self.assertRaises(AccountAdmissionBusy):
                await self.manager.prepare_token(await self.db.get_token(2))
        self.probe.assert_not_awaited()
        self.assertEqual(self.db.writes, [])
        self.assertFalse(self.manager._lock(2).locked())
        self.assertTrue(self.state()["accounts"]["2"]["due"])

    async def test_prepare_holds_admission_through_probe_and_commit(self):
        admission = AccountAdmission(self.root / "database.db")
        self.token_manager.account_admission = admission
        await self.mark_health_error()
        entered, resume = asyncio.Event(), asyncio.Event()

        async def probe(route):
            if route == OLD:
                entered.set()
                await resume.wait()
            return await self.probe(route)

        original_update = self.db.update_token

        async def checked_update(token_id, **changes):
            with self.assertRaises(AccountAdmissionBusy):
                admission.maintenance(token_id)
            await original_update(token_id, **changes)

        self.db.update_token = checked_update
        self.manager._probe_override = probe
        pending = asyncio.create_task(self.manager.prepare_token(await self.db.get_token(2)))
        await asyncio.wait_for(entered.wait(), timeout=1)
        with self.assertRaises(AccountAdmissionBusy):
            admission.maintenance(2)
        resume.set()
        self.assertEqual((await asyncio.wait_for(pending, timeout=1)).proxy_url, NEW)
        with admission.maintenance(2):
            pass

    async def test_cancelled_prepare_releases_admission_without_route_write(self):
        admission = AccountAdmission(self.root / "database.db")
        self.token_manager.account_admission = admission
        await self.mark_health_error()
        entered = asyncio.Event()

        async def probe(route):
            entered.set()
            await asyncio.Event().wait()

        self.manager._probe_override = probe
        pending = asyncio.create_task(self.manager.prepare_token(await self.db.get_token(2)))
        await asyncio.wait_for(entered.wait(), timeout=1)
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertEqual(self.db.writes, [])
        self.assertEqual(self.manager._probe_tasks, {})
        with admission.maintenance(2):
            pass

    async def test_admin_maintenance_delegation_rotates_without_self_lock(self):
        admission = AccountAdmission(self.root / "database.db")
        self.token_manager.account_admission = admission
        await self.mark_health_error()
        with admission.maintenance(2) as lease:
            token = await self.manager.prepare_token_under_maintenance(
                await self.db.get_token(2), lease,
            )
            self.assertEqual(token.proxy_url, NEW)
            self.assertTrue(admission.maintenance_active(2))
        self.assertFalse(admission.maintenance_active(2))

    async def test_admin_maintenance_delegation_rejects_wrong_or_closed_lease(self):
        admission = AccountAdmission(self.root / "database.db")
        self.token_manager.account_admission = admission
        await self.mark_health_error()
        token = await self.db.get_token(2)
        with admission.maintenance(3) as lease:
            with self.assertRaises(AccountAdmissionBusy):
                await self.manager.prepare_token_under_maintenance(token, lease)
        with self.assertRaises(AccountAdmissionBusy):
            await self.manager.prepare_token_under_maintenance(token, lease)
        self.probe.assert_not_awaited()
        self.assertEqual(self.db.writes, [])

    async def test_acquire_retains_admission_until_correct_owner_releases(self):
        admission = AccountAdmission(self.root / "database.db")
        self.token_manager.account_admission = admission
        await self.manager.acquire(await self.db.get_token(2), "owner")
        with self.assertRaises(AccountAdmissionBusy):
            admission.maintenance(2)
        await self.manager.release(2, "wrong-owner")
        with self.assertRaises(AccountAdmissionBusy):
            admission.maintenance(2)
        await self.manager.release(2, "owner")
        with admission.maintenance(2):
            pass

    async def test_ip_and_flow_checks_for_one_route_run_concurrently(self):
        active = 0
        maximum_active = 0
        both_entered = asyncio.Event()

        class Response:
            status_code = 200

            def __init__(self, url):
                self.url = url

            def json(self):
                return {"ip": "192.0.2.2"}

        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(inner_self, url, **kwargs):
                nonlocal active, maximum_active
                active += 1
                maximum_active = max(maximum_active, active)
                if active >= 2:
                    both_entered.set()
                await both_entered.wait()
                active -= 1
                return Response(url)

        self.manager._probe_override = None
        with patch("src.services.exit_rotation.AsyncSession", return_value=Session()):
            result = await asyncio.wait_for(self.manager._probe(NEW, 1), timeout=1)
        self.assertEqual(result, {"ip": "192.0.2.2", "flow_status": 200})
        self.assertEqual(maximum_active, 2)

    async def test_empty_account_route_uses_dead_inherited_route_then_sets_verified_route(self):
        inherited = "http://inherited.test:8190"
        self.db.tokens[2] = self.db.tokens[2].model_copy(update={
            "proxy_url": None, "captcha_proxy_url": None,
        })
        getter = AsyncMock(return_value=inherited)
        self.token_manager.flow_client = SimpleNamespace(
            proxy_manager=SimpleNamespace(get_request_proxy_url=getter),
        )

        async def probe(route):
            if route == inherited:
                return {"ip": "", "flow_status": None}
            return {
                "ip": {OLD: "192.0.2.1", NEW: "192.0.2.2", OTHER: "192.0.2.3"}[route],
                "flow_status": 200,
            }

        self.manager._probe_override = probe
        await self.mark_health_error()
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertIn(token.proxy_url, {OLD, NEW, OTHER})
        self.assertEqual(token.proxy_url, token.captcha_proxy_url)
        getter.assert_awaited_once()

    async def test_generation_error_preserves_healthy_inherited_route(self):
        inherited = "http://inherited.test:8190"
        self.db.tokens[2] = self.db.tokens[2].model_copy(update={
            "proxy_url": None, "captcha_proxy_url": None,
        })
        getter = AsyncMock(return_value=inherited)
        self.token_manager.flow_client = SimpleNamespace(
            proxy_manager=SimpleNamespace(get_request_proxy_url=getter),
        )
        self.manager._probe_override = AsyncMock(
            return_value={"ip": "192.0.2.90", "flow_status": 200},
        )
        await self.manager.note_error(2, "previous-generation")
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertFalse(token.proxy_url)
        self.assertEqual(self.db.writes, [])
        self.assertFalse(self.state()["accounts"]["2"]["due"])
        getter.assert_awaited_once()

    async def test_failed_inherited_route_lookup_never_probes_direct_as_current(self):
        self.db.tokens[2] = self.db.tokens[2].model_copy(update={
            "proxy_url": None, "captcha_proxy_url": None,
        })
        getter = AsyncMock(side_effect=RuntimeError("private global proxy failure"))
        self.token_manager.flow_client = SimpleNamespace(
            proxy_manager=SimpleNamespace(get_request_proxy_url=getter),
        )
        probed = []

        async def probe(route):
            probed.append(route)
            return {"ip": "", "flow_status": None}

        self.manager._probe_override = probe
        await self.mark_health_error()
        with self.assertRaises(BrowserCaptchaError):
            await self.manager.prepare_token(await self.db.get_token(2))
        self.assertNotIn("", probed)
        self.assertTrue(self.state()["accounts"]["2"]["due"])

    async def test_inherited_route_migration_is_stably_spread_by_account(self):
        inherited = "http://inherited.test:8190"
        routes = [f"http://route-{index}.test:{8200 + index}" for index in range(7)]
        self.pool["proxies"] = {
            f"route-{index}": {"host": f"route-{index}.test", "port": 8200 + index}
            for index in range(7)
        }
        self.pool_path.write_text(json.dumps(self.pool))
        self.policy["token_ids"] = [12, 13, 14, 15]
        self.save_policy()
        for token_id in self.policy["token_ids"]:
            self.db.tokens[token_id] = self.db.tokens[2].model_copy(update={
                "id": token_id,
                "st": f"session-{token_id}",
                "email": f"account-{token_id}@example.test",
                "proxy_url": "",
                "captcha_proxy_url": "",
            })
        self.token_manager.flow_client = SimpleNamespace(
            proxy_manager=SimpleNamespace(
                get_request_proxy_url=AsyncMock(return_value=inherited),
            ),
        )

        async def probe(route):
            if route == inherited:
                return {"ip": "", "flow_status": None}
            index = routes.index(route)
            return {"ip": f"192.0.2.{100 + index}", "flow_status": 200}

        self.manager._probe_override = probe
        selected = []
        for token_id in self.policy["token_ids"]:
            await self.manager.mark_health_error(token_id, NETWORK_ERROR)
            token = await self.manager.prepare_token(await self.db.get_token(token_id))
            selected.append(token.proxy_url)
        self.assertEqual(len(set(selected)), 4)
        self.assertTrue(set(selected).issubset(set(routes)))

    async def test_two_accounts_share_same_slow_candidate_probe(self):
        self.policy["max_candidates"] = 1
        self.save_policy()
        active = 0
        maximum_active = 0
        entered = asyncio.Event()
        resume = asyncio.Event()
        calls = []

        async def probe(route):
            nonlocal active, maximum_active
            if route == OLD:
                return {"ip": "", "flow_status": None}
            calls.append(route)
            active += 1
            maximum_active = max(maximum_active, active)
            entered.set()
            await resume.wait()
            active -= 1
            return {"ip": "192.0.2.2", "flow_status": 200}

        self.manager._probe_override = probe
        await self.manager.mark_health_error(2, NETWORK_ERROR)
        await self.manager.mark_health_error(3, NETWORK_ERROR)
        pending = asyncio.gather(
            self.manager.prepare_token(await self.db.get_token(2)),
            self.manager.prepare_token(await self.db.get_token(3)),
        )
        await asyncio.wait_for(entered.wait(), timeout=1)
        await asyncio.sleep(0)
        self.assertEqual(calls, [NEW])
        resume.set()
        results = await asyncio.wait_for(pending, timeout=1)
        self.assertEqual([token.proxy_url for token in results], [NEW, NEW])
        self.assertEqual(maximum_active, 1)

    async def test_candidate_cap_covers_all_tiers_and_probes_concurrently(self):
        static = "http://static.test:8101"
        tier0 = "http://tier0.test:8102"
        tier1 = "http://tier1.test:8103"
        self.pool["proxies"] = {
            "old": self.pool["proxies"]["old"],
            "static": {"host": "static.test", "port": 8101},
            "static-extra-1": {"host": "static-extra-1.test", "port": 8104},
            "static-extra-2": {"host": "static-extra-2.test", "port": 8105},
            "tier0": {"source": "airport", "fallback_tier": 0,
                      "host": "tier0.test", "port": 8102},
            "tier1": {"source": "airport", "fallback_tier": 1,
                      "host": "tier1.test", "port": 8103},
        }
        self.pool_path.write_text(json.dumps(self.pool))
        self.policy["max_candidates"] = 3
        self.save_policy()
        active = 0
        maximum_active = 0
        probed = []

        async def probe(route):
            nonlocal active, maximum_active
            probed.append(route)
            if route == OLD:
                return {"ip": "", "flow_status": None}
            active += 1
            maximum_active = max(maximum_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            if route == tier1:
                return {"ip": "192.0.2.31", "flow_status": 200}
            return {"ip": "", "flow_status": None}

        self.manager._probe_override = probe
        await self.mark_health_error()
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(token.proxy_url, tier1)
        self.assertEqual(set(probed[1:]), {static, tier0, tier1})
        self.assertGreaterEqual(maximum_active, 2)

    async def test_concurrent_probe_completion_does_not_change_priority_winner(self):
        airport = "http://airport.test:8102"
        self.pool["proxies"] = {
            **self.pool["proxies"],
            "airport": {"source": "airport", "fallback_tier": 0,
                        "host": "airport.test", "port": 8102},
        }
        self.pool_path.write_text(json.dumps(self.pool))
        self.policy["max_candidates"] = 2
        self.save_policy()

        async def probe(route):
            if route == OLD:
                return {"ip": "", "flow_status": None}
            if route == NEW:
                await asyncio.sleep(0.02)
                return {"ip": "192.0.2.2", "flow_status": 200}
            if route == airport:
                return {"ip": "192.0.2.20", "flow_status": 200}
            return {"ip": "", "flow_status": None}

        self.manager._probe_override = probe
        await self.mark_health_error()
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(token.proxy_url, NEW)

    async def test_duplicate_send_is_counted_once_and_health_checks_not_counted(self):
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertFalse(self.state_path.exists())
        await self.manager.acquire(token, "single")
        await self.manager.note_sent(2, "single")
        await self.manager.note_sent(2, "single")
        self.assertEqual(self.state()["accounts"]["2"]["count"], 1)
        await self.manager.release(2, "single")
        await self.manager.note_sent(2, "single")
        self.assertEqual(self.state()["accounts"]["2"]["count"], 1)

    async def test_concurrent_sixth_waits_for_fifth_and_other_account_is_independent(self):
        for number in range(1, 5):
            await self.request(number)
        token = await self.manager.acquire(await self.db.get_token(2), "fifth")
        await self.manager.note_sent(2, "fifth")
        waiting = asyncio.create_task(self.manager.acquire(token, "sixth"))
        await asyncio.sleep(0)
        self.assertFalse(waiting.done())
        independent = await asyncio.wait_for(
            self.manager.acquire(await self.db.get_token(3), "other-account"), timeout=1)
        self.assertEqual(independent.proxy_url, OLD)
        await self.manager.release(3, "other-account")
        await self.manager.release(2, "fifth")
        self.assertEqual((await asyncio.wait_for(waiting, timeout=1)).proxy_url, NEW)
        await self.manager.release(2, "sixth")

    async def test_wrong_owner_release_cannot_unlock_account(self):
        token = await self.manager.acquire(await self.db.get_token(2), "owner")
        await self.manager.release(2, "unrelated")
        self.assertEqual((await self.manager.snapshot())["accounts"], {})
        waiting = asyncio.create_task(self.manager.acquire(token, "next"))
        await asyncio.sleep(0)
        self.assertFalse(waiting.done())
        await self.manager.release(2, "owner")
        await waiting
        await self.manager.release(2, "next")

    async def test_due_count_survives_restart_and_private_state_contains_no_secrets(self):
        for number in range(1, 6):
            await self.request(number)
        restarted = self.make_manager()
        token = await restarted.acquire(await self.db.get_token(2), "after-restart")
        self.assertEqual(token.proxy_url, NEW)
        await restarted.release(2, "after-restart")
        self.assertEqual(stat.S_IMODE(self.state_path.stat().st_mode), 0o600)
        text = self.state_path.read_text()
        for secret in ("private-", "example.test", "http://", "request-", "email", "cookies"):
            self.assertNotIn(secret, text)

    async def test_rotation_changes_only_two_proxy_fields_and_invalidates_cache(self):
        before = (await self.db.get_token(2)).model_dump()
        await self.mark_health_error(fail_current=True)
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(self.db.writes, [(2, {"proxy_url": NEW, "captcha_proxy_url": NEW})])
        self.token_manager._clear_at_validation_cache.assert_called_once_with(2)
        for name, value in before.items():
            if name not in {"proxy_url", "captcha_proxy_url"}:
                self.assertEqual(getattr(token, name), value, name)

    async def test_all_failed_probes_keep_old_route_due_and_release_failed_acquisition(self):
        self.failures.update((OLD, NEW, OTHER))
        await self.mark_health_error()
        with self.assertRaises(BrowserCaptchaError) as failed:
            await self.manager.acquire(await self.db.get_token(2), "failed")
        self.assertIs(failed.exception.submission_pending, False)
        self.assertEqual(failed.exception.stage, "exit_rotation")
        self.assertEqual(self.db.writes, [])
        self.assertTrue(self.state()["accounts"]["2"]["due"])
        self.failures.clear()
        # A recovery attempt waits for the bounded failure interval. A
        # successful homepage cannot clear the earlier credits health error.
        self.manager._health_backoff.clear()
        recovered = await asyncio.wait_for(
            self.manager.acquire(await self.db.get_token(2), "recovered"), timeout=1)
        self.assertEqual(recovered.proxy_url, NEW)
        self.assertFalse(self.state()["accounts"]["2"]["due"])
        await self.manager.release(2, "recovered")

    async def test_dead_old_route_does_not_block_verified_recovery(self):
        self.failures.add(OLD)
        await self.mark_health_error()
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(token.proxy_url, NEW)
        self.assertEqual(self.state()["accounts"]["2"]["known_exit_ip"], "192.0.2.2")

    async def test_state_persistence_failure_restores_both_account_routes(self):
        await self.mark_health_error(fail_current=True)
        original_write = self.manager._write
        writes = 0
        def fail_once(state):
            nonlocal writes
            writes += 1
            if writes == 1:
                raise OSError("private path and credentials")
            original_write(state)
        with patch.object(self.manager, "_write", side_effect=fail_once):
            with self.assertRaises(BrowserCaptchaError) as failed:
                await self.manager.acquire(await self.db.get_token(2), "failed-state")
        self.assertIs(failed.exception.submission_pending, False)
        token = await self.db.get_token(2)
        self.assertEqual((token.proxy_url, token.captcha_proxy_url), (OLD, OLD))
        self.assertTrue(self.state()["accounts"]["2"]["due"])
        self.assertEqual(self.db.writes, [
            (2, {"proxy_url": NEW, "captcha_proxy_url": NEW}),
            (2, {"proxy_url": OLD, "captcha_proxy_url": OLD}),
        ])

    async def test_cancelled_probe_releases_account_and_pool_locks(self):
        await self.mark_health_error()
        entered = asyncio.Event()
        async def waiting_probe(route):
            if route == OLD:
                return {"ip": "", "flow_status": None}
            entered.set()
            await asyncio.Event().wait()
        self.manager._probe_override = waiting_probe
        pending = asyncio.create_task(self.manager.acquire(await self.db.get_token(2), "cancelled"))
        await entered.wait()
        pending.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await pending
        self.assertEqual(self.db.writes, [])
        self.manager._probe_override = self.probe
        token = await asyncio.wait_for(self.manager.acquire(await self.db.get_token(2), "after-cancel"), timeout=1)
        self.assertEqual(token.proxy_url, NEW)
        self.assertFalse(self.state()["accounts"]["2"]["due"])
        await self.manager.release(2, "after-cancel")

    async def test_same_actual_ip_is_rejected_even_when_proxy_url_differs(self):
        async def probe(route):
            return {
                "ip": "192.0.2.3" if route == OTHER else "192.0.2.1",
                "flow_status": 503 if route == OLD else 200,
            }
        self.manager._probe_override = probe
        await self.mark_health_error()
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(token.proxy_url, OTHER)

    async def test_static_candidates_precede_airport_and_bad_or_disabled_are_skipped(self):
        self.pool["proxies"] = {
            "airport": {"source": "airport", "fallback_tier": 0, "host": "airport.test", "port": 8004},
            "disabled": {"disabled": True, "host": "disabled.test", "port": 8005},
            "invalid": {"host": "invalid.test", "port": 0},
            **self.pool["proxies"],
        }
        self.pool_path.write_text(json.dumps(self.pool))
        await self.mark_health_error(fail_current=True)
        await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(self.probes[0], OLD)
        self.assertIn(NEW, self.probes)

    async def test_repeated_threshold_rotations_advance_through_static_pool(self):
        self.policy["threshold"] = 1
        self.save_policy()
        routes = []
        token = await self.db.get_token(2)
        for number in range(3):
            token = await self.manager.acquire(token, f"threshold-{number}")
            await self.manager.note_sent(2, f"threshold-{number}")
            await self.manager.release(2, f"threshold-{number}")
            token = await self.manager.prepare_token(token)
            routes.append(token.proxy_url)
        self.assertEqual(routes, [NEW, OTHER, OLD])

    async def test_candidate_bound_and_non_200_flow_preserve_old_route(self):
        self.policy["max_candidates"] = 1
        self.save_policy()
        self.manager._probe_override = AsyncMock(return_value={"ip": "192.0.2.2", "flow_status": 403})
        await self.mark_health_error()
        with self.assertRaises(BrowserCaptchaError):
            await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(self.manager._probe_override.await_count, 2)
        self.assertEqual(self.db.writes, [])

    async def test_logs_and_public_status_never_contain_proxy_credentials(self):
        self.failures.update((OLD, NEW))
        await self.mark_health_error()
        with self.assertLogs("debug_logger", level=logging.WARNING) as captured:
            await self.manager.prepare_token(await self.db.get_token(2))
        text = "\n".join(captured.output) + json.dumps(await self.manager.snapshot())
        for secret in ("private-", "example.test", "http://", "Cookie", "Authorization"):
            self.assertNotIn(secret, text)

    async def test_absent_policy_and_unregistered_account_are_inert(self):
        self.policy_path.unlink()
        token = await self.db.get_token(2)
        self.assertIs(await self.manager.acquire(token, "disabled"), token)
        await self.manager.note_sent(2, "disabled")
        await self.manager.note_error(2, "disabled")
        await self.manager.release(2, "disabled")
        self.assertFalse(self.state_path.exists())
        self.assertFalse((await self.manager.snapshot())["enabled"])
        self.policy["token_ids"] = [3]
        self.save_policy()
        self.assertIs(await self.manager.prepare_token(token), token)
        await self.manager.mark_health_error(2, NETWORK_ERROR)
        self.assertFalse(self.state_path.exists())
        self.probe.assert_not_awaited()

    async def test_corrupt_state_fails_closed_without_resetting_counter_or_route(self):
        self.state_path.write_text("broken state")
        with self.assertRaises(BrowserCaptchaError) as failed:
            await self.manager.acquire(await self.db.get_token(2), "request")
        self.assertIs(failed.exception.submission_pending, False)
        self.assertEqual(self.state_path.read_text(), "broken state")
        self.assertEqual(self.db.writes, [])


if __name__ == "__main__":
    unittest.main()
