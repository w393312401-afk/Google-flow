"""Offline rotation invariants: accounting, leases and no paid request replay."""
import asyncio
import json
import logging
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from src.core.models import Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.exit_rotation import ExitRotationManager


OLD = "http://old:private-old@old.example.test:8000"
NEW = "http://new:private-new@new.example.test:8001"
OTHER = "http://other:private-other@other.example.test:8002"


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

    async def test_generation_error_marks_future_rotation_without_replaying_current(self):
        await self.request(1, error=True)
        self.assertEqual(self.db.writes, [])
        self.assertEqual(self.state()["accounts"]["2"]["error"], "generation_error")
        token = await self.manager.acquire(await self.db.get_token(2), "next")
        self.assertEqual(token.proxy_url, NEW)
        self.assertEqual(self.probe.await_count, 2)
        await self.manager.release(2, "next")

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
        await self.manager.mark_health_error(2)
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(self.db.writes, [(2, {"proxy_url": NEW, "captcha_proxy_url": NEW})])
        self.token_manager._clear_at_validation_cache.assert_called_once_with(2)
        for name, value in before.items():
            if name not in {"proxy_url", "captcha_proxy_url"}:
                self.assertEqual(getattr(token, name), value, name)

    async def test_all_failed_probes_keep_old_route_due_and_release_failed_acquisition(self):
        self.failures.update((NEW, OTHER))
        await self.manager.mark_health_error(2)
        with self.assertRaises(BrowserCaptchaError) as failed:
            await self.manager.acquire(await self.db.get_token(2), "failed")
        self.assertIs(failed.exception.submission_pending, False)
        self.assertEqual(failed.exception.stage, "exit_rotation")
        self.assertEqual(self.db.writes, [])
        self.assertTrue(self.state()["accounts"]["2"]["due"])
        self.failures.clear()
        recovered = await asyncio.wait_for(
            self.manager.acquire(await self.db.get_token(2), "recovered"), timeout=1)
        self.assertEqual(recovered.proxy_url, NEW)
        await self.manager.release(2, "recovered")

    async def test_dead_old_route_does_not_block_verified_recovery(self):
        self.failures.add(OLD)
        await self.manager.mark_health_error(2)
        token = await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(token.proxy_url, NEW)
        self.assertEqual(self.state()["accounts"]["2"]["known_exit_ip"], "192.0.2.2")

    async def test_state_persistence_failure_restores_both_account_routes(self):
        await self.manager.mark_health_error(2)
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
        await self.manager.mark_health_error(2)
        entered = asyncio.Event()
        async def waiting_probe(route):
            if route == OLD:
                return {"ip": "192.0.2.1", "flow_status": 200}
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
        await self.manager.release(2, "after-cancel")

    async def test_same_actual_ip_is_rejected_even_when_proxy_url_differs(self):
        async def probe(route):
            return {"ip": "192.0.2.3" if route == OTHER else "192.0.2.1", "flow_status": 200}
        self.manager._probe_override = probe
        await self.manager.mark_health_error(2)
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
        await self.manager.mark_health_error(2)
        await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(self.probes, [OLD, NEW])

    async def test_repeated_rotations_advance_through_static_pool(self):
        routes = []
        for _ in range(3):
            await self.manager.mark_health_error(2)
            token = await self.manager.prepare_token(await self.db.get_token(2))
            routes.append(token.proxy_url)
        self.assertEqual(routes, [NEW, OTHER, OLD])

    async def test_candidate_bound_and_non_200_flow_preserve_old_route(self):
        self.policy["max_candidates"] = 1
        self.save_policy()
        self.manager._probe_override = AsyncMock(return_value={"ip": "192.0.2.2", "flow_status": 403})
        await self.manager.mark_health_error(2)
        with self.assertRaises(BrowserCaptchaError):
            await self.manager.prepare_token(await self.db.get_token(2))
        self.assertEqual(self.manager._probe_override.await_count, 2)
        self.assertEqual(self.db.writes, [])

    async def test_logs_and_public_status_never_contain_proxy_credentials(self):
        self.failures.add(NEW)
        await self.manager.mark_health_error(2)
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
        await self.manager.mark_health_error(2)
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
