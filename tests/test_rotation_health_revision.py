"""One successful check cannot consume a later failure on the same identity."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from src.core.database import Database
from src.core.models import Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.exit_rotation import ExitRotationManager
from src.services.token_manager import TokenManager


FAILURE = "AT_CHECK: network or proxy unavailable"
ROUTE = "http://offline.example.test:8000"


class RotationHealthRevisionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.db = Database(str(root / "offline.db"))
        await self.db.init_db()
        self.token_id = await self.db.add_token(Token(
            email="offline@example.test", st="offline-session", at="offline-at",
            at_expires=datetime.now(timezone.utc) + timedelta(days=1),
            google_cookies="OSID=offline; SID=offline", proxy_url=ROUTE,
            captcha_proxy_url=ROUTE,
        ))
        pool = root / "pool.json"
        pool.write_text(json.dumps({"proxies": {
            "current": {"host": "offline.example.test", "port": 8000},
        }}))
        self.policy_path = root / "policy.json"
        self.policy_path.write_text(json.dumps({
            "enabled": True, "token_ids": [self.token_id], "threshold": 5,
            "pool_path": str(pool), "max_candidates": 3, "probe_timeout_seconds": 1,
        }))
        self.state_path = root / "state.json"
        self.manager = TokenManager(self.db, SimpleNamespace())
        self.manager._get_credits_for_token = AsyncMock(return_value={"credits": 123})
        self.probe = AsyncMock(return_value={"ip": "192.0.2.1", "flow_status": 200})
        self.rotation = self.restart_rotation()
        self.assertTrue(await self.mark())

    def restart_rotation(self):
        return ExitRotationManager(self.db, self.manager, policy_path=self.policy_path,
                                   state_path=self.state_path, probe=self.probe)

    async def token(self):
        return await self.db.get_token(self.token_id)

    async def mark(self):
        return await self.rotation.mark_health_error(self.token_id, FAILURE,
            failed_identity=TokenManager.health_identity(await self.token()))

    def record(self):
        return json.loads(self.state_path.read_text())["accounts"][str(self.token_id)]

    def change_record(self, **changes):
        state = json.loads(self.state_path.read_text())
        state["accounts"][str(self.token_id)].update(changes)
        self.state_path.write_text(json.dumps(state))

    async def prepare(self):
        return await asyncio.wait_for(self.rotation.prepare_token(await self.token()), 2)

    async def test_same_identity_new_failure_survives_earlier_success(self):
        real_revalidate = self.manager.revalidate_token_under_admission

        async def new_failure():
            token = await self.token()
            await self.manager._record_at_failure(self.token_id, FAILURE, token=token)
            self.assertTrue(await self.mark())

        async def revalidate_then_new_failure(token):
            validated = await real_revalidate(token)
            # A different caller retains its own immutable validation outcome.
            await asyncio.create_task(new_failure())
            return validated

        self.manager.revalidate_token_under_admission = revalidate_then_new_failure
        with self.assertRaises(BrowserCaptchaError):
            await self.prepare()
        self.assertTrue(self.record()["due"])
        self.assertEqual(self.record()["error"], "health_error")
        self.assertEqual(self.record()["health_error_revision"], 2)
        self.assertIsNotNone(self.manager.get_validation_cooldown_reason(await self.token()))

    async def test_new_mark_waiting_on_db_commits_before_old_success_can_clear(self):
        real_revalidate = self.manager.revalidate_token_under_admission
        original_get = self.db.get_token
        mark_entered, finish_mark = asyncio.Event(), asyncio.Event()
        marker = None

        async def held_get(token_id):
            if asyncio.current_task() is marker:
                mark_entered.set()
                await finish_mark.wait()
            return await original_get(token_id)

        async def revalidate_then_pending_mark(token):
            nonlocal marker
            validated = await real_revalidate(token)
            marker = asyncio.create_task(self.rotation.mark_health_error(
                self.token_id, FAILURE, failed_identity=TokenManager.health_identity(validated)))
            await mark_entered.wait()
            # mark_health_error holds _state_lock while its DB read is pending.
            return validated

        self.db.get_token = held_get
        self.manager.revalidate_token_under_admission = revalidate_then_pending_mark
        pending = asyncio.create_task(self.prepare())
        try:
            await asyncio.wait_for(mark_entered.wait(), 2)
            await asyncio.sleep(0)
            finish_mark.set()
            self.assertTrue(await asyncio.wait_for(marker, 2))
            with self.assertRaises(BrowserCaptchaError):
                await pending
        finally:
            finish_mark.set()
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            if marker is not None:
                await asyncio.gather(marker, return_exceptions=True)
        self.assertTrue(self.record()["due"])
        self.assertEqual(self.record()["health_error_revision"], 2)

    async def test_normal_recovery_clears_only_due_and_keeps_revision_private(self):
        self.assertEqual((await self.prepare()).proxy_url, ROUTE)
        self.assertFalse(self.record()["due"])
        self.assertEqual(self.record()["health_error_revision"], 1)
        public = json.dumps(await self.rotation.snapshot())
        self.assertNotIn("health_error_identity", public)
        self.assertNotIn("health_error_revision", public)
        self.manager._get_credits_for_token.assert_awaited_once()

    async def test_revision_never_resets_after_recovery_and_restart(self):
        await self.prepare()
        self.rotation = self.restart_rotation()
        self.assertTrue(await self.mark())
        self.assertEqual(self.record()["health_error_revision"], 2)
        await self.prepare()
        self.rotation = self.restart_rotation()
        self.assertTrue(await self.mark())
        self.assertEqual(self.record()["health_error_revision"], 3)

    async def test_stale_identity_cleanup_preserves_revision_for_next_failure(self):
        await self.db.update_token(self.token_id, at="replacement-at")
        await self.prepare()
        self.assertFalse(self.record()["due"])
        self.assertEqual(self.record()["health_error_revision"], 1)
        self.assertTrue(await self.mark())
        self.assertEqual(self.record()["health_error_revision"], 2)

    async def test_legacy_state_without_revision_recovers_and_starts_counter(self):
        state = json.loads(self.state_path.read_text())
        state["accounts"][str(self.token_id)].pop("health_error_revision")
        self.state_path.write_text(json.dumps(state))
        self.rotation = self.restart_rotation()
        await self.prepare()
        self.assertFalse(self.record()["due"])
        self.assertEqual(self.record()["health_error_revision"], 0)
        self.assertTrue(await self.mark())
        self.assertEqual(self.record()["health_error_revision"], 1)

    async def test_threshold_is_never_waived_by_revision_or_current_route_health(self):
        self.change_record(count=5, due=True, error="threshold")
        self.assertTrue(await self.mark())
        with self.assertRaises(BrowserCaptchaError):
            await self.prepare()
        self.manager._get_credits_for_token.assert_not_awaited()
        self.assertTrue(self.record()["due"])
        self.assertEqual(self.record()["count"], 5)
        self.assertEqual(self.record()["error"], "threshold")
        self.assertEqual(self.record()["health_error_revision"], 2)


if __name__ == "__main__":
    unittest.main()
