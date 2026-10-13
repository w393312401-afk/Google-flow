"""Offline recovery/generation admission regressions, including non-stream work."""

import asyncio
import importlib.util
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock

from src.core.account_admission import AccountAdmission, AccountAdmissionBusy
from src.services.concurrency_manager import ConcurrencyManager
from src.services.credential_recovery import CredentialRecoveryError
from src.services.generation_handler import GenerationHandler


_fixture_spec = importlib.util.spec_from_file_location(
    "offline_admission_recovery_fixture", Path(__file__).with_name("test_credential_recovery.py"))
_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture)


class RecoveryGenerationAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.case = _fixture.CredentialRecoveryTests(
            "test_login_then_live_sync_verifies_identity_and_credits_and_preserves_flags")
        await self.case.asyncSetUp()
        self.addCleanup(self.clean_fixture)
        with sqlite3.connect(self.case.db.db_path) as conn:
            conn.execute("CREATE TABLE tasks(token_id INTEGER, status TEXT)")
            conn.execute("CREATE TABLE request_logs(token_id INTEGER,status_code INTEGER,status_text TEXT)")
        self.token = self.case.token.model_copy(update={
            "is_active": True, "user_paygate_tier": "PAYGATE_TIER_ONE"})
        self.case.db.rows[7] = self.token
        self.case.manager.account_admission = AccountAdmission(self.case.db.db_path)
        self.case.manager._ensure_valid_token_inner = AsyncMock(side_effect=lambda value: value)

        async def busy(token_id):
            return False, self.case.sync.flow_busy(self.case.db.db_path, token_id)

        self.case.busy.side_effect = busy
        self.handler = GenerationHandler.__new__(GenerationHandler)
        self.handler.db = self.case.db
        self.handler.concurrency_manager = ConcurrencyManager()
        await self.handler.concurrency_manager.initialize([self.token])
        self.handler.flow_client = SimpleNamespace(
            clear_request_fingerprint=Mock(), prefill_remote_browser_pool=AsyncMock())
        self.handler.load_balancer = SimpleNamespace(
            select_token=AsyncMock(return_value=self.token), release_pending=AsyncMock())
        self.handler.token_manager = self.case.manager
        self.handler.token_manager.ensure_project_exists = AsyncMock(return_value="synthetic-project")
        self.handler.token_manager.record_usage = AsyncMock()
        self.handler.token_manager.record_success = AsyncMock()
        self.handler.token_manager.record_error = AsyncMock()
        self.handler._log_request = AsyncMock(return_value=None)
        self.model = "omni-1.1-flash-10s-portrait-360p"
        self.tasks = []
        self.releases = []

    def clean_fixture(self):
        # This reused IsolatedAsyncioTestCase is a fixture, without its own
        # unittest runner; its registered temporary-directory/patch cleanups
        # are synchronous and must run in the current test's runner.
        while self.case._cleanups:
            cleanup, args, kwargs = self.case._cleanups.pop()
            cleanup(*args, **kwargs)

    async def asyncTearDown(self):
        for release in self.releases:
            release.set()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for task in tuple(self.case.service._running.values()):
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def start(self, awaitable):
        task = asyncio.create_task(awaitable)
        self.tasks.append(task)
        return task

    def make_event(self):
        release = asyncio.Event()
        self.releases.append(release)
        return release

    async def collect_generation(self):
        return [part async for part in self.handler.handle_generation(
            self.model, "synthetic prompt", stream=False)]

    def pipeline(self, entered, release=None):
        async def submission(*args, generation_result, **kwargs):
            entered.set()
            if release is not None:
                await release.wait()
            generation_result["success"] = True
            yield "synthetic-complete"

        self.handler._handle_video_generation = submission

    async def wait_entered(self, event):
        await asyncio.wait_for(event.wait(), 2)

    def assert_generation_blocked(self):
        with self.assertRaises(AccountAdmissionBusy):
            self.case.manager.account_admission.generation(7)

    async def test_live_nonstream_generation_rejects_recovery_before_host_or_write(self):
        entered, release = asyncio.Event(), self.make_event()
        self.pipeline(entered, release)
        generation = self.start(self.collect_generation())
        await self.wait_entered(entered)
        self.assertEqual(await self.handler.concurrency_manager.get_video_inflight(7), 1)
        # The original bug: an in-flight non-stream submission has no DB receipt.
        self.assertFalse(self.case.sync.flow_busy(self.case.db.db_path, 7))
        with self.assertRaises(CredentialRecoveryError) as caught:
            await self.case.service.recover(7)
        self.assertEqual(caught.exception.code, "generation_busy")
        self.case.host.assert_not_awaited()
        self.assertEqual(self.case.db.writes, [])
        release.set()
        self.assertEqual(await generation, ["synthetic-complete"])
        self.assertTrue((await self.case.service.recover(7))["success"])

    async def test_refresh_owns_account_before_host_and_blocks_new_generation_pipeline(self):
        host_entered, release = asyncio.Event(), self.make_event()

        async def blocked_host(*args, **kwargs):
            host_entered.set()
            await release.wait()
            return self.case.proof

        self.case.host.side_effect = blocked_host
        recovery = self.start(self.case.service.recover(7))
        await self.wait_entered(host_entered)
        self.assert_generation_blocked()
        pipeline_entered = asyncio.Event()
        self.pipeline(pipeline_entered)
        generation = self.start(self.collect_generation())
        await asyncio.sleep(0.05)
        self.assertFalse(pipeline_entered.is_set())
        self.assertEqual(self.case.db.writes, [])
        release.set()
        self.assertTrue((await recovery)["success"])
        await asyncio.wait_for(generation, 2)
        with self.case.manager.account_admission.maintenance(7):
            pass

    async def test_host_return_to_live_sync_keeps_maintenance_ownership(self):
        sync_entered, release = asyncio.Event(), self.make_event()

        async def blocked_conversion(*args, **kwargs):
            sync_entered.set()
            await release.wait()
            return {"access_token": "SYNTHETIC_FRESH_AT", "expires": "2099-01-01T00:00:00Z"}

        self.case.manager._st_to_at_for_token.side_effect = blocked_conversion
        recovery = self.start(self.case.service.recover(7))
        await self.wait_entered(sync_entered)
        self.case.host.assert_awaited_once()
        self.assert_generation_blocked()
        self.assertEqual(self.case.db.writes, [])
        release.set()
        self.assertTrue((await recovery)["success"])
        with self.case.manager.account_admission.generation(7):
            pass

    async def test_disconnected_caller_cannot_release_shielded_maintenance(self):
        host_entered, release = asyncio.Event(), self.make_event()

        async def blocked_host(*args, **kwargs):
            host_entered.set()
            await release.wait()
            return self.case.proof

        self.case.host.side_effect = blocked_host
        first = self.start(self.case.service.recover(7))
        await self.wait_entered(host_entered)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        self.assert_generation_blocked()
        second = self.start(self.case.service.recover(7))
        await asyncio.sleep(0)
        self.case.host.assert_awaited_once()
        release.set()
        self.assertTrue((await second)["success"])
        self.assertEqual(len(self.case.db.writes), 1)
        self.assertEqual(self.case.service._running, {})
        with self.case.manager.account_admission.generation(7):
            pass

    async def test_cancelled_generation_releases_account_before_next_recovery(self):
        entered, release = asyncio.Event(), self.make_event()
        self.pipeline(entered, release)
        generation = self.start(self.collect_generation())
        await self.wait_entered(entered)
        generation.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await generation
        self.assertEqual(await self.handler.concurrency_manager.get_video_inflight(7), 0)
        self.assertTrue((await self.case.service.recover(7))["success"])


if __name__ == "__main__":
    unittest.main()
