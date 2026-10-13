"""Offline admin/scheduled-sync admission and fail-closed snapshot regressions."""

import asyncio
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
import httpx

from src.api import admin
from src.core.account_admission import AccountAdmission, AccountAdmissionBusy
from src.core.models import Token
from src.services.credential_recovery import CredentialRecoveryError


_fixture_spec = importlib.util.spec_from_file_location(
    "offline_api_recovery_fixture", Path(__file__).with_name("test_credential_recovery.py"))
_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture)


class AccountAdmissionApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.admission = AccountAdmission(self.root / "synthetic.db")
        self.manager = SimpleNamespace(account_admission=self.admission)
        self.enterContext(patch.object(admin, "token_manager", self.manager))
        self.enterContext(patch.object(admin, "db", None))
        self.enterContext(patch.object(admin, "concurrency_manager", None))
        self.real_inner = admin._update_token_admitted
        self.inner = self.enterContext(patch.object(
            admin, "_update_token_admitted", AsyncMock(return_value={"success": True})))
        app = FastAPI()
        app.include_router(admin.router)
        app.dependency_overrides[admin.verify_admin_token] = lambda: "synthetic-admin"
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://offline.test")
        self.addAsyncCleanup(self.client.aclose)

    async def update(self, capability=None):
        headers = {} if capability is None else {"X-Flow-Maintenance-Capability": capability}
        return await self.client.put("/api/tokens/7", json={"auto_enable_on_update": False}, headers=headers)

    async def test_manual_update_rejects_generation_before_calling_inner(self):
        with self.admission.generation(7):
            response = await self.update()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["code"], "generation_busy")
        self.inner.assert_not_awaited()

    async def test_scheduled_header_joins_worker_during_parent_maintenance(self):
        with self.admission.maintenance(7) as parent:
            response = await self.update(parent.capability)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()["success"])
            self.inner.assert_awaited_once()
            with self.assertRaises(AccountAdmissionBusy):
                self.admission.generation(7)
        with self.admission.generation(7):
            pass

    async def test_update_without_capability_cannot_reenter_parent_maintenance(self):
        with self.admission.maintenance(7):
            response = await self.update()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["code"], "already_running")
        self.inner.assert_not_awaited()

    async def test_bad_capabilities_fail_safely_without_conversion(self):
        for capability in ("SYNTHETIC_PRIVATE_CAPABILITY", "a" * 63, "A" * 64, "f" * 64):
            with self.subTest(capability_type=len(capability)):
                response = await self.update(capability)
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.json()["detail"]["code"], "busy_state_unknown")
                self.assertNotIn(capability, response.text)
        self.inner.assert_not_awaited()
        with self.admission.generation(7):
            pass

    async def test_expired_and_previous_owner_capabilities_are_rejected(self):
        parent = self.admission.maintenance(7)
        capability = parent.capability
        parent.close()
        expired = await self.update(capability)
        self.assertEqual(expired.status_code, 409)
        self.assertEqual(expired.json()["detail"]["code"], "busy_state_unknown")
        with self.admission.maintenance(7):
            stale = await self.update(capability)
            self.assertEqual(stale.status_code, 409)
            self.assertEqual(stale.json()["detail"]["code"], "busy_state_unknown")
        self.inner.assert_not_awaited()

    async def test_conversion_keeps_worker_ownership_when_parent_exits(self):
        entered, release = asyncio.Event(), asyncio.Event()
        existing = Token(id=7, st="synthetic-st", at="synthetic-at", email="synthetic@example.test")
        self.manager.get_token = AsyncMock(return_value=existing)
        self.manager.update_token = AsyncMock()

        async def convert(*args, **kwargs):
            entered.set()
            await release.wait()
            return {"access_token": "synthetic-new-at", "expires": "2099-01-01T00:00:00Z"}

        async def routed(_proxy, action):
            return await action()

        self.manager.flow_client = SimpleNamespace(st_to_at=AsyncMock(side_effect=convert))
        self.manager._flow_call_with_proxy = routed
        self.inner.side_effect = self.real_inner
        parent = self.admission.maintenance(7)
        task = asyncio.create_task(self.update(parent.capability))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            parent.close()
            with self.assertRaises(AccountAdmissionBusy):
                self.admission.generation(7)
            with self.assertRaises(AccountAdmissionBusy) as caught:
                self.admission.maintenance(7)
            self.assertEqual(caught.exception.reason, "already_running")
            self.manager.update_token.assert_not_awaited()
            release.set()
            response = await asyncio.wait_for(task, 2)
            self.assertEqual(response.status_code, 200)
            self.manager.flow_client.st_to_at.assert_awaited_once()
            self.manager.update_token.assert_awaited_once()
            with self.admission.generation(7):
                pass
        finally:
            parent.close()
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_inner_failure_releases_delegated_worker(self):
        self.inner.side_effect = RuntimeError("synthetic conversion failed")
        with self.admission.maintenance(7) as parent:
            with self.assertRaisesRegex(RuntimeError, "synthetic"):
                await self.update(parent.capability)
            with self.admission.worker(7, parent.capability):
                pass

    async def test_optional_manager_without_admission_preserves_test_compatibility(self):
        with patch.object(admin, "token_manager", SimpleNamespace()):
            response = await self.update()
        self.assertEqual(response.status_code, 200)
        self.inner.assert_awaited_once()


class RecoverySnapshotFailureTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.case = _fixture.CredentialRecoveryTests(
            "test_login_then_live_sync_verifies_identity_and_credits_and_preserves_flags")
        await self.case.asyncSetUp()
        self.addCleanup(self.clean_fixture)
        with sqlite3.connect(self.case.db.db_path) as conn:
            conn.execute("CREATE TABLE tasks(token_id INTEGER, status TEXT)")
            conn.execute("CREATE TABLE request_logs(token_id INTEGER,status_code INTEGER,status_text TEXT)")
        self.real_sync = _fixture.load_local("sync_adspower_cookies")
        self.gateway = self.real_sync.Gateway(self.case.config, None, {})
        self.enterContext(patch.object(self.real_sync, "private_json", return_value={}))

        async def busy(token_id):
            return await self.gateway.busy(token_id)

        self.case.busy.side_effect = busy

    def clean_fixture(self):
        while self.case._cleanups:
            cleanup, args, kwargs = self.case._cleanups.pop()
            cleanup(*args, **kwargs)

    async def assert_snapshot_rejected(self, tasks, board):
        self.gateway.request = AsyncMock(side_effect=[tasks, board])
        with self.assertRaises(CredentialRecoveryError) as caught:
            await self.case.service.recover(7)
        self.assertEqual(caught.exception.code, "busy_state_unknown")
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.case.db.writes, [])
        self.case.manager._st_to_at_for_token.assert_not_awaited()
        self.assertEqual(self.case.service._running, {})
        with self.case.manager.account_admission.generation(7):
            pass

    async def test_incomplete_spark_inventory_maps_to_safe_busy_409(self):
        await self.assert_snapshot_rejected(
            {"tasks": [], "total_count": 1},
            {"status": "ok", "board": {"leases": [], "waiting": []}})

    async def test_unknown_spark_task_status_maps_to_safe_busy_409(self):
        await self.assert_snapshot_rejected(
            {"tasks": [{"status": "SYNTHETIC_UNKNOWN_STATUS"}], "total_count": 1},
            {"status": "ok", "board": {"leases": [], "waiting": []}})

    async def test_malformed_spark_lease_inventory_maps_to_safe_busy_409(self):
        await self.assert_snapshot_rejected(
            {"tasks": [], "total_count": 0},
            {"status": "ok", "board": {"leases": None, "waiting": []}})


if __name__ == "__main__":
    unittest.main()
