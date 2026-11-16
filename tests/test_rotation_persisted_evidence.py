"""Stored rotation evidence must remain bound to the session it actually checked."""

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
from src.services.exit_rotation import ExitRotationManager
from src.services.token_manager import TokenManager


OLD = "http://old.example.test:8000"
NEW = "http://new.example.test:8001"
OTHER = "http://other.example.test:8002"
HEALTH_FAILURE = "AT_CHECK: upstream unavailable (HTTP 502)"


class PersistedRotationEvidenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.db = Database(db_path=str(root / "offline.db"))
        await self.db.init_db()
        self.token_id = await self.db.add_token(Token(
            email="offline@example.test", st="offline-session", at="offline-at",
            at_expires=datetime.now(timezone.utc) + timedelta(days=1),
            google_cookies="OSID=offline; SID=offline",
            proxy_url=OLD, captcha_proxy_url=OLD,
        ))
        pool_path = root / "pool.json"
        pool_path.write_text(json.dumps({"proxies": {
            "old": {"host": "old.example.test", "port": 8000},
            "new": {"host": "new.example.test", "port": 8001},
            "other": {"host": "other.example.test", "port": 8002},
        }}))
        self.policy_path = root / "policy.json"
        self.policy_path.write_text(json.dumps({
            "enabled": True, "token_ids": [self.token_id], "threshold": 5,
            "pool_path": str(pool_path), "max_candidates": 3,
            "probe_timeout_seconds": 1,
        }))
        self.state_path = root / "state.json"
        self.manager = TokenManager(self.db, SimpleNamespace())

        async def probe(route):
            return {"ip": {OLD: "192.0.2.1", NEW: "192.0.2.2", OTHER: "192.0.2.3"}[route],
                    "flow_status": 200}

        self.probe = AsyncMock(side_effect=probe)
        self.rotation = self.restart_rotation()
        self.route_writes = []
        original_update = self.db.update_token

        async def update(token_id, **changes):
            await original_update(token_id, **changes)
            if "proxy_url" in changes:
                self.route_writes.append(changes["proxy_url"])

        self.db.update_token = update
        conditional_update = getattr(self.db, "update_token_routes_if_health_matches", None)
        if conditional_update is not None:
            async def update_if_matches(expected, **changes):
                applied = await conditional_update(expected, **changes)
                if applied:
                    self.route_writes.append(changes["proxy_url"])
                return applied

            self.db.update_token_routes_if_health_matches = update_if_matches

    def restart_rotation(self):
        rotation = ExitRotationManager(
            self.db, self.manager, policy_path=self.policy_path,
            state_path=self.state_path, probe=self.probe,
        )
        self.manager.exit_rotation = rotation
        return rotation

    async def token(self):
        return await self.db.get_token(self.token_id)

    async def mark_current_failure(self):
        return await self.rotation.mark_health_error(
            self.token_id, HEALTH_FAILURE,
            failed_identity=TokenManager.health_identity(await self.token()),
        )

    async def replace_route_under_maintenance(self):
        with self.manager.account_admission.maintenance(self.token_id):
            await self.manager.update_token(
                self.token_id, proxy_url=NEW, captcha_proxy_url=NEW,
            )

    def saved_state(self):
        return json.loads(self.state_path.read_text())["accounts"][str(self.token_id)]

    async def test_old_due_evidence_cannot_rotate_manual_replacement(self):
        self.assertTrue(await self.mark_current_failure())
        await self.replace_route_under_maintenance()
        prepared = await self.rotation.prepare_token(await self.token())
        self.assertEqual(prepared.proxy_url, NEW)
        self.assertEqual(self.route_writes, [NEW])
        self.assertFalse(self.saved_state()["due"])
        self.assertIsNone(self.saved_state()["error"])

    async def test_restart_preserves_evidence_binding_and_keeps_manual_replacement(self):
        self.assertTrue(await self.mark_current_failure())
        await self.replace_route_under_maintenance()
        self.rotation = self.restart_rotation()
        prepared = await self.rotation.prepare_token(await self.token())
        self.assertEqual(prepared.proxy_url, NEW)
        self.assertEqual(self.route_writes, [NEW])
        self.assertFalse(self.saved_state()["due"])

    async def test_restart_preserves_same_identity_failure_and_still_repairs_it(self):
        self.assertTrue(await self.mark_current_failure())
        self.rotation = self.restart_rotation()
        prepared = await self.rotation.prepare_token(await self.token())
        self.assertNotEqual(prepared.proxy_url, OLD)
        self.assertEqual(len(self.route_writes), 1)
        self.assertFalse(self.saved_state()["due"])

    async def test_new_identity_failure_supersedes_old_persisted_evidence(self):
        self.assertTrue(await self.mark_current_failure())
        await self.replace_route_under_maintenance()
        self.assertTrue(await self.mark_current_failure())
        self.rotation = self.restart_rotation()
        prepared = await self.rotation.prepare_token(await self.token())
        self.assertNotEqual(prepared.proxy_url, NEW)
        self.assertEqual(len(self.route_writes), 2)
        self.assertFalse(self.saved_state()["due"])

    async def test_threshold_remains_due_when_old_health_identity_is_superseded(self):
        for index in range(4):
            request_id = f"completed-{index}"
            await self.rotation.acquire(await self.token(), request_id)
            await self.rotation.note_sent(self.token_id, request_id)
            await self.rotation.release(self.token_id, request_id)
        await self.rotation.acquire(await self.token(), "fifth")
        self.assertTrue(await self.mark_current_failure())
        await self.rotation.note_sent(self.token_id, "fifth")
        await self.rotation.release(self.token_id, "fifth")
        self.assertEqual(self.saved_state()["count"], 5)
        await self.replace_route_under_maintenance()
        self.rotation = self.restart_rotation()
        prepared = await self.rotation.prepare_token(await self.token())
        self.assertNotEqual(prepared.proxy_url, NEW)
        self.assertEqual(len(self.route_writes), 2)
        self.assertEqual(self.saved_state()["count"], 0)
        self.assertFalse(self.saved_state()["due"])

    async def test_replacement_credentials_do_not_inherit_old_failure_evidence(self):
        self.assertTrue(await self.mark_current_failure())
        with self.manager.account_admission.maintenance(self.token_id):
            await self.manager.update_token(
                self.token_id, st="new-session", google_cookies="OSID=new; SID=new",
            )
        self.rotation = self.restart_rotation()
        prepared = await self.rotation.prepare_token(await self.token())
        self.assertEqual(prepared.proxy_url, OLD)
        self.assertEqual(self.route_writes, [])
        self.assertFalse(self.saved_state()["due"])

    async def update_at_while_probe_is_pending(self):
        entered, release = asyncio.Event(), asyncio.Event()
        original_probe = self.probe.side_effect

        async def wait_for_at_update(route):
            if route == OLD:
                entered.set()
                await release.wait()
            return await original_probe(route)

        self.probe.side_effect = wait_for_at_update
        pending = asyncio.create_task(self.rotation.prepare_token(await self.token()))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            # A direct AT refresh can commit while the rotation's shared
            # generation admission is held; it needs no maintenance lease.
            await self.manager.update_token(self.token_id, at="newly-validated-at")
            release.set()
            return await asyncio.wait_for(pending, 2)
        finally:
            release.set()
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)

    async def test_at_replaced_during_probe_invalidates_error_before_route_commit(self):
        self.assertTrue(await self.mark_current_failure())
        prepared = await self.update_at_while_probe_is_pending()
        self.assertEqual(prepared.proxy_url, OLD)
        self.assertEqual(prepared.at, "newly-validated-at")
        self.assertEqual((await self.token()).at, "newly-validated-at")
        self.assertEqual(self.route_writes, [])
        self.assertFalse(self.saved_state()["due"])

    async def test_at_replaced_during_probe_does_not_cancel_threshold_rotation(self):
        for index in range(5):
            request_id = f"threshold-{index}"
            await self.rotation.acquire(await self.token(), request_id)
            await self.rotation.note_sent(self.token_id, request_id)
            await self.rotation.release(self.token_id, request_id)
        self.assertTrue(await self.mark_current_failure())
        prepared = await self.update_at_while_probe_is_pending()
        self.assertNotEqual(prepared.proxy_url, OLD)
        self.assertEqual(prepared.at, "newly-validated-at")
        self.assertEqual((await self.token()).at, "newly-validated-at")
        self.assertEqual(len(self.route_writes), 1)
        self.assertEqual(self.saved_state()["count"], 0)
        self.assertFalse(self.saved_state()["due"])

    async def test_at_replaced_after_final_check_is_rejected_by_atomic_route_write(self):
        self.assertTrue(await self.mark_current_failure())
        entered, release = asyncio.Event(), asyncio.Event()
        conditional_update = self.db.update_token_routes_if_health_matches

        async def wait_before_atomic_write(expected, **changes):
            entered.set()
            await release.wait()
            return await conditional_update(expected, **changes)

        self.db.update_token_routes_if_health_matches = wait_before_atomic_write
        pending = asyncio.create_task(self.rotation.prepare_token(await self.token()))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            await self.manager.update_token(self.token_id, at="new-at-before-atomic-write")
            release.set()
            prepared = await asyncio.wait_for(pending, 2)
            self.assertEqual(prepared.proxy_url, OLD)
            self.assertEqual(prepared.at, "new-at-before-atomic-write")
            self.assertEqual((await self.token()).proxy_url, OLD)
            self.assertEqual(self.route_writes, [])
            self.assertFalse(self.saved_state()["due"])
        finally:
            release.set()
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
