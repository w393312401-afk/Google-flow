"""Offline admin refresh integration with real rotation and file-lock admission."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from src.api import admin
from src.core.models import Token
from src.services.exit_rotation import ExitRotationManager
from src.services.token_manager import TokenManager


OLD = "http://old.example.test:8000"
NEW = "http://new.example.test:8001"
OTHER = "http://other.example.test:8002"


class GatewayUnavailable(Exception):
    status_code = 502


class MemoryDB:
    def __init__(self, path):
        self.db_path = str(path)
        self.token = Token(
            id=2, email="offline@example.test", st="offline-session", at="offline-at",
            at_expires=datetime.now(timezone.utc) + timedelta(days=1),
            proxy_url=OLD, captcha_proxy_url=OLD,
        )
        self.writes = []
        self.health = {}

    async def get_token(self, token_id):
        return self.token.model_copy(deep=True) if token_id == self.token.id else None

    async def update_token(self, token_id, **changes):
        assert token_id == self.token.id
        self.writes.append(dict(changes))
        self.token = self.token.model_copy(update=changes)

    async def commit_token_health_result(
        self, expected, *, reason, updates=None, preserve_health=False,
    ):
        if (expected.id != self.token.id
                or TokenManager.health_identity(expected) != TokenManager.health_identity(self.token)):
            return False
        if updates:
            await self.update_token(expected.id, **updates)
        if preserve_health:
            return True
        if reason:
            self.health[expected.id] = reason
        else:
            self.health.pop(expected.id, None)
        return True

    async def set_token_health(self, token_id, reason, *, expected=None):
        if expected is not None:
            assert expected.id == token_id
            return await self.commit_token_health_result(expected, reason=reason)
        self.health[token_id] = reason
        return True

    async def clear_token_health(self, token_id):
        self.health.pop(token_id, None)


class AdminRotationAdversarialTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        pool_path = self.root / "pool.json"
        pool_path.write_text(json.dumps({"proxies": {
            "old": {"proxy_type": "http", "host": "old.example.test", "port": 8000},
            "new": {"proxy_type": "http", "host": "new.example.test", "port": 8001},
            "other": {"proxy_type": "http", "host": "other.example.test", "port": 8002},
        }}))
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps({
            "enabled": True, "token_ids": [2], "threshold": 5,
            "pool_path": str(pool_path), "max_candidates": 3,
            "probe_timeout_seconds": 1,
        }))
        policy_path.chmod(0o600)
        self.state_path = self.root / "state.json"
        self.db = MemoryDB(self.root / "offline.db")
        self.manager = TokenManager(self.db, SimpleNamespace())
        self.probes = []
        self.balance_routes = []
        self.balance_during_maintenance = []
        self.always_bad_balance = False

        async def probe(route):
            self.probes.append(route)
            return {"ip": {OLD: "192.0.2.1", NEW: "192.0.2.2", OTHER: "192.0.2.3"}[route],
                    "flow_status": 200}

        self.probe = AsyncMock(side_effect=probe)
        self.rotation = ExitRotationManager(
            self.db, self.manager, policy_path=policy_path,
            state_path=self.state_path, probe=self.probe,
        )
        self.manager.exit_rotation = self.rotation
        self.manager._st_to_at_for_token = AsyncMock(return_value={
            "access_token": "fresh-offline-at",
            "expires": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        })

        async def credits(token, _at):
            self.balance_routes.append(token.proxy_url)
            self.balance_during_maintenance.append(
                self.manager.account_admission.maintenance_active(token.id)
            )
            if token.proxy_url == OLD or self.always_bad_balance:
                raise GatewayUnavailable("upstream gateway unavailable")
            return {"credits": 123, "userPaygateTier": "PAYGATE_TIER_ONE"}

        self.credits = credits
        self.manager._get_credits_for_token = AsyncMock(side_effect=credits)
        self.enterContext(patch.object(admin, "token_manager", self.manager))
        self.enterContext(patch.object(admin, "refresh_all_retry_delays", (0, 0)))

    def route_writes(self):
        return [write for write in self.db.writes if "proxy_url" in write]

    async def refresh(self):
        return await admin._refresh_token_for_batch(await self.db.get_token(2))

    async def test_homepage_200_does_not_clear_balance_502_and_retry_uses_new_route(self):
        # The real admin path already owns an exclusive maintenance lease when
        # entering rotation. Real flock admission catches accidental re-entry.
        result = await asyncio.wait_for(self.refresh(), timeout=3)

        self.assertTrue(result["success"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(self.balance_routes, [OLD, NEW])
        self.assertEqual(self.balance_during_maintenance, [False, False])
        self.assertEqual(self.route_writes(), [{"proxy_url": NEW, "captcha_proxy_url": NEW}])
        self.assertFalse(json.loads(self.state_path.read_text())["accounts"]["2"]["due"])
        self.assertNotIn(2, self.db.health)
        self.assertTrue(self.db.token.is_active)

    async def test_persistent_balance_failure_has_one_rotation_and_bounded_retries(self):
        self.always_bad_balance = True

        result = await asyncio.wait_for(self.refresh(), timeout=3)

        self.assertFalse(result["success"])
        self.assertEqual(result["attempts"], 3)
        self.assertEqual(self.balance_routes, [OLD, NEW, NEW])
        self.assertEqual(len(self.route_writes()), 1)
        self.assertFalse(result["disabled"])
        self.assertTrue(self.db.token.is_active)

    async def test_login_maintenance_blocks_admin_rotation_and_releases_cleanly(self):
        with self.manager.account_admission.maintenance(2):
            result = await asyncio.wait_for(self.refresh(), timeout=3)
            self.assertFalse(result["success"])
            self.assertEqual(result["attempts"], 1)
            self.assertEqual(self.route_writes(), [])
            self.assertTrue(self.manager.account_admission.maintenance_active(2))

        self.assertFalse(self.manager.account_admission.maintenance_active(2))
        recovered = await asyncio.wait_for(self.refresh(), timeout=3)
        self.assertTrue(recovered["success"])
        self.assertEqual(len(self.route_writes()), 1)

    async def test_delayed_shared_failure_does_not_rotate_new_route_again(self):
        """A stale waiter reaches repair after the first repair lease is gone."""
        both_started = asyncio.Event()
        new_balance_started = asyncio.Event()
        secondary_retry_started = asyncio.Event()
        finish_new_balance = asyncio.Event()
        caller_attempts = {}
        actual_refresh = self.manager._refresh_at

        async def controlled_credits(token, at):
            if token.proxy_url == OLD:
                await both_started.wait()
            else:
                new_balance_started.set()
                await finish_new_balance.wait()
            return await self.credits(token, at)

        async def delayed_refresh(token_id):
            name = asyncio.current_task().get_name()
            caller_attempts[name] = caller_attempts.get(name, 0) + 1
            if name == "delayed-admin" and caller_attempts[name] == 1:
                both_started.set()
            if name == "delayed-admin" and caller_attempts[name] == 2:
                secondary_retry_started.set()
            result = await actual_refresh(token_id)
            if name == "delayed-admin" and caller_attempts[name] == 1:
                await new_balance_started.wait()
            return result

        self.manager._get_credits_for_token.side_effect = controlled_credits
        self.manager._refresh_at = delayed_refresh
        first = asyncio.create_task(self.refresh(), name="first-admin")
        second = asyncio.create_task(self.refresh(), name="delayed-admin")
        try:
            await asyncio.wait_for(secondary_retry_started.wait(), timeout=3)
            self.assertEqual(self.route_writes(), [{"proxy_url": NEW, "captcha_proxy_url": NEW}])
        finally:
            finish_new_balance.set()
            results = await asyncio.wait_for(asyncio.gather(first, second), timeout=3)

        self.assertTrue(all(result["success"] for result in results))
        self.assertEqual([result["attempts"] for result in results], [2, 2])
        self.assertEqual(self.balance_routes, [OLD, NEW])
        self.assertEqual(self.balance_during_maintenance, [False, False])
        self.assertEqual(len(self.route_writes()), 1)

    async def test_late_admin_joins_old_refresh_without_rotating_current_route_again(self):
        """The late caller's snapshot is newer than the refresh it joins."""
        old_balance_started = asyncio.Event()
        finish_old_balance = asyncio.Event()
        new_balance_started = asyncio.Event()
        finish_new_balance = asyncio.Event()
        late_started = asyncio.Event()
        late_retry_started = asyncio.Event()
        caller_attempts = {}
        actual_refresh = self.manager._refresh_at

        async def controlled_credits(token, at):
            if token.proxy_url == OLD:
                old_balance_started.set()
                await finish_old_balance.wait()
            else:
                new_balance_started.set()
                await finish_new_balance.wait()
            return await self.credits(token, at)

        async def delayed_refresh(token_id):
            name = asyncio.current_task().get_name()
            caller_attempts[name] = caller_attempts.get(name, 0) + 1
            if name == "late-admin" and caller_attempts[name] == 1:
                late_started.set()
            if name == "late-admin" and caller_attempts[name] == 2:
                late_retry_started.set()
            result = await actual_refresh(token_id)
            if name == "late-admin" and caller_attempts[name] == 1:
                await new_balance_started.wait()
            return result

        self.manager._get_credits_for_token.side_effect = controlled_credits
        self.manager._refresh_at = delayed_refresh
        first = asyncio.create_task(self.refresh(), name="early-admin")
        second = None
        try:
            await asyncio.wait_for(old_balance_started.wait(), timeout=3)
            # The scheduler can apply an earlier pending rotation while the
            # manual refresh is still using its OLD account snapshot.
            await self.rotation.mark_health_error(2, "upstream unavailable (HTTP 502)")
            await self.rotation.prepare_token(await self.db.get_token(2))
            self.assertEqual(self.db.token.proxy_url, NEW)
            second = asyncio.create_task(self.refresh(), name="late-admin")
            await asyncio.wait_for(late_started.wait(), timeout=3)
            finish_old_balance.set()
            await asyncio.wait_for(late_retry_started.wait(), timeout=3)
            self.assertEqual(self.route_writes(), [{"proxy_url": NEW, "captcha_proxy_url": NEW}])
        finally:
            finish_old_balance.set()
            finish_new_balance.set()
            results = await asyncio.wait_for(
                asyncio.gather(*[task for task in (first, second) if task is not None]),
                timeout=3,
            )

        self.assertTrue(all(result["success"] for result in results))
        self.assertEqual([result["attempts"] for result in results], [2, 2])
        self.assertEqual(self.balance_routes, [OLD, NEW])
        self.assertEqual(self.db.token.proxy_url, NEW)
        self.assertEqual(len(self.route_writes()), 1)

    async def test_success_on_old_route_revalidates_current_route_before_returning(self):
        """A completed OLD validation cannot certify an unvalidated NEW route."""
        old_balance_started = asyncio.Event()
        finish_old_balance = asyncio.Event()

        async def controlled_credits(token, _at):
            self.balance_routes.append(token.proxy_url)
            if token.proxy_url == OLD:
                old_balance_started.set()
                await finish_old_balance.wait()
            return {"credits": 123, "userPaygateTier": "PAYGATE_TIER_ONE"}

        self.manager._get_credits_for_token.side_effect = controlled_credits
        pending = asyncio.create_task(self.refresh())
        try:
            await asyncio.wait_for(old_balance_started.wait(), timeout=3)
            await self.rotation.mark_health_error(2, "upstream unavailable (HTTP 502)")
            await self.rotation.prepare_token(await self.db.get_token(2))
            self.assertEqual(self.db.token.proxy_url, NEW)
        finally:
            finish_old_balance.set()
            result = await asyncio.wait_for(pending, timeout=3)

        self.assertTrue(result["success"])
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(self.balance_routes, [OLD, NEW])
        self.assertEqual(self.route_writes(), [{"proxy_url": NEW, "captcha_proxy_url": NEW}])
        self.assertTrue(self.manager._has_recent_at_validation(
            2, proxy_url=NEW, token=await self.db.get_token(2),
        ))


if __name__ == "__main__":
    unittest.main()
