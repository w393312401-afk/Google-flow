"""Offline end-to-end scheduling recovery after temporary transport failures."""

import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from src.core.database import Database
from src.core.models import Token
from src.services.exit_rotation import ExitRotationManager, _proxy_identity
from src.services.load_balancer import LoadBalancer
from src.services.token_manager import TokenManager


OLD = "http://old.example.test:8000"
NEW = "http://new.example.test:8001"
OTHER = "http://other.example.test:8002"


class GatewayUnavailable(Exception):
    status_code = 502


class AutomaticTransportRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.db = Database(db_path=str(self.root / "offline.db"))
        await self.db.init_db()
        self.now = 1000.0
        for module in ("token_manager", "exit_rotation", "load_balancer"):
            self.enterContext(patch(
                f"src.services.{module}.time", SimpleNamespace(monotonic=lambda: self.now),
            ))
        self.enterContext(patch("src.services.load_balancer.config", SimpleNamespace(
            captcha_method="browser", call_logic_mode="polling", flow_min_video_credits=0,
        )))
        self.token_id = await self.add_account(1)
        self.policy_path = self.root / "rotation.json"
        pool_path = self.root / "pool.json"
        pool_path.write_text(json.dumps({"proxies": {
            "old": {"host": "old.example.test", "port": 8000},
            "new": {"host": "new.example.test", "port": 8001},
            "other": {"host": "other.example.test", "port": 8002},
        }}))
        self.policy = {
            "enabled": True, "token_ids": [self.token_id], "threshold": 5,
            "pool_path": str(pool_path), "max_candidates": 3,
            "probe_timeout_seconds": 1,
        }
        self.write_policy()
        self.state_path = self.root / "state.json"
        self.manager = TokenManager(self.db, SimpleNamespace())
        self.bad_balance_routes = {OLD}
        self.bad_probe_routes = set()
        self.balance_calls, self.probe_calls = [], []

        async def credits(token, at):
            self.balance_calls.append((token.id, token.proxy_url, at))
            if token.proxy_url in self.bad_balance_routes:
                raise ConnectionError("temporary network connection failed")
            return {"credits": 123, "userPaygateTier": "PAYGATE_TIER_ONE"}

        async def probe(route):
            self.probe_calls.append(route)
            if route in self.bad_probe_routes:
                raise ConnectionError("temporary route unavailable")
            return {"ip": {OLD: "192.0.2.1", NEW: "192.0.2.2", OTHER: "192.0.2.3"}[route],
                    "flow_status": 200}

        self.manager._get_credits_for_token = AsyncMock(side_effect=credits)
        self.manager._st_to_at_for_token = AsyncMock(return_value={
            "access_token": "refreshed-offline-at",
            "expires": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        })
        self.rotation = ExitRotationManager(
            self.db, self.manager, policy_path=self.policy_path,
            state_path=self.state_path, probe=probe,
        )
        self.manager.exit_rotation = self.rotation
        self.balancer = LoadBalancer(self.manager)
        self.balancer.exit_rotation = self.rotation

    async def add_account(self, number):
        return await self.db.add_token(Token(
            email=f"offline-{number}@example.test", st=f"offline-session-{number}",
            at="offline-at", at_expires=datetime.now(timezone.utc) + timedelta(days=1),
            google_cookies=f"OSID=offline-{number}; SID=offline-{number}",
            proxy_url=OLD, captcha_proxy_url=OLD,
        ))

    def write_policy(self):
        self.policy_path.write_text(json.dumps(self.policy))

    async def select(self):
        return await asyncio.wait_for(self.balancer.select_token(for_image_generation=True), 3)

    def record(self, token_id=None):
        return json.loads(self.state_path.read_text())["accounts"][str(token_id or self.token_id)]

    async def test_pending_network_failure_waits_sixty_seconds_then_fails_over(self):
        self.assertIsNone(await self.select())
        self.assertTrue(self.record()["due"])
        self.now = 1059.99
        self.assertIsNone(await self.select())
        self.assertEqual(len(self.balance_calls), 1)
        self.assertEqual(self.probe_calls, [])
        self.now = 1060.0
        recovered = await self.select()
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.proxy_url, NEW)
        self.assertEqual([row[1] for row in self.balance_calls], [OLD, NEW])
        self.assertFalse(self.record()["due"])
        self.assertTrue(recovered.is_active)

    async def test_same_identity_can_revalidate_after_cooldown_without_rotation_policy(self):
        self.policy["enabled"] = False
        self.write_policy()
        self.assertIsNone(await self.select())
        self.bad_balance_routes.clear()
        self.now = 1059
        self.assertIsNone(await self.select())
        self.now = 1060
        recovered = await self.select()
        self.assertEqual(recovered.proxy_url, OLD)
        self.assertEqual(len(self.balance_calls), 2)
        self.assertTrue(recovered.is_active)
        self.assertIsNone(self.manager.get_last_validation_error(self.token_id))

    async def test_recovered_current_route_is_revalidated_when_no_replacement_is_healthy(self):
        self.bad_probe_routes.update((NEW, OTHER))
        self.assertIsNone(await self.select())
        self.bad_balance_routes.clear()
        results = []
        for now in (1060, 1066, 1097, 1218, 1519, 1820):
            self.now = now
            results.append(await self.select())
        self.assertTrue((await self.db.get_token(self.token_id)).is_active)
        self.assertIsNotNone(results[-1],
            "Current route recovered, but pending health_error prevented every real revalidation")
        self.assertEqual(results[-1].proxy_url, OLD)
        self.assertFalse(self.record()["due"])

    async def test_expired_at_can_resume_refresh_on_recovered_current_route_without_replacement(self):
        await self.db.update_token(self.token_id, at_expires=datetime.now(timezone.utc) - timedelta(seconds=1))
        self.bad_probe_routes.update((NEW, OTHER))
        self.manager._st_to_at_for_token.side_effect = ConnectionError("temporary network connection failed")
        self.assertIsNone(await self.select())
        self.assertEqual(self.manager._st_to_at_for_token.await_count, 1)
        self.manager._st_to_at_for_token.side_effect = None
        self.bad_balance_routes.clear()
        self.now = 1060
        recovered = await self.select()
        self.assertIsNotNone(recovered,
            "Expired AT refresh remained blocked after transport recovered on the original route")
        self.assertEqual(recovered.at, "refreshed-offline-at")
        self.assertTrue(recovered.is_active)

    async def test_unhealthy_candidates_become_eligible_after_five_second_probe_backoff(self):
        self.bad_probe_routes.update((OLD, NEW, OTHER))
        self.assertIsNone(await self.select())
        self.now = 1060
        self.assertIsNone(await self.select())
        counts = Counter(self.probe_calls)
        self.assertEqual(counts[NEW], 1)
        self.bad_probe_routes.remove(NEW)
        self.now = 1064.99
        self.assertIsNone(await self.select())
        self.assertEqual(Counter(self.probe_calls)[NEW], 1)
        self.now = 1065
        self.assertTrue(self.rotation._healthy(await self.rotation._probe_health(NEW, 1)))
        self.assertEqual(Counter(self.probe_calls)[NEW], 2)
        self.assertNotIn(_proxy_identity(NEW), self.rotation._health_backoff)
        # The current-route authenticated retry also failed at t=1060. Its
        # separate 60-second account cooldown still bounds real API retries.
        self.assertIsNone(await self.select())
        self.now = 1120
        recovered = await self.select()
        self.assertEqual(recovered.proxy_url, NEW)
        self.assertEqual(Counter(self.probe_calls)[NEW], 2)
        self.assertNotIn(_proxy_identity(NEW), self.rotation._health_backoff)

    async def test_healthy_homepage_and_cached_success_cannot_clear_persistent_rpc_502(self):
        self.bad_probe_routes.update((NEW, OTHER))
        self.manager._get_credits_for_token.side_effect = GatewayUnavailable("gateway unavailable")
        self.assertIsNone(await self.select())
        token = await self.db.get_token(self.token_id)
        self.manager._mark_at_valid(self.token_id, proxy_url=OLD, token=token)
        self.now = 1060
        self.assertIsNone(await self.select())
        self.assertEqual(self.manager._get_credits_for_token.await_count, 2)
        self.assertTrue(self.record()["due"])
        self.assertEqual(self.record()["error"], "health_error")
        self.assertTrue((await self.db.get_token(self.token_id)).is_active)
        self.now = 1061
        self.assertIsNone(await self.select())
        self.assertEqual(self.manager._get_credits_for_token.await_count, 2)

    async def test_threshold_cannot_be_waived_by_successful_current_route_validation(self):
        self.bad_probe_routes.update((NEW, OTHER))
        self.bad_balance_routes.clear()
        for index in range(5):
            request = f"threshold-{index}"
            await self.rotation.acquire(await self.db.get_token(self.token_id), request)
            await self.rotation.note_sent(self.token_id, request)
            await self.rotation.release(self.token_id, request)
        await self.rotation.mark_health_error(
            self.token_id, "AT_CHECK: network or proxy unavailable",
            failed_identity=TokenManager.health_identity(await self.db.get_token(self.token_id)),
        )
        self.assertIsNone(await self.select())
        self.manager._get_credits_for_token.assert_not_awaited()
        self.assertTrue(self.record()["due"])
        self.assertEqual(self.record()["count"], 5)
        self.assertEqual((await self.db.get_token(self.token_id)).proxy_url, OLD)

    async def test_late_success_for_replaced_identity_does_not_clear_due_or_admit_account(self):
        self.bad_probe_routes.update((NEW, OTHER))
        self.assertIsNone(await self.select())
        self.bad_balance_routes.clear()
        self.now = 1060
        actual_revalidate = self.manager.revalidate_token_under_admission

        async def replaced_after_validation(token):
            validated = await actual_revalidate(token)
            await self.db.update_token(self.token_id, at="unvalidated-concurrent-at")
            return validated

        self.manager.revalidate_token_under_admission = replaced_after_validation
        self.assertIsNone(await self.select())
        self.assertTrue(self.record()["due"])
        self.assertEqual((await self.db.get_token(self.token_id)).at, "unvalidated-concurrent-at")

    async def test_current_route_revalidation_reuses_exclusive_maintenance_lease(self):
        self.bad_probe_routes.update((NEW, OTHER))
        self.assertIsNone(await self.select())
        self.bad_balance_routes.clear()
        self.now = 1060
        with self.manager.account_admission.maintenance(self.token_id) as lease:
            recovered = await asyncio.wait_for(self.rotation.prepare_token_under_maintenance(
                await self.db.get_token(self.token_id), lease,
            ), 3)
            self.assertEqual(recovered.proxy_url, OLD)
            self.assertTrue(self.manager.account_admission.maintenance_active(self.token_id))
        self.assertFalse(self.record()["due"])
        self.assertEqual(len(self.balance_calls), 2)
        self.assertFalse(self.manager.account_admission.maintenance_active(self.token_id))
        self.assertFalse(self.record()["due"])

    async def test_probe_success_cache_expires_and_force_detects_then_recovers_failure(self):
        self.assertTrue(self.rotation._healthy(await self.rotation._probe_health(NEW, 1)))
        self.bad_probe_routes.add(NEW)
        self.now = 1059.99
        self.assertTrue(self.rotation._healthy(await self.rotation._probe_health(NEW, 1)))
        self.assertEqual(Counter(self.probe_calls)[NEW], 1)
        self.now = 1060
        self.assertFalse(self.rotation._healthy(await self.rotation._probe_health(NEW, 1)))
        self.assertEqual(Counter(self.probe_calls)[NEW], 2)
        self.bad_probe_routes.remove(NEW)
        self.now = 1064.99
        self.assertFalse(self.rotation._healthy(await self.rotation._probe_health(NEW, 1, force=True)))
        self.now = 1065
        self.assertTrue(self.rotation._healthy(await self.rotation._probe_health(NEW, 1, force=True)))
        self.assertEqual(Counter(self.probe_calls)[NEW], 3)
        self.assertNotIn(_proxy_identity(NEW), self.rotation._health_backoff)

    async def test_fourteen_temporary_transport_failures_keep_every_account_enabled(self):
        ids = [self.token_id]
        for number in range(2, 15):
            ids.append(await self.add_account(number))
        self.policy["token_ids"] = ids
        self.write_policy()
        self.assertIsNone(await self.select())
        self.assertEqual(len(self.balance_calls), 14)
        self.assertEqual(len(await self.db.get_active_tokens()), 14)
        self.assertTrue(all(self.record(token_id)["due"] for token_id in ids))
        self.now = 1059
        self.assertIsNone(await self.select())
        self.assertEqual(len(self.balance_calls), 14)
        self.assertEqual(len(await self.db.get_active_tokens()), 14)
        self.now = 1060
        self.assertIsNotNone(await self.select())
        self.assertEqual(len(await self.db.get_active_tokens()), 14)


if __name__ == "__main__":
    unittest.main()
