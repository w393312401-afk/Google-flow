"""Late validation failures must never schedule rotation for a replacement route."""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from src.core.database import Database
from src.core.models import Token
from src.services.exit_rotation import ExitRotationManager
from src.services.load_balancer import LoadBalancer
from src.services.token_manager import TokenManager


OLD = "http://old.example.test:8000"
NEW = "http://new.example.test:8001"
OTHER = "http://other.example.test:8002"


class GatewayUnavailable(Exception):
    status_code = 502


class RotationValidationRaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.db = Database(db_path=str(root / "offline.db"))
        await self.db.init_db()
        self.token_id = await self.db.add_token(Token(
            email="offline@example.test", st="offline-session", at="offline-at",
            at_expires=datetime.now(timezone.utc) + timedelta(days=1),
            proxy_url=OLD, captcha_proxy_url=OLD,
        ))
        pool_path = root / "pool.json"
        pool_path.write_text(json.dumps({"proxies": {
            "old": {"host": "old.example.test", "port": 8000},
            "new": {"host": "new.example.test", "port": 8001},
            "other": {"host": "other.example.test", "port": 8002},
        }}))
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps({
            "enabled": True, "token_ids": [self.token_id], "threshold": 5,
            "pool_path": str(pool_path), "max_candidates": 3,
            "probe_timeout_seconds": 1,
        }))
        self.state_path = root / "state.json"
        self.manager = TokenManager(self.db, SimpleNamespace())

        async def probe(route):
            return {"ip": {OLD: "192.0.2.1", NEW: "192.0.2.2", OTHER: "192.0.2.3"}[route],
                    "flow_status": 200}

        self.rotation = ExitRotationManager(
            self.db, self.manager, policy_path=policy_path,
            state_path=self.state_path, probe=probe,
        )
        self.manager.exit_rotation = self.rotation
        self.balancer = LoadBalancer(self.manager)
        self.balancer.exit_rotation = self.rotation
        self.enterContext(patch("src.services.load_balancer.config", SimpleNamespace(
            captcha_method="browser", call_logic_mode="polling",
        )))

    async def test_old_validation_failure_cannot_rotate_successful_replacement(self):
        entered, finish, rotated = asyncio.Event(), asyncio.Event(), asyncio.Event()
        route_writes, balance_routes = [], []
        original_update = self.db.update_token

        async def update(token_id, **changes):
            await original_update(token_id, **changes)
            if "proxy_url" in changes:
                route_writes.append(changes["proxy_url"])
            if changes.get("proxy_url") == NEW:
                rotated.set()

        self.db.update_token = update

        async def credits(token, _at):
            balance_routes.append(token.proxy_url)
            if token.proxy_url == OLD:
                entered.set()
                await finish.wait()
                raise GatewayUnavailable("old route returned a gateway error")
            return {"credits": 123, "userPaygateTier": "PAYGATE_TIER_ONE"}

        self.manager._get_credits_for_token = AsyncMock(side_effect=credits)
        token_id = self.token_id
        for index in range(4):
            request = f"completed-{index}"
            await self.rotation.acquire(await self.db.get_token(token_id), request)
            await self.rotation.note_sent(token_id, request)
            await self.rotation.release(token_id, request)
        await self.rotation.acquire(await self.db.get_token(token_id), "fifth-generation")
        first = asyncio.create_task(self.balancer.select_token(for_image_generation=True))
        second = None
        try:
            await asyncio.wait_for(entered.wait(), 2)
            await self.rotation.note_sent(token_id, "fifth-generation")
            await self.rotation.release(token_id, "fifth-generation")
            second = asyncio.create_task(self.balancer.select_token(for_image_generation=True))
            await asyncio.wait_for(rotated.wait(), 2)
            finish.set()
            first_result, second_result = await asyncio.wait_for(asyncio.gather(first, second), 2)
            self.assertIsNone(first_result)
            self.assertEqual(second_result.proxy_url, NEW)
            state = json.loads(self.state_path.read_text())["accounts"][str(token_id)]
            self.assertFalse(state["due"])
            self.assertIsNone(state["error"])
            third = await self.balancer.select_token(for_image_generation=True)
            self.assertEqual(third.proxy_url, NEW)
            self.assertEqual(route_writes, [NEW])
            self.assertEqual(balance_routes, [OLD, NEW])
        finally:
            finish.set()
            for task in (first, second):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(*(task for task in (first, second) if task is not None), return_exceptions=True)
            await self.rotation.release(token_id, "fifth-generation")
