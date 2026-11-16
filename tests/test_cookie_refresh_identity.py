"""Offline recovery races using real SQLite health and renewal metadata."""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

from src.core.config import config
from src.core.database import Database
from src.core.models import Token
from src.services.token_manager import TokenManager


class CookieRefreshIdentityTests(unittest.IsolatedAsyncioTestCase):
    async def test_old_route_failure_cannot_postpone_recovery_on_replacement_route(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        db = Database(str(Path(directory.name) / "offline.db"))
        await db.init_db()
        previous_refresh = datetime.now(timezone.utc) - timedelta(hours=3)
        token_id = await db.add_token(Token(
            st="frontend-offline-session", at="flow-frontend-cookie",
            at_expires=datetime.now(timezone.utc) + timedelta(minutes=55),
            email="offline@example.test", google_cookies="OSID=old; SID=account",
            protocol_mode="protocol", auto_refresh_enabled=True,
            refresh_interval_minutes=120, last_st_refresh_at=previous_refresh,
            last_st_refresh_result="previous renewal result",
            proxy_url="http://old.example.test:80",
            captcha_proxy_url="http://old.example.test:80",
        ))
        flow = MagicMock()
        flow.get_request_fingerprint.return_value = None
        flow.st_to_at = AsyncMock(return_value={
            "access_token": "flow-frontend-cookie",
            "expires": (datetime.now(timezone.utc) + timedelta(minutes=55)).isoformat(),
            "credits": 123,
        })
        manager = TokenManager(db, flow)
        db.get_token_refresh_config = AsyncMock(return_value=SimpleNamespace(
            enabled=True, refresh_interval_minutes=120,
        ))
        old_started = asyncio.Event()
        finish_old = asyncio.Event()
        login_routes = []

        async def login(_cookies, *, proxy, email):
            login_routes.append(proxy)
            if len(login_routes) == 1:
                old_started.set()
                await finish_old.wait()
                raise TimeoutError("old route timed out")
            return {
                "success": True, "google_cookies": "OSID=new; SID=account",
                "email": email,
            }

        with patch.object(type(config), "captcha_method", new_callable=PropertyMock,
                          return_value="yescaptcha"), patch(
            "src.services.protocol_login.protocol_loginer.login", side_effect=login,
        ):
            original = await db.get_token(token_id)
            pending = asyncio.create_task(manager._refresh_protocol_token(
                original, datetime.now(timezone.utc),
            ))
            try:
                await asyncio.wait_for(old_started.wait(), timeout=3)
                # A scheduler rotation preserves the same credential values.
                await db.update_token(
                    token_id, proxy_url="http://new.example.test:80",
                    captcha_proxy_url="http://new.example.test:80",
                )
            finally:
                finish_old.set()
                await asyncio.wait_for(pending, timeout=3)

            after_old = await db.get_token(token_id)
            self.assertEqual(after_old.last_st_refresh_at, previous_refresh)
            self.assertEqual(after_old.last_st_refresh_result, "previous renewal result")
            self.assertEqual(after_old.google_cookies, original.google_cookies)
            self.assertTrue(after_old.is_active)

            # The obsolete failure must not reset the two-hour polling interval
            # for the fresh route; the very next cycle can recover its cookies.
            await manager.run_protocol_refresh_once()

        self.assertEqual(login_routes, [
            "http://old.example.test:80", "http://new.example.test:80",
        ])
        recovered = await db.get_token(token_id)
        self.assertEqual(recovered.google_cookies, "OSID=new; SID=account")
        self.assertEqual(recovered.last_st_refresh_result, "success")
        self.assertGreater(recovered.last_st_refresh_at, previous_refresh)


if __name__ == "__main__":
    unittest.main()
