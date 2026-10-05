"""Manual balance refresh reports real failures instead of a fake zero balance."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from src.api import admin
from src.core.database import Database
from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager


class RefreshCreditsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Database(db_path=f'{self.temp_dir.name}/flow.db')
        await self.db.init_db()
        proxy = SimpleNamespace(normalize_proxy_url=lambda value: value.strip(),
                                get_request_proxy_url=AsyncMock(return_value='http://global.invalid:1'))
        self.flow = FlowClient(proxy_manager=proxy, db=self.db)
        self.manager = TokenManager(self.db, self.flow)
        self.enterContext(patch.object(admin, 'token_manager', self.manager))
        self.enterContext(patch.object(admin, 'db', self.db))
        self.token_id = await self.add('a@example.test')

    async def add(self, email, **overrides):
        fields = dict(st=f'st-{email}', at='at', email=email, login_account=email,
                      google_cookies='cookies', credits=77, proxy_url='http://account.invalid:2',
                      at_expires=datetime.now(timezone.utc) + timedelta(hours=6))
        fields.update(overrides)
        return await self.db.add_token(Token(**fields))

    async def credits(self):
        return (await self.db.get_token(self.token_id)).credits

    async def test_success_stores_the_balance_through_the_account_proxy(self):
        seen = []

        async def balance(at, google_cookies=None, token_id=None):
            seen.append(self.flow.get_request_fingerprint().get('proxy_url'))
            return {'credits': 321, 'userPaygateTier': 'PAYGATE_TIER_ONE'}

        self.flow.get_credits = AsyncMock(side_effect=balance)

        result = await admin.refresh_credits(self.token_id, token='admin')

        self.assertEqual(result['credits'], 321)
        self.assertEqual(await self.credits(), 321)
        self.assertEqual(seen, ['http://account.invalid:2', 'http://account.invalid:2'])

    async def test_query_failure_is_an_error_and_keeps_the_stored_balance(self):
        self.flow.get_credits = AsyncMock(side_effect=Exception('curl: (56) CONNECT tunnel failed, response 404'))

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_credits(self.token_id, token='admin')

        self.assertEqual(caught.exception.status_code, 500)
        self.assertIn('网络或代理暂时不可用', caught.exception.detail)
        self.assertEqual(await self.credits(), 77)
        row = (await admin.get_tokens(token='admin'))[0]
        self.assertIn('network or proxy unavailable', row['last_health_reason'])

    async def test_disabled_account_is_reported_not_shown_as_zero(self):
        await self.db.update_token(self.token_id, is_active=False)

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_credits(self.token_id, token='admin')

        self.assertEqual(caught.exception.status_code, 500)
        self.assertIn('已禁用', caught.exception.detail)
        self.assertEqual(await self.credits(), 77)

    async def test_unknown_account_is_404(self):
        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_credits(999, token='admin')

        self.assertEqual(caught.exception.status_code, 404)

    async def test_failed_session_validation_is_reported_with_its_reason(self):
        await self.db.update_token(self.token_id, at_expires=datetime.now(timezone.utc) - timedelta(hours=1))
        self.flow.st_to_at = AsyncMock(side_effect=Exception('curl: (56) CONNECT tunnel failed, response 404'))

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_credits(self.token_id, token='admin')

        self.assertIn('网络或代理暂时不可用', caught.exception.detail)
        self.assertEqual(await self.credits(), 77)


if __name__ == '__main__':
    unittest.main()
