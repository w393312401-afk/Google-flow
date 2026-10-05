"""Account health reason survives restarts and is cleared by fresh credentials."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from src.api import admin
from src.core.database import Database
from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager

NETWORK = 'AT_REFRESH: network or proxy unavailable'


class HealthPersistenceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Database(db_path=f'{self.temp_dir.name}/flow.db')
        await self.db.init_db()
        proxy = SimpleNamespace(normalize_proxy_url=lambda value: value.strip(),
                                get_request_proxy_url=AsyncMock(return_value=''))
        self.flow = FlowClient(proxy_manager=proxy, db=self.db)
        self.manager = TokenManager(self.db, self.flow)
        self.enterContext(patch.object(admin, 'db', self.db))
        self.token_id = await self.db.add_token(Token(
            st='st-a', at='old-at', email='a@example.test', login_account='a@example.test',
            google_cookies='cookies',
            at_expires=datetime.now(timezone.utc) + timedelta(hours=6)))

    def succeed(self):
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self.flow.st_to_at = AsyncMock(return_value={'access_token': 'new-at', 'user': {}, 'expires': expires})
        self.flow.get_credits = AsyncMock(return_value={'credits': 5})

    def fail_network(self):
        self.flow.st_to_at = AsyncMock(side_effect=Exception('curl: (56) CONNECT tunnel failed, response 404'))

    async def reason(self):
        row = [r for r in await self.db.get_all_tokens_with_stats() if r['id'] == self.token_id][0]
        return row['last_health_reason']

    async def test_failure_reason_is_stored_listed_and_cleared_on_success(self):
        self.fail_network()
        self.assertFalse(await self.manager._refresh_at(self.token_id))

        row = (await admin.get_tokens(token='admin'))[0]
        self.assertEqual(row['last_health_reason'], NETWORK)
        self.assertTrue(row['last_health_at'])

        self.succeed()
        self.assertTrue(await self.manager._refresh_at(self.token_id))
        row = (await admin.get_tokens(token='admin'))[0]
        self.assertEqual((row['last_health_reason'], row['last_health_at']), ('', None))

    async def test_a_failed_check_never_rewrites_the_account_row(self):
        before = (await self.db.get_token(self.token_id)).model_dump()

        await self.manager._record_at_failure(self.token_id, NETWORK, error=Exception('timed out'))

        self.assertEqual((await self.db.get_token(self.token_id)).model_dump(), before)
        self.assertEqual(await self.reason(), NETWORK)

    async def test_credits_check_success_clears_the_reason(self):
        await self.manager._record_at_failure(self.token_id, NETWORK, error=Exception('timed out'))
        self.assertEqual(await self.reason(), NETWORK)

        self.manager._validation_retry_after.clear()  # skip the 60 s failure cooldown
        self.flow.get_credits = AsyncMock(return_value={'credits': 9})
        token = await self.manager.ensure_valid_token(await self.db.get_token(self.token_id))

        self.assertEqual(token.credits, 9)
        self.assertEqual(await self.reason(), '')

    async def test_new_credentials_clear_a_stale_failure(self):
        await self.manager._record_at_failure(
            self.token_id, 'AT_REFRESH: credentials rejected (UNAUTHENTICATED)',
            error=Exception('UNAUTHENTICATED'))
        self.assertIn('credentials rejected', await self.reason())

        await self.manager.update_token(self.token_id, remark='only a note')
        self.assertIn('credentials rejected', await self.reason())

        await self.manager.update_token(self.token_id, at='fresh-at')
        self.assertEqual(await self.reason(), '')

    async def test_deleting_an_account_removes_its_health_row(self):
        await self.manager._record_at_failure(self.token_id, NETWORK, error=Exception('timed out'))

        await self.db.delete_token(self.token_id)

        self.assertEqual(await self.db.get_all_tokens_with_stats(), [])
        async with self.db._connect() as raw:
            self.assertEqual(await (await raw.execute('SELECT COUNT(*) FROM token_health')).fetchone(), (0,))

    async def test_storage_failure_never_breaks_the_refresh_flow(self):
        with patch.object(self.db, 'set_token_health', AsyncMock(side_effect=RuntimeError('db locked'))):
            await self.manager._record_at_failure(self.token_id, NETWORK, error=Exception('timed out'))

        self.assertEqual(self.manager.get_last_validation_error(self.token_id), NETWORK)


if __name__ == '__main__':
    unittest.main()
