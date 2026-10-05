"""AdsPower environment serial shown in the account list."""

import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import aiosqlite
from fastapi import HTTPException
from pydantic import ValidationError

from src.api import admin
from src.core.database import Database
from src.core.models import Token
from src.services.flow_client import FlowClient
from src.services.token_manager import TokenManager


class AdsPowerSerialTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db_path = f'{self.temp_dir.name}/flow.db'
        self.db = Database(db_path=self.db_path)
        await self.db.init_db()
        proxy = SimpleNamespace(normalize_proxy_url=lambda value: value.strip(),
                                get_request_proxy_url=AsyncMock(return_value=''))
        self.manager = TokenManager(self.db, FlowClient(proxy_manager=proxy, db=self.db))
        self.enterContext(patch.object(admin, 'db', self.db))
        self.enterContext(patch.object(admin, 'token_manager', self.manager))

    async def add(self, email, **overrides):
        fields = dict(st=f'st-{email}', email=email, login_account=email, google_cookies='cookies')
        fields.update(overrides)
        return await self.db.add_token(Token(**fields))

    async def listed(self):
        return {row['email']: row['adspower_serial'] for row in await admin.get_tokens(token='admin')}

    async def test_serial_is_stored_and_listed(self):
        await self.add('a@example.test', adspower_serial=63)
        await self.add('b@example.test')

        self.assertEqual(await self.listed(), {'a@example.test': 63, 'b@example.test': None})

    async def test_update_sets_keeps_and_clears_the_serial(self):
        token_id = await self.add('a@example.test', adspower_serial=63)

        await self.manager.update_token(token_id, adspower_serial=70)
        self.assertEqual((await self.listed())['a@example.test'], 70)

        await self.manager.update_token(token_id, remark='note')
        self.assertEqual((await self.listed())['a@example.test'], 70)

        await self.manager.update_token(token_id, adspower_serial=0)
        self.assertIsNone((await self.listed())['a@example.test'])

    async def test_existing_database_gains_the_column_on_upgrade(self):
        async with aiosqlite.connect(self.db_path) as raw:
            await raw.execute('ALTER TABLE tokens DROP COLUMN adspower_serial')
            await raw.commit()

        await self.db.check_and_migrate_db()

        async with aiosqlite.connect(self.db_path) as raw:
            columns = {row[1] for row in await (await raw.execute('PRAGMA table_info(tokens)')).fetchall()}
        self.assertIn('adspower_serial', columns)

    def test_request_models_reject_negative_serials(self):
        with self.assertRaises(ValidationError):
            admin.UpdateTokenRequest(adspower_serial=-1)
        self.assertIsNone(admin.UpdateTokenRequest().adspower_serial)

    async def test_serial_endpoint_edits_only_the_serial_without_validating_cookies(self):
        token_id = await self.add('dead@example.test', adspower_serial=5, ban_reason='429_rate_limit')
        self.manager.flow_client.st_to_at = AsyncMock(side_effect=AssertionError('must not validate cookies'))
        before = (await self.db.get_token(token_id)).model_dump()

        result = await admin.set_adspower_serial(token_id, admin.AdsPowerSerialRequest(adspower_serial=9), token='admin')

        self.assertEqual(result, {'success': True, 'adspower_serial': 9})
        after = (await self.db.get_token(token_id)).model_dump()
        self.assertEqual(after.pop('adspower_serial'), 9)
        before.pop('adspower_serial')
        self.assertEqual(after, before)

    async def test_serial_endpoint_clears_with_zero_and_rejects_unknown_accounts(self):
        token_id = await self.add('a@example.test', adspower_serial=5)

        await admin.set_adspower_serial(token_id, admin.AdsPowerSerialRequest(adspower_serial=0), token='admin')
        self.assertIsNone((await self.listed())['a@example.test'])

        with self.assertRaises(HTTPException) as caught:
            await admin.set_adspower_serial(999, admin.AdsPowerSerialRequest(adspower_serial=1), token='admin')
        self.assertEqual(caught.exception.status_code, 404)
        with self.assertRaises(ValidationError):
            admin.AdsPowerSerialRequest(adspower_serial=-3)

    async def test_import_carries_the_serial_for_new_and_existing_accounts(self):
        calls = []
        known = [SimpleNamespace(id=n, email=f'old{n}@example.test', login_account=f'old{n}@example.test',
                                 is_active=True) for n in (7, 9)]

        async def add_token(**kwargs):
            calls.append(('add', kwargs.get('adspower_serial')))
            return SimpleNamespace(id=8, is_active=True)

        async def update_token(**kwargs):
            calls.append(('update', kwargs.get('adspower_serial')))

        fake = SimpleNamespace(
            get_all_tokens=AsyncMock(return_value=known),
            flow_client=SimpleNamespace(st_to_at=AsyncMock(return_value={'access_token': 'at', 'expires': None})),
            add_token=add_token, update_token=update_token,
            enable_token=AsyncMock(), disable_token=AsyncMock(),
        )
        items = [
            admin.ImportTokenItem(login_account='new@example.test', google_cookies='c1', adspower_serial=12),
            admin.ImportTokenItem(login_account='old7@example.test', google_cookies='c2', adspower_serial=3),
            admin.ImportTokenItem(login_account='old9@example.test', google_cookies='c3'),
        ]
        with patch.object(admin, 'token_manager', fake), patch.object(admin, 'concurrency_manager', None):
            result = await admin.import_tokens(admin.ImportTokensRequest(tokens=items), token='admin')

        self.assertEqual((result['added'], result['updated'], result['errors']), (1, 2, None))
        self.assertEqual(calls, [('add', 12), ('update', 3), ('update', None)])

    def test_import_still_rejects_unknown_keys(self):
        with self.assertRaises(ValidationError):
            admin.ImportTokenItem(login_account='a@example.test', google_cookies='c', adspower_serial_typo=1)


if __name__ == '__main__':
    unittest.main()
