"""Offline account creation/sync: scoped proxies and explicit activation policy."""

import asyncio
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


class AccountCookieSyncProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db = Database(db_path=f'{self.temp_dir.name}/flow.db')
        await self.db.init_db()
        self.proxy = SimpleNamespace(
            normalize_proxy_url=lambda value: value.strip(),
            get_request_proxy_url=AsyncMock(return_value='http://global.invalid:8000'),
        )
        self.flow = FlowClient(proxy_manager=self.proxy, db=self.db)
        self.manager = TokenManager(self.db, self.flow)
        self.manager._get_project_pool_size = lambda: 2
        self.outer = {'proxy_url': 'http://outer.invalid:8000', 'user_agent': 'preserved'}
        self.flow._set_request_fingerprint(self.outer)
        self.calls = []
        self.counter = 0

        async def record(kind, cookies):
            before = self.flow.get_request_fingerprint()
            await asyncio.sleep(0)
            self.assertEqual(self.flow.get_request_fingerprint(), before)
            self.calls.append((kind, cookies, before))

        async def validate(st, google_cookies=None, **kwargs):
            await record('validate', google_cookies)
            return {'access_token': 'test-access', 'user': {},
                    'expires': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}

        async def credits(at, google_cookies=None, **kwargs):
            await record('credits', google_cookies)
            return {'credits': 100}

        async def project(st, name, google_cookies=None, **kwargs):
            await record('project', google_cookies)
            self.counter += 1
            return f'project-{self.counter}'

        self.flow.st_to_at = AsyncMock(side_effect=validate)
        self.flow.get_credits = AsyncMock(side_effect=credits)
        self.flow.create_project = AsyncMock(side_effect=project)
        self.enterContext(patch.object(admin, 'token_manager', self.manager))
        self.enterContext(patch.object(admin, 'concurrency_manager', None))

    async def add(self, **overrides):
        options = dict(st='', login_account='sync@example.test', google_cookies='test-cookies',
                       proxy_url='http://account.invalid:8000', is_active=False,
                       image_enabled=False, video_enabled=False)
        options.update(overrides)
        return await self.manager.add_token(**options)

    async def existing(self, **overrides):
        options = dict(st='test-st', email='existing@example.test', google_cookies='old-cookies',
                       proxy_url='http://existing.invalid:8000', captcha_proxy_url='http://browser.invalid:8000',
                       current_project_id='existing-project', is_active=False,
                       ban_reason='manual-test', banned_at=datetime.now(timezone.utc))
        options.update(overrides)
        token = Token(**options)
        token.id = await self.db.add_token(token)
        # Ban metadata is set by account state transitions, not the INSERT path.
        await self.db.update_token(token.id, ban_reason=token.ban_reason, banned_at=token.banned_at)
        return await self.db.get_token(token.id)

    async def test_add_scopes_validation_credits_and_all_projects_and_can_start_disabled(self):
        token = await self.add()
        self.assertEqual([kind for kind, _, _ in self.calls], ['validate', 'credits', 'project', 'project'])
        self.assertTrue(all(fp['proxy_url'] == token.proxy_url for _, _, fp in self.calls))
        self.assertEqual(self.flow.get_request_fingerprint(), self.outer)
        saved = await self.db.get_token(token.id)
        self.assertFalse(saved.is_active or saved.image_enabled or saved.video_enabled)
        self.assertEqual(len(await self.db.get_projects_by_token(token.id)), 2)

    async def test_add_api_forwards_initial_disabled_state(self):
        result = await admin.add_token(admin.AddTokenRequest(
            google_cookies='test-cookies', login_account='api@example.test',
            proxy_url='http://account.invalid:8000', is_active=False,
            image_enabled=False, video_enabled=False,
        ), token='admin')
        self.assertTrue(result['success'])
        self.assertFalse((await self.db.get_token(result['token']['id'])).is_active)

    async def test_parallel_adds_do_not_leak_proxy_between_accounts(self):
        await asyncio.gather(*(
            self.add(login_account=f'{key}@example.test', google_cookies=f'cookies-{key}',
                     proxy_url=f'http://{key}.invalid:8000') for key in ('first', 'second')
        ))
        for _, cookies, fingerprint in self.calls:
            key = cookies.split('-')[-1]
            self.assertEqual(fingerprint['proxy_url'], f'http://{key}.invalid:8000')
        self.assertEqual(self.flow.get_request_fingerprint(), self.outer)

    async def test_add_failure_and_cancellation_restore_previous_fingerprint(self):
        for failure in (RuntimeError('validation failed'), asyncio.CancelledError()):
            with self.subTest(error_type=type(failure).__name__):
                self.flow.st_to_at.side_effect = failure
                expected = asyncio.CancelledError if isinstance(failure, asyncio.CancelledError) else ValueError
                with self.assertRaises(expected):
                    await self.add()
                self.assertEqual(self.flow.get_request_fingerprint(), self.outer)
        self.flow.st_to_at.side_effect = None
        self.flow.st_to_at.return_value = {'access_token': 'test', 'user': {}}
        self.flow.create_project.side_effect = RuntimeError('project failed')
        with self.assertRaises(ValueError):
            await self.add()
        self.assertEqual(self.flow.get_request_fingerprint(), self.outer)

    async def test_blank_account_proxy_uses_global_instead_of_inherited_account_override(self):
        await self.add(proxy_url='')
        self.assertTrue(all('proxy_url' not in fp for _, _, fp in self.calls))
        self.assertEqual(self.flow.get_request_fingerprint(), self.outer)

    async def test_cookie_put_uses_existing_proxy_and_preserves_activation_and_binding(self):
        token = await self.existing()
        result = await admin.update_token(token.id, admin.UpdateTokenRequest(
            google_cookies='new-cookies', auto_enable_on_update=False,
        ), token='admin')
        self.assertTrue(result['success'])
        self.assertEqual(self.calls[0][2]['proxy_url'], token.proxy_url)
        self.assertEqual(self.flow.get_request_fingerprint(), self.outer)
        saved = await self.db.get_token(token.id)
        self.assertEqual(saved.google_cookies, 'new-cookies')
        for field in ('is_active', 'ban_reason', 'banned_at', 'proxy_url', 'captcha_proxy_url',
                      'current_project_id', 'email', 'image_enabled', 'video_enabled'):
            self.assertEqual(getattr(saved, field), getattr(token, field), field)

    async def test_credentials_only_put_renews_deadline_without_replacing_session_or_settings(self):
        token = await self.existing(at='old-access',
                                    at_expires=datetime.now(timezone.utc) - timedelta(minutes=1),
                                    auto_refresh_enabled=False)
        before = token.model_dump()
        result = await admin.update_token(token.id, admin.UpdateTokenRequest(
            auto_enable_on_update=False,
        ), token='admin')
        self.assertTrue(result['success'])
        self.assertEqual(self.calls[0][0:2], ('validate', token.google_cookies))
        self.assertEqual(self.calls[0][2]['proxy_url'], token.proxy_url)
        self.assertEqual(self.flow.get_request_fingerprint(), self.outer)
        saved = (await self.db.get_token(token.id)).model_dump()
        self.assertGreater(saved['at_expires'].replace(tzinfo=timezone.utc), datetime.now(timezone.utc))
        self.assertEqual(saved['at'], 'test-access')
        for field in before:
            if field not in ('at', 'at_expires'):
                self.assertEqual(saved[field], before[field], field)

    async def test_cookie_put_explicit_new_proxy_is_used_for_validation_before_save(self):
        token = await self.existing()
        await admin.update_token(token.id, admin.UpdateTokenRequest(
            google_cookies='new-cookies', proxy_url='http://replacement.invalid:8000',
            auto_enable_on_update=False,
        ), token='admin')
        self.assertEqual(self.calls[0][2]['proxy_url'], 'http://replacement.invalid:8000')
        saved = await self.db.get_token(token.id)
        self.assertEqual(saved.proxy_url, 'http://replacement.invalid:8000')
        self.assertEqual(saved.captcha_proxy_url, token.captcha_proxy_url)
        self.assertEqual(self.flow.get_request_fingerprint(), self.outer)

    async def test_cookie_only_or_enable_flags_put_does_not_reset_inflight_counters(self):
        token = await self.existing()
        concurrency = SimpleNamespace(reset_token=AsyncMock())
        with patch.object(admin, 'concurrency_manager', concurrency):
            for fields in ({}, {'image_enabled': False, 'video_enabled': False}):
                await admin.update_token(token.id, admin.UpdateTokenRequest(
                    google_cookies='new-cookies', auto_enable_on_update=False, **fields,
                ), token='admin')
        concurrency.reset_token.assert_not_awaited()
        saved = await self.db.get_token(token.id)
        self.assertFalse(saved.image_enabled or saved.video_enabled)

    async def test_explicit_concurrency_put_resets_to_updated_limits(self):
        token = await self.existing(image_concurrency=2, video_concurrency=3)
        concurrency = SimpleNamespace(reset_token=AsyncMock())
        with patch.object(admin, 'concurrency_manager', concurrency):
            for fields in ({'image_concurrency': 0}, {'video_concurrency': 1}):
                with self.subTest(fields=fields):
                    concurrency.reset_token.reset_mock()
                    await admin.update_token(token.id, admin.UpdateTokenRequest(
                        google_cookies='new-cookies', auto_enable_on_update=False, **fields,
                    ), token='admin')
                    saved = await self.db.get_token(token.id)
                    concurrency.reset_token.assert_awaited_once_with(
                        token.id, image_concurrency=saved.image_concurrency,
                        video_concurrency=saved.video_concurrency,
                    )

    async def test_failed_put_does_not_change_cookie_activation_or_proxy(self):
        token = await self.existing()
        before = (await self.db.get_token(token.id)).model_dump()
        self.flow.st_to_at.side_effect = RuntimeError('validation failed')
        with self.assertRaises(HTTPException):
            await admin.update_token(token.id, admin.UpdateTokenRequest(
                google_cookies='bad-cookies', proxy_url='http://replacement.invalid:8000',
                auto_enable_on_update=False,
            ), token='admin')
        self.assertEqual((await self.db.get_token(token.id)).model_dump(), before)
        self.assertEqual(self.flow.get_request_fingerprint(), self.outer)

    async def test_opt_out_preserves_rate_limit_reason_and_active_state(self):
        for active in (False, True):
            token = await self.existing(is_active=active, email=f'active-{active}@example.test',
                                        st=f'active-{active}', ban_reason='429_rate_limit',
                                        at_expires=datetime.now(timezone.utc) + timedelta(hours=1))
            await self.manager.update_token(token.id, at='new-access', auto_enable_on_update=False)
            saved = await self.db.get_token(token.id)
            self.assertEqual(saved.is_active, active)
            self.assertEqual(saved.ban_reason, '429_rate_limit')

    async def test_legacy_update_keeps_automatic_enable_default(self):
        token = await self.existing()
        await self.manager.update_token(token.id, at='new-access')
        self.assertTrue((await self.db.get_token(token.id)).is_active)


if __name__ == '__main__':
    unittest.main()
