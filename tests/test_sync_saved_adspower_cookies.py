"""Saved-cookie opt-in tests; all AdsPower/CDP calls are mocked."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch


_spec = importlib.util.spec_from_file_location(
    'sync_saved_cookies', Path(__file__).resolve().parents[1] / 'local/sync_adspower_cookies.py')
sync = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sync)


def config(**fields):
    return sync.validate_config(dict(profile_id='fixed-profile', expected_email='fixed@example.test',
        adspower_base='http://127.0.0.1:50325', flow_base='http://127.0.0.1:38000', **fields))


def cookie(**fields):
    value = dict(name='SID', value='synthetic-value', domain='.google.com', path='/', secure=True,
                 httpOnly=True, sameSite='Lax', expires=-1)
    value.update(fields)
    return value


def listing():
    return {'code': 0, 'data': {'list': [{'user_id': 'fixed-profile',
        'user_proxy_config': {'proxy_type': 'direct'}}]}}


def active(status='Active', **fields):
    return {'code': 0, 'data': dict(status=status, **fields)}


class SavedCookieTests(unittest.IsolatedAsyncioTestCase):
    def gateway(self, **options):
        gateway = sync.Gateway(config(**options), None, {})
        gateway._profile_request = AsyncMock()
        return gateway

    def test_saved_source_requires_strict_opt_in(self):
        self.assertIs(config()['allow_saved_cookies'], False)
        self.assertIs(config(allow_saved_cookies=True)['allow_saved_cookies'], True)
        for value in (None, 0, 1, 'true', 'false', [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(sync.SyncError, 'invalid_cookie_source_option'):
                config(allow_saved_cookies=value)

    async def test_inactive_default_still_stops_before_inventory_or_cookie_query(self):
        gateway = self.gateway()
        gateway._profile_request.return_value = active('Inactive')
        with self.assertRaisesRegex(sync.SyncError, 'profile_inactive'):
            await gateway.profile()
        gateway._profile_request.assert_awaited_once_with('/api/v1/browser/active', params={'user_id': 'fixed-profile'})

    async def test_inactive_opt_in_has_stable_source_identity(self):
        gateway = self.gateway(allow_saved_cookies=True)
        gateway._profile_request.side_effect = [active('Inactive'), listing()] * 2
        first, second = await gateway.profile(), await gateway.profile()
        self.assertEqual(first, second)
        self.assertEqual(first, {'ws': 'saved:fixed-profile', 'source': 'saved', 'proxy': ''})
        self.assertEqual([call.args[0] for call in gateway._profile_request.await_args_list],
                         ['/api/v1/browser/active', '/api/v1/user/list'] * 2)

    async def test_active_always_uses_live_cdp_even_when_saved_allowed(self):
        gateway = self.gateway(allow_saved_cookies=True)
        ws = 'ws://127.0.0.1:4444/devtools/browser/test'
        gateway._profile_request.side_effect = [active(ws={'puppeteer': ws}), listing()]
        profile = await gateway.profile()
        self.assertEqual(profile, {'ws': ws, 'source': 'cdp', 'proxy': ''})
        context = SimpleNamespace(cookies=AsyncMock(return_value=[cookie()]))
        browser = SimpleNamespace(contexts=[context], close=AsyncMock())
        chromium = SimpleNamespace(connect_over_cdp=AsyncMock(return_value=browser))
        manager = MagicMock()
        manager.__aenter__ = AsyncMock(return_value=SimpleNamespace(chromium=chromium))
        manager.__aexit__ = AsyncMock(return_value=None)
        with patch('playwright.async_api.async_playwright', return_value=manager):
            self.assertEqual(await gateway.cookies(profile), [cookie()])
            chromium.connect_over_cdp.assert_awaited_once_with(ws, timeout=15000)
            context.cookies.assert_awaited_once_with(sync.COOKIE_URLS)
            browser.close.assert_not_awaited()
            chromium.connect_over_cdp.side_effect = RuntimeError('CDP unavailable')
            with self.assertRaises(RuntimeError):
                await gateway.cookies(profile)
        # CDP failure never falls back to stale saved cookies.
        self.assertEqual(gateway._profile_request.await_count, 2)

    async def test_invalid_active_state_or_websocket_cannot_fall_back_to_saved(self):
        for response in ({'code': -1}, {'code': False}, {'code': 0, 'data': []}, active('Unknown'),
                         active(), active(ws={'puppeteer': 'saved:fixed-profile'})):
            with self.subTest(response=response):
                gateway = self.gateway(allow_saved_cookies=True)
                gateway._profile_request.return_value = response
                with self.assertRaises(sync.SyncError):
                    await gateway.profile()
                self.assertEqual(gateway._profile_request.await_count, 1)

    async def test_saved_cookie_endpoint_parses_filters_and_never_opens_browser(self):
        gateway = self.gateway(allow_saved_cookies=True)
        raw = [cookie(sameSite='no_restriction'), cookie(name='other', domain='mail.google.com')]
        gateway._profile_request.return_value = {'code': 0, 'data': {'cookies': json.dumps(raw)}}
        with patch('playwright.async_api.async_playwright') as browser:
            result = await gateway.cookies({'source': 'saved', 'ws': 'saved:fixed-profile'})
            browser.assert_not_called()
        self.assertEqual(result, [cookie(sameSite='None')])
        gateway._profile_request.assert_awaited_once_with('/api/v2/browser-profile/cookies',
                                                         params={'profile_id': 'fixed-profile'})

    async def test_saved_marker_is_bound_and_never_used_as_cdp_url(self):
        for allowed, profile in ((False, {'source': 'saved', 'ws': 'saved:fixed-profile'}),
                                 (True, {'source': 'saved', 'ws': 'saved:other'}),
                                 (True, {'source': 'cdp', 'ws': 'saved:fixed-profile'}),
                                 (True, {'source': 'unknown', 'ws': 'saved:fixed-profile'})):
            with self.subTest(allowed=allowed, profile=profile):
                gateway = self.gateway(allow_saved_cookies=allowed)
                with patch('playwright.async_api.async_playwright') as browser:
                    with self.assertRaises(sync.SyncError):
                        await gateway.cookies(profile)
                    browser.assert_not_called()
                gateway._profile_request.assert_not_awaited()

    async def test_saved_api_errors_fail_closed(self):
        failures = ({'code': -1}, {'code': False}, {'code': 0, 'data': []},
                    {'code': 0, 'data': {'cookies': []}},
                    {'code': 0, 'data': {'cookies': 'not json'}},
                    {'code': 0, 'data': {'cookies': '{}'}})
        for failure in failures:
            with self.subTest(response=failure):
                gateway = self.gateway(allow_saved_cookies=True)
                gateway._profile_request.return_value = failure
                with self.assertRaises(sync.SyncError):
                    await gateway.cookies({'source': 'saved', 'ws': 'saved:fixed-profile'})
                self.assertEqual(gateway._profile_request.await_count, 1)
        gateway._profile_request.side_effect = sync.SyncError('local_transport_failed', 'network')
        with self.assertRaisesRegex(sync.SyncError, 'local_transport_failed'):
            await gateway.cookies({'source': 'saved', 'ws': 'saved:fixed-profile'})

    def test_domain_path_secure_and_expiry_filter_matches_only_target_urls(self):
        keep = [cookie(), cookie(domain='flow.google.com'), cookie(domain='.www.google.com', secure=False),
                cookie(domain='google.com', hostOnly=False)]
        omit = [cookie(domain='mail.google.com'), cookie(domain='.accounts.google.com'),
                cookie(domain='evilgoogle.com'), cookie(domain='.google.com.evil.test'),
                cookie(domain='.com'), cookie(domain='google.com'), cookie(domain='.google.com', hostOnly=True),
                cookie(path='/accounts'), cookie(expires=1), cookie(domain='.flow.google.com', path='/project')]
        self.assertEqual(sync.filter_source_cookies(keep + omit), keep)
        with patch.object(sync, 'COOKIE_URLS', ['http://flow.google.com/']):
            self.assertEqual(sync.filter_source_cookies([cookie(), cookie(secure=False)]), [cookie(secure=False)])

    def test_structure_is_checked_without_widening_or_defaulting_scope(self):
        invalid = [None, {}, 'cookie', [None], [cookie(domain=None)], [cookie(domain='')],
                   [cookie(path='')], [cookie(secure='true')], [cookie(hostOnly='false')],
                   [cookie(expires=float('nan'))], [cookie(expires=True)],
                   [cookie(value=123)], [cookie(sameSite='invalid')]]
        for cookies in invalid:
            with self.subTest(shape=type(cookies).__name__), self.assertRaises(sync.SyncError):
                sync.filter_source_cookies(cookies, saved=True)

    def test_filtered_hash_is_stable_and_tracks_real_scope_metadata_changes(self):
        initial = sync.filter_source_cookies([cookie(), cookie(domain='accounts.google.com')], saved=True)
        changed_other = sync.filter_source_cookies([cookie(), cookie(domain='accounts.google.com', value='other')], saved=True)
        self.assertEqual(sync.auth_hash(initial), sync.auth_hash(changed_other))
        self.assertNotEqual(sync.auth_hash(initial), sync.auth_hash([cookie(expires=4000000000)]))
        no_auth = sync.filter_source_cookies([cookie(domain='accounts.google.com')], saved=True)
        with self.assertRaises(sync.SyncError):
            sync.auth_hash(no_auth)

    async def test_profile_read_rate_limit_waits_only_for_remaining_interval(self):
        gateway = sync.Gateway(config(), None, {})
        gateway.request = AsyncMock(return_value={})
        with patch.object(sync, 'time', SimpleNamespace(monotonic=MagicMock(side_effect=[10, 10.2, 11, 13, 13]))), \
                patch.object(sync.asyncio, 'sleep', new=AsyncMock()) as sleep:
            for path in ('/active', '/list', '/cookies'):
                await gateway._profile_request(path, params={})
        sleep.assert_awaited_once()
        self.assertAlmostEqual(sleep.await_args.args[0], .8)
        self.assertEqual(gateway.request.await_count, 3)


if __name__ == '__main__':
    unittest.main()
