"""Admin one-click refresh: active accounts only, sequential, isolated failures."""

import asyncio
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from src.api import admin


def account(token_id, *, active=True, expires=None):
    return SimpleNamespace(id=token_id, email=f'a{token_id}@example.test',
                           is_active=active, at_expires=expires)


class FakeManager:
    def __init__(self, accounts, outcomes=None):
        self.accounts = {a.id: a for a in accounts}
        self.outcomes = outcomes or {}
        self._last_at_refresh_error = {}
        self.order = []
        self.gate = None

    async def get_all_tokens(self):
        return list(self.accounts.values())

    async def get_token(self, token_id):
        return self.accounts.get(token_id)

    async def _refresh_at(self, token_id):
        self.order.append(token_id)
        if self.gate is not None:
            await self.gate.wait()
        outcome = self.outcomes.get(token_id, True)
        if isinstance(outcome, list):
            outcome = outcome.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if outcome == 'transient':
            self._last_at_refresh_error[token_id] = 'AT_REFRESH: network or proxy unavailable'
            return False
        if outcome is False:
            self._last_at_refresh_error[token_id] = 'AT_REFRESH: credentials rejected'
            self.accounts[token_id].is_active = False
        return outcome


class RefreshAllTests(unittest.IsolatedAsyncioTestCase):
    def use(self, manager):
        self.enterContext(patch.object(admin, 'token_manager', manager))
        self.enterContext(patch.object(admin, 'refresh_all_retry_delays', (0, 0)))
        self.addCleanup(setattr, admin, 'refresh_all_running', False)

    async def test_refreshes_only_active_accounts_in_order(self):
        expires = datetime(2026, 10, 6, tzinfo=timezone.utc)
        manager = FakeManager([account(1, expires=expires), account(2, active=False),
                               account(3, expires=expires)])
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 3])
        self.assertEqual((result['total'], result['succeeded'], result['failed']), (2, 2, 0))
        self.assertEqual(result['results'][0]['at_expires'], expires.isoformat())
        self.assertFalse(admin.refresh_all_running)

    async def test_failure_is_reported_and_does_not_stop_the_rest(self):
        manager = FakeManager([account(1), account(2), account(3)],
                              outcomes={1: RuntimeError('boom'), 2: False})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 2, 3])
        self.assertEqual((result['succeeded'], result['failed']), (1, 2))
        first, second, third = result['results']
        self.assertEqual(first['error'], 'boom')
        self.assertEqual(second['error'], 'AT_REFRESH: credentials rejected')
        self.assertTrue(second['disabled'])
        self.assertTrue(third['success'])

    async def test_transient_network_failure_is_retried_until_it_succeeds(self):
        manager = FakeManager([account(1), account(2)],
                              outcomes={1: ['transient', 'transient', True]})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 1, 1, 2])
        self.assertEqual((result['succeeded'], result['failed']), (2, 0))
        first = result['results'][0]
        self.assertEqual(first['attempts'], 3)
        self.assertNotIn('error', first)

    async def test_persistent_network_failure_stops_after_bounded_retries(self):
        manager = FakeManager([account(1), account(2)], outcomes={1: ['transient'] * 10})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1, 1, 1, 2])
        first = result['results'][0]
        self.assertEqual(first['attempts'], 3)
        self.assertEqual(first['error'], 'AT_REFRESH: network or proxy unavailable')
        self.assertFalse(first['disabled'])
        self.assertTrue(result['results'][1]['success'])

    async def test_credential_rejection_is_not_retried(self):
        manager = FakeManager([account(1)], outcomes={1: False})
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual(manager.order, [1])
        self.assertEqual(result['results'][0]['attempts'], 1)

    async def test_overlapping_request_is_rejected_and_flag_is_released(self):
        manager = FakeManager([account(1)])
        manager.gate = asyncio.Event()
        self.use(manager)

        running = asyncio.create_task(admin.refresh_all_tokens(token='admin'))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_all_tokens(token='admin')
        self.assertEqual(caught.exception.status_code, 409)

        manager.gate.set()
        result = await running
        self.assertEqual(result['succeeded'], 1)
        self.assertFalse(admin.refresh_all_running)

    async def test_no_active_accounts_is_a_successful_noop(self):
        manager = FakeManager([account(1, active=False)])
        self.use(manager)

        result = await admin.refresh_all_tokens(token='admin')

        self.assertEqual((result['total'], result['results']), (0, []))
        self.assertEqual(manager.order, [])


class RefreshSingleTests(unittest.IsolatedAsyncioTestCase):
    def use(self, manager):
        self.enterContext(patch.object(admin, 'token_manager', manager))
        self.enterContext(patch.object(admin, 'refresh_all_retry_delays', (0, 0)))

    async def test_success_returns_new_expiry(self):
        expires = datetime(2026, 10, 6, tzinfo=timezone.utc)
        self.use(FakeManager([account(1, expires=expires)]))

        result = await admin.refresh_at(1, token='admin')

        self.assertEqual(result['token'], {'id': 1, 'email': 'a1@example.test',
                                           'at_expires': expires.isoformat()})

    async def test_rejected_credentials_explain_the_real_cause(self):
        self.use(FakeManager([account(1)], outcomes={1: False}))

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(1, token='admin')

        self.assertEqual(caught.exception.status_code, 500)
        self.assertIn('登录态已失效', caught.exception.detail)
        self.assertIn('已被自动禁用', caught.exception.detail)
        self.assertNotIn('personal', caught.exception.detail)

    async def test_transient_failure_is_retried_then_reported_as_network_problem(self):
        manager = FakeManager([account(1), account(2)],
                              outcomes={1: ['transient', True], 2: ['transient'] * 10})
        self.use(manager)

        self.assertEqual((await admin.refresh_at(1, token='admin'))['success'], True)
        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(2, token='admin')

        self.assertEqual(manager.order, [1, 1, 2, 2, 2])
        self.assertIn('网络或代理暂时不可用', caught.exception.detail)

    async def test_unknown_account_is_404(self):
        self.use(FakeManager([]))

        with self.assertRaises(HTTPException) as caught:
            await admin.refresh_at(9, token='admin')

        self.assertEqual(caught.exception.status_code, 404)


if __name__ == '__main__':
    unittest.main()
