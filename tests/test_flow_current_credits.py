"""Offline current Flow credits validation; the RPC transport is always mocked."""
import unittest
from unittest.mock import AsyncMock

from src.services.flow_current import CurrentFlowClientMixin


class FlowCurrentCreditsTests(unittest.IsolatedAsyncioTestCase):
    def client(self, payload):
        client = CurrentFlowClientMixin()
        client._current_rpc = AsyncMock(return_value=payload)
        return client

    async def test_real_zero_and_finite_numeric_balances_remain_valid(self):
        for payload, expected in (([0], 0), ([42], 42), ([12.0], 12),
                                  ([None, True, False, 0], 0),
                                  (['metadata', 12.5], 12), ([10 ** 400], 10 ** 400)):
            with self.subTest(payload=payload):
                result = await self.client(payload).get_credits()
                self.assertEqual(result['credits'], expected)
                self.assertEqual(result['userPaygateTier'],
                                 'PAYGATE_TIER_ONE' if expected > 0 else 'PAYGATE_TIER_NOT_PAID')

    async def test_missing_boolean_string_nested_nonfinite_or_negative_balance_fails_safely(self):
        invalid = (None, {}, {'credits': 0}, [], [None], [True], [False], ['0'],
                   [['synthetic-private-value']], [float('nan')], [float('inf')],
                   [float('-inf')], [-0.5], [-1], [-0.5, 42],
                   [True, None, 'synthetic-private-value'])
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(RuntimeError) as caught:
                    await self.client(payload).get_credits()
                self.assertEqual(str(caught.exception), 'Flow credits RPC response invalid')
                self.assertNotIn('synthetic-private-value', str(caught.exception))

    async def test_request_protocol_and_cookie_account_arguments_are_unchanged(self):
        client = self.client([890])
        result = await client.get_credits(google_cookies='synthetic-cookie', token_id=2)
        self.assertEqual(result['credits'], 890)
        client._current_rpc.assert_awaited_once_with(
            rpc_id='nzlxg', argument=[], google_cookies='synthetic-cookie', token_id=2,
        )

    async def test_local_credential_refresh_requires_real_credits_but_accepts_zero(self):
        with self.assertRaisesRegex(RuntimeError, '^Flow credits RPC response invalid$'):
            await self.client([]).st_to_at(token_id=2)
        result = await self.client([0]).st_to_at(token_id=2)
        self.assertEqual(result['credits'], 0)
        self.assertTrue(result['expires'])


if __name__ == '__main__':
    unittest.main()
