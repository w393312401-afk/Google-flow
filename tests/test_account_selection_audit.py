import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from src.core.database import Database
from src.core.models import Token
from src.services.load_balancer import LoadBalancer


class AccountSelectionAuditTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Database(str(Path(directory.name) / "flow.db"))
        await self.db.init_db()
        self.manager = SimpleNamespace(db=self.db, get_active_tokens=AsyncMock(return_value=[]))
        self.balancer = LoadBalancer(self.manager)

    async def test_empty_pool_records_one_pool_failure(self):
        self.assertIsNone(await self.balancer.select_token(for_image_generation=True))
        logs = await self.db.get_account_operation_logs()
        self.assertEqual(logs["total"], 1)
        event = logs["items"][0]
        self.assertIsNone(event["token_id"])
        self.assertEqual(event["operation"], "account_selection")
        self.assertEqual(event["reason"], "account_selection_failed")
        self.assertEqual(event["source"], "generation")
        self.assertEqual(event["details"], {"token_count": 0})

    async def test_capability_filter_records_one_failure_without_disabling_account(self):
        token_id = await self.db.add_token(Token(st="unused-test", email="pool@example.test", image_enabled=False))
        token = await self.db.get_token(token_id)
        self.manager.get_active_tokens.return_value = [token]
        self.assertIsNone(await self.balancer.select_token(for_image_generation=True))
        logs = await self.db.get_account_operation_logs()
        self.assertEqual(logs["total"], 1)
        self.assertEqual(logs["items"][0]["details"], {"token_count": 1})
        self.assertTrue((await self.db.get_token(token_id)).is_active)


if __name__ == "__main__":
    unittest.main()
