"""Missing-project recovery never replays an accepted or uncertain generation."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from src.core.database import Database
from src.core.models import Project, Task, Token
from src.services.captcha_errors import BrowserCaptchaError
from src.services.flow_client import FlowClient
from src.services.generation_handler import GenerationHandler, MODEL_CONFIG
from src.services.submission_ledger import SubmissionLedger
from src.services.token_manager import TokenManager


IMAGE_MODEL = next(name for name, cfg in MODEL_CONFIG.items()
                   if cfg["type"] == "image" and not cfg.get("upsample"))
VIDEO_MODEL = "omni-1.1-flash-frames-10s-portrait-360p"


def missing_project(pending=False):
    failure = BrowserCaptchaError("editor_readiness", "project_not_found")
    failure.submission_pending = pending
    return failure


class ProjectRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db = Database(str(Path(directory.name) / "flow.db"))
        await self.db.init_db()
        self.token_id = await self.db.add_token(Token(
            st="synthetic-session", email="fixture@example.test", credits=500,
            user_paygate_tier="PAYGATE_TIER_ONE", current_project_id="missing-project",
            current_project_name="original name",
        ))
        self.other_token = await self.db.add_token(Token(st="other", email="other@example.test"))
        await self.db.add_project(Project(
            project_id="missing-project", token_id=self.token_id, project_name="original name",
        ))
        self.flow = FlowClient(None, db=self.db)
        self.flow.create_project = AsyncMock(return_value="replacement-project")
        self.flow.delete_project = AsyncMock()
        self.flow.prefill_remote_browser_pool = AsyncMock()
        self.manager = TokenManager(self.db, self.flow)
        self.manager._get_project_pool_size = Mock(return_value=1)
        self.recover_missing_project = self.manager.recover_missing_project

    async def test_recovery_keeps_project_history_and_accepted_receipt_and_task(self):
        ledger = SubmissionLedger(self.db)
        await ledger.reserve("historical-submission", "original-hash")
        await ledger.accepted("historical-submission", self.token_id, "missing-project", [{"name": "historical-task"}])
        await self.db.create_task(Task(
            task_id="historical-task", token_id=self.token_id, model="video", prompt="fixture", status="processing",
        ))
        receipt_before = await ledger.get("historical-submission")
        task_before = await self.db.get_task("historical-task")
        replacement = await self.manager.recover_missing_project(self.token_id, "missing-project")
        self.assertEqual(replacement, "replacement-project")
        original = await self.db.get_project_by_id("missing-project")
        self.assertFalse(original.is_active)
        self.assertEqual(original.project_name, "original name")
        self.assertEqual((await self.db.get_token(self.token_id)).current_project_id, replacement)
        self.assertEqual(await ledger.get("historical-submission"), receipt_before)
        self.assertEqual(await self.db.get_task("historical-task"), task_before)
        self.flow.delete_project.assert_not_awaited()
        self.flow.create_project.assert_awaited_once()

    async def test_foreign_or_unknown_project_cannot_change_pool_or_current_project(self):
        for token_id, project_id in (
            (self.other_token, "missing-project"), (self.token_id, "unknown-project"),
        ):
            with self.subTest(token_id=token_id, project_id=project_id):
                self.assertFalse(await self.db.deactivate_project_for_token(token_id, project_id))
                with self.assertRaisesRegex(ValueError, "does not belong"):
                    await self.manager.recover_missing_project(token_id, project_id)
        self.assertTrue((await self.db.get_project_by_id("missing-project")).is_active)
        self.assertEqual((await self.db.get_token(self.token_id)).current_project_id, "missing-project")
        self.flow.create_project.assert_not_awaited()

    async def test_concurrent_recovery_and_selection_share_account_lock(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def create(*args, **kwargs):
            entered.set()
            await release.wait()
            return "replacement-project"

        self.flow.create_project.side_effect = create
        first = asyncio.create_task(self.manager.recover_missing_project(self.token_id, "missing-project"))
        await entered.wait()
        repeated = asyncio.create_task(self.manager.recover_missing_project(self.token_id, "missing-project"))
        selection = asyncio.create_task(self.manager.ensure_project_exists(self.token_id))
        # Queue both behind the exact lock held across deactivation and creation.
        await asyncio.sleep(0)
        self.assertFalse(repeated.done())
        self.assertFalse(selection.done())
        release.set()
        self.assertEqual(await asyncio.gather(first, repeated, selection), ["replacement-project"] * 3)
        self.flow.create_project.assert_awaited_once()
        projects = await self.db.get_projects_by_token(self.token_id)
        self.assertEqual({p.project_id for p in projects if p.is_active}, {"replacement-project"})

    async def test_failed_replacement_leaves_missing_project_inactive_and_pointer_clear(self):
        self.flow.create_project.side_effect = RuntimeError("synthetic unavailable")
        with self.assertRaisesRegex(ValueError, "Failed to prepare project pool"):
            await self.manager.recover_missing_project(self.token_id, "missing-project")
        self.assertFalse((await self.db.get_project_by_id("missing-project")).is_active)
        self.assertIsNone((await self.db.get_token(self.token_id)).current_project_id)
        self.assertIsNone((await self.db.get_token(self.token_id)).current_project_name)
        self.flow.delete_project.assert_not_awaited()

    async def test_recovery_does_not_block_another_accounts_project_selection(self):
        await self.db.add_project(Project(
            project_id="other-project", token_id=self.other_token, project_name="other",
        ))
        entered, release = asyncio.Event(), asyncio.Event()

        async def create(*args, **kwargs):
            entered.set()
            await release.wait()
            return "replacement-project"

        self.flow.create_project.side_effect = create
        recovery = asyncio.create_task(self.manager.recover_missing_project(self.token_id, "missing-project"))
        await entered.wait()
        try:
            selected = await asyncio.wait_for(self.manager.ensure_project_exists(self.other_token), timeout=2)
            self.assertEqual(selected, "other-project")
        finally:
            release.set()
            await recovery

    def make_handler(self, outcomes, *, state=None):
        handler = GenerationHandler.__new__(GenerationHandler)
        handler.db = self.db
        handler.flow_client = self.flow
        handler.token_manager = self.manager
        self.manager.ensure_valid_token = AsyncMock(side_effect=lambda token: token)
        self.manager.record_error = AsyncMock()
        self.manager.record_usage = AsyncMock()
        self.manager.record_success = AsyncMock()
        self.manager.recover_missing_project = AsyncMock(wraps=self.recover_missing_project)
        handler.load_balancer = SimpleNamespace(
            select_token=AsyncMock(),
            release_pending=AsyncMock(), record_generation_failure=AsyncMock(return_value=False),
            record_generation_success=Mock(),
        )
        async def select(**kwargs):
            return await self.db.get_token(self.token_id)
        handler.load_balancer.select_token.side_effect = select
        handler._update_request_log_progress = AsyncMock()
        handler._log_request = AsyncMock()
        self.attempts = []
        scripted = list(outcomes)

        async def pipeline(token, project_id, *args, generation_result, **kwargs):
            self.attempts.append((token.id, project_id))
            if state:
                generation_result.update(state)
            outcome = scripted.pop(0) if scripted else None
            if outcome is not None:
                raise outcome
            generation_result["success"] = True
            yield "confirmed-result"

        handler._handle_image_generation = pipeline
        handler._handle_video_generation = pipeline
        return handler

    async def collect(self, handler, model=VIDEO_MODEL, **kwargs):
        return [chunk async for chunk in handler.handle_generation(model, "synthetic prompt", **kwargs)]

    async def test_unsubmitted_missing_project_retries_same_account_once_and_succeeds(self):
        for model in (IMAGE_MODEL, VIDEO_MODEL):
            with self.subTest(model=model):
                # Restore only this isolated fixture between image and video cases.
                async with self.db._connect(write=True) as connection:
                    await connection.execute("UPDATE projects SET is_active=1 WHERE project_id='missing-project'")
                    await connection.execute("DELETE FROM projects WHERE project_id='replacement-project'")
                    await connection.commit()
                handler = self.make_handler([missing_project(), None])
                self.assertEqual(await self.collect(handler, model), ["confirmed-result"])
                self.assertEqual(self.attempts, [(self.token_id, "missing-project"), (self.token_id, "replacement-project")])
                self.manager.recover_missing_project.assert_awaited_once_with(self.token_id, "missing-project")
                handler.load_balancer.select_token.assert_awaited_once()
                handler.load_balancer.record_generation_failure.assert_not_awaited()
                self.manager.record_error.assert_not_awaited()
                performance = handler._log_request.await_args.args[3]["performance"]
                self.assertEqual(performance["project_recovery"]["status"], "succeeded")

    async def test_stream_announces_replacement_once_and_has_one_final_success(self):
        handler = self.make_handler([missing_project(), None])
        chunks = await self.collect(handler, stream=True)
        self.assertEqual("".join(chunks).count("更换项目后重试一次"), 1)
        self.assertEqual(chunks.count("confirmed-result"), 1)
        self.assertEqual([call.args[4] for call in handler._log_request.await_args_list if call.args], [200])

    async def test_second_missing_project_failure_is_returned_without_third_attempt(self):
        handler = self.make_handler([missing_project(), missing_project(), None])
        responses = await self.collect(handler)
        self.assertEqual(len(self.attempts), 2)
        self.manager.recover_missing_project.assert_awaited_once()
        self.assertEqual(json.loads(responses[-1])["error"]["reason"], "project_not_found")
        self.assertEqual(handler._log_request.await_args.args[3]["performance"]["project_recovery"]["status"], "retry_failed")
        self.assertTrue((await self.db.get_project_by_id("replacement-project")).is_active)

    async def test_project_recovery_budget_is_shared_with_cross_account_retry(self):
        await self.db.update_token(self.other_token, user_paygate_tier="PAYGATE_TIER_ONE", credits=500)
        await self.db.add_project(Project(
            project_id="other-project", token_id=self.other_token, project_name="other",
        ))
        other_failure = BrowserCaptchaError("editor_readiness", "editor_missing")
        other_failure.submission_pending = False
        handler = self.make_handler([missing_project(), other_failure, missing_project(), None])
        accounts = iter((self.token_id, self.other_token))
        async def select(**kwargs):
            return await self.db.get_token(next(accounts))
        handler.load_balancer.select_token.side_effect = select
        handler.load_balancer.record_generation_failure.return_value = True
        responses = await self.collect(handler)
        self.assertEqual(self.attempts, [
            (self.token_id, "missing-project"), (self.token_id, "replacement-project"),
            (self.other_token, "other-project"),
        ])
        self.manager.recover_missing_project.assert_awaited_once_with(self.token_id, "missing-project")
        self.flow.create_project.assert_awaited_once()
        self.assertEqual(json.loads(responses[-1])["error"]["reason"], "project_not_found")

    async def test_unknown_or_pending_submission_never_repairs_or_retries(self):
        for pending in (None, True):
            with self.subTest(pending=pending):
                handler = self.make_handler([missing_project(pending)])
                responses = await self.collect(handler)
                self.assertEqual(len(self.attempts), 1)
                self.assertEqual(json.loads(responses[-1])["error"]["code"], "generation_failed")
                self.manager.recover_missing_project.assert_not_awaited()
                self.assertTrue((await self.db.get_project_by_id("missing-project")).is_active)
        self.flow.create_project.assert_not_awaited()

    async def test_other_failure_and_existing_acceptance_markers_never_repair(self):
        cases = [
            (BrowserCaptchaError("editor_readiness", "editor_missing"), {}),
            (missing_project(), {"submitted_video": {"operations": [{"name": "accepted"}]}}),
            (missing_project(), {"submission_pending": True}),
            (missing_project(), {"upstream_accepted": True}),
            (missing_project(), {"usage_recorded": True}),
        ]
        cases[0][0].submission_pending = False
        for failure, state in cases:
            with self.subTest(reason=failure.reason, state=state):
                handler = self.make_handler([failure], state=state)
                await self.collect(handler)
                self.assertEqual(len(self.attempts), 1)
                self.manager.recover_missing_project.assert_not_awaited()
        self.flow.create_project.assert_not_awaited()

    async def test_accepted_client_receipt_blocks_repair_even_with_false_pending_flag(self):
        ledger = SubmissionLedger(self.db)
        await ledger.reserve("accepted-submission", "original-hash")
        await ledger.accepted("accepted-submission", self.token_id, "missing-project", [{"name": "accepted-task"}])
        receipt_before = await ledger.get("accepted-submission")
        handler = self.make_handler([missing_project()])
        await self.collect(handler, client_submission_id="accepted-submission")
        self.assertEqual(len(self.attempts), 1)
        self.manager.recover_missing_project.assert_not_awaited()
        self.assertTrue((await self.db.get_project_by_id("missing-project")).is_active)
        receipt_after = await ledger.get("accepted-submission")
        for field in ("state", "account_id", "operation_id", "project_id", "operations", "video_url", "error"):
            self.assertEqual(receipt_after[field], receipt_before[field])
        self.flow.create_project.assert_not_awaited()

    async def test_repair_failure_preserves_original_non_submission_error(self):
        handler = self.make_handler([missing_project()])
        self.flow.create_project.side_effect = RuntimeError("synthetic unavailable")
        responses = await self.collect(handler)
        self.assertEqual(len(self.attempts), 1)
        error = json.loads(responses[-1])["error"]
        self.assertEqual((error["reason"], error["submission_pending"]), ("project_not_found", False))
        self.assertEqual(handler._log_request.await_args.args[3]["performance"]["project_recovery"]["status"], "failed")
