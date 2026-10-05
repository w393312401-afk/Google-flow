"""Background page creation regressions, without browser imports or startup."""

import ast
import asyncio
import types
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from unittest.mock import AsyncMock, Mock, patch

from src.services.captcha_errors import BrowserCaptchaError


SOURCE = Path(__file__).parents[1] / "src/services/browser_captcha.py"
tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
namespace = dict(globals())
namespace.update(
    config=types.SimpleNamespace(browser_launch_background=True),
    debug_logger=types.SimpleNamespace(log_info=Mock(), log_warning=Mock(), log_error=Mock()),
)
# Importing this production module can install Playwright. Load only the class.
exec(compile(ast.Module(
    body=[node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "TokenBrowser"],
    type_ignores=[],
), str(SOURCE), "exec"), namespace)
TokenBrowser = namespace["TokenBrowser"]


class FakePageEvent:
    """The expect_page protocol; page delivery can fail or await cancellation."""

    def __init__(self, page, events, *, error=None, delivery_gate=None):
        self.page = page
        self.events = events
        self.error = error
        self.delivery_gate = delivery_gate
        self.delivery_started = asyncio.Event()

    async def __aenter__(self):
        self.events.append("expect_page")
        return self

    async def __aexit__(self, error_type, error, traceback):
        if error_type is None and self.error is not None:
            raise self.error
        return False

    @property
    def value(self):
        async def deliver():
            self.delivery_started.set()
            if self.delivery_gate is not None:
                await self.delivery_gate.wait()
            return self.page
        return deliver()


class FakeBrowserContext(types.SimpleNamespace):
    @property
    def pages(self):
        # Match Playwright's list snapshot rather than exposing its backing list.
        return list(self._pages)


class BackgroundPageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.browser = TokenBrowser.__new__(TokenBrowser)
        self.browser.token_id = 0

    def make_context(self, *, has_anchor=False, context_ids=None, event_error=None,
                     delivery_gate=None, window_state=None):
        events = []
        page = types.SimpleNamespace(close=AsyncMock(), is_closed=Mock(return_value=False))
        anchor = types.SimpleNamespace(close=AsyncMock(), is_closed=Mock(return_value=False))
        context_ids = ["isolated-context"] if context_ids is None else context_ids
        window_state = window_state or ("minimized" if has_anchor else "normal")

        async def close_owned_page():
            context._pages = [item for item in context._pages if item is not page]
            page.is_closed.return_value = True
        page.close.side_effect = close_owned_page

        async def browser_send(method, params=None):
            events.append(method)
            if method == "Target.getBrowserContexts":
                return {"browserContextIds": context_ids}
            if method == "Target.createTarget":
                context._pages.append(page)
                return {"targetId": "owned-target"}
            if method == "Target.closeTarget":
                await close_owned_page()
                return {"success": True}
            if method == "Browser.getWindowForTarget":
                return {"windowId": 42, "bounds": {"windowState": window_state}}
            if method == "Browser.setWindowBounds":
                return {}
            raise AssertionError(f"Unexpected browser CDP method: {method}")

        async def anchor_send(method, params=None):
            if method == "Target.getTargetInfo":
                events.append(method)
                return {"targetInfo": {
                    "targetId": "anchor-target", "browserContextId": "isolated-context",
                }}
            return await browser_send(method, params)

        browser_session = types.SimpleNamespace(send=AsyncMock(side_effect=browser_send), detach=AsyncMock())
        anchor_session = types.SimpleNamespace(send=AsyncMock(side_effect=anchor_send), detach=AsyncMock())
        page_event = FakePageEvent(page, events, error=event_error, delivery_gate=delivery_gate)
        browser = types.SimpleNamespace(new_browser_cdp_session=AsyncMock(return_value=browser_session))
        context = FakeBrowserContext(
            browser=browser, _pages=[anchor] if has_anchor else [],
            new_cdp_session=AsyncMock(return_value=anchor_session),
            new_page=AsyncMock(return_value=page), expect_page=Mock(return_value=page_event),
        )
        return types.SimpleNamespace(
            context=context, page=page, anchor=anchor, event=page_event, events=events,
            browser_session=browser_session, anchor_session=anchor_session,
            session=anchor_session if has_anchor else browser_session,
        )

    def assert_background_target(self, fixture):
        create = next(call for call in fixture.session.send.await_args_list
                      if call.args[0] == "Target.createTarget")
        self.assertEqual(create.args[1], {
            "url": "about:blank", "browserContextId": "isolated-context", "background": True,
        })
        fixture.context.expect_page.assert_called_once_with(timeout=10000)
        self.assertLess(fixture.events.index("expect_page"), fixture.events.index("Target.createTarget"))
        fixture.context.new_page.assert_not_awaited()
        fixture.session.detach.assert_awaited_once()

    async def test_first_page_is_created_in_unique_context_without_window_activation(self):
        fixture = self.make_context()

        page = await self.browser._new_page(fixture.context)

        self.assertIs(page, fixture.page)
        self.assert_background_target(fixture)
        fixture.browser_session.send.assert_any_await("Target.getBrowserContexts")
        fixture.context.new_cdp_session.assert_not_awaited()
        fixture.page.close.assert_not_awaited()
        fixture.session.send.assert_any_await("Browser.getWindowForTarget", {"targetId": "owned-target"})
        fixture.session.send.assert_any_await("Browser.setWindowBounds", {
            "windowId": 42, "bounds": {"windowState": "minimized"},
        })

    async def test_existing_anchor_selects_its_context_even_when_other_contexts_exist(self):
        fixture = self.make_context(has_anchor=True, context_ids=["isolated-context", "another-context"])

        page = await self.browser._new_page(fixture.context)

        self.assertIs(page, fixture.page)
        self.assert_background_target(fixture)
        fixture.context.new_cdp_session.assert_awaited_once_with(fixture.anchor)
        fixture.anchor_session.send.assert_any_await("Target.getTargetInfo")
        fixture.anchor_session.detach.assert_awaited_once()
        fixture.context.browser.new_browser_cdp_session.assert_not_awaited()
        self.assertNotIn("Target.getBrowserContexts", fixture.events)
        fixture.session.send.assert_any_await("Browser.getWindowForTarget", {"targetId": "owned-target"})
        self.assertNotIn("Browser.setWindowBounds", fixture.events)
        fixture.anchor.close.assert_not_awaited()

    async def test_new_page_minimizes_window_restored_by_chromium_with_an_existing_anchor(self):
        fixture = self.make_context(has_anchor=True, window_state="normal")

        page = await self.browser._new_page(fixture.context)

        self.assertIs(page, fixture.page)
        self.assert_background_target(fixture)
        fixture.session.send.assert_any_await("Browser.setWindowBounds", {
            "windowId": 42, "bounds": {"windowState": "minimized"},
        })
        fixture.anchor.close.assert_not_awaited()

    async def test_already_minimized_first_window_does_not_repeat_window_state_change(self):
        fixture = self.make_context(window_state="minimized")

        page = await self.browser._new_page(fixture.context)

        self.assertIs(page, fixture.page)
        self.assert_background_target(fixture)
        fixture.session.send.assert_any_await("Browser.getWindowForTarget", {"targetId": "owned-target"})
        self.assertNotIn("Browser.setWindowBounds", fixture.events)

    async def test_missing_setting_defaults_to_background_creation(self):
        fixture = self.make_context()
        with patch.dict(namespace, {"config": types.SimpleNamespace()}):
            page = await self.browser._new_page(fixture.context)
        self.assertIs(page, fixture.page)
        self.assert_background_target(fixture)

    async def test_foreground_setting_uses_normal_context_page_creation(self):
        page = object()
        # No CDP or browser fields: the foreground path must not inspect them.
        context = types.SimpleNamespace(new_page=AsyncMock(return_value=page))
        with patch.dict(namespace, {"config": types.SimpleNamespace(browser_launch_background=False)}):
            actual = await self.browser._new_page(context)
        self.assertIs(actual, page)
        context.new_page.assert_awaited_once_with()

    async def test_missing_or_ambiguous_context_id_never_creates_a_foreground_page(self):
        for context_ids in ([], ["first-context", "second-context"]):
            with self.subTest(context_ids=context_ids):
                fixture = self.make_context(context_ids=context_ids)
                with self.assertRaises(Exception):
                    await self.browser._new_page(fixture.context)
                fixture.context.new_page.assert_not_awaited()
                self.assertNotIn("Target.createTarget", fixture.events)
                self.assertNotIn("Target.closeTarget", fixture.events)
                fixture.browser_session.detach.assert_awaited_once()

    async def test_anchor_without_context_id_never_guesses_another_context(self):
        fixture = self.make_context(has_anchor=True)
        fixture.session.send.side_effect = None
        fixture.session.send.return_value = {"targetInfo": {"targetId": "anchor-target"}}
        with self.assertRaises(Exception):
            await self.browser._new_page(fixture.context)
        fixture.session.send.assert_awaited_once_with("Target.getTargetInfo")
        fixture.context.new_page.assert_not_awaited()
        fixture.context.browser.new_browser_cdp_session.assert_not_awaited()
        fixture.session.detach.assert_awaited_once()

    async def test_window_minimize_failure_keeps_successful_background_page(self):
        fixture = self.make_context()
        original_send = fixture.session.send.side_effect

        async def unsupported_window_bounds(method, params=None):
            if method == "Browser.setWindowBounds":
                raise RuntimeError("synthetic unsupported window state")
            return await original_send(method, params)

        fixture.session.send.side_effect = unsupported_window_bounds
        page = await self.browser._new_page(fixture.context)

        self.assertIs(page, fixture.page)
        self.assert_background_target(fixture)
        self.assertNotIn("Target.closeTarget", fixture.events)
        fixture.page.close.assert_not_awaited()

    async def test_create_target_error_detaches_session_without_foreground_fallback(self):
        fixture = self.make_context()
        original_send = fixture.session.send.side_effect

        async def fail_create(method, params=None):
            if method == "Target.createTarget":
                raise RuntimeError("synthetic CDP failure")
            return await original_send(method, params)

        fixture.session.send.side_effect = fail_create
        with self.assertRaises(Exception):
            await self.browser._new_page(fixture.context)
        fixture.context.new_page.assert_not_awaited()
        self.assertNotIn("Target.closeTarget", fixture.events)
        fixture.session.detach.assert_awaited_once()

    async def test_page_event_failure_closes_only_owned_target(self):
        fixture = self.make_context(has_anchor=True, event_error=TimeoutError("synthetic page event timeout"))
        with self.assertRaises(Exception):
            await self.browser._new_page(fixture.context)

        self.assert_background_target(fixture)
        fixture.session.send.assert_any_await("Target.closeTarget", {"targetId": "owned-target"})
        closes = [call for call in fixture.session.send.await_args_list
                  if call.args[0] == "Target.closeTarget"]
        self.assertEqual(len(closes), 1)
        fixture.anchor.close.assert_not_awaited()
        fixture.anchor_session.detach.assert_awaited_once()

    async def test_cancellation_after_creation_closes_only_owned_target(self):
        fixture = self.make_context(has_anchor=True, delivery_gate=asyncio.Event())
        task = asyncio.create_task(self.browser._new_page(fixture.context))
        await asyncio.wait_for(fixture.event.delivery_started.wait(), timeout=1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assert_background_target(fixture)
        fixture.session.send.assert_any_await("Target.closeTarget", {"targetId": "owned-target"})
        closes = [call for call in fixture.session.send.await_args_list
                  if call.args[0] == "Target.closeTarget"]
        self.assertEqual(len(closes), 1)
        fixture.anchor.close.assert_not_awaited()
        fixture.anchor_session.detach.assert_awaited_once()

    async def test_cancellation_before_create_target_response_closes_only_new_context_page(self):
        fixture = self.make_context(has_anchor=True)
        original_send = fixture.session.send.side_effect
        creation_started = asyncio.Event()
        release_response = asyncio.Event()

        async def delay_created_target_response(method, params=None):
            result = await original_send(method, params)
            if method == "Target.createTarget":
                creation_started.set()
                await release_response.wait()
            return result

        fixture.session.send.side_effect = delay_created_target_response
        task = asyncio.create_task(self.browser._new_page(fixture.context))
        await asyncio.wait_for(creation_started.wait(), timeout=1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assert_background_target(fixture)
        fixture.page.close.assert_awaited_once_with()
        self.assertEqual(fixture.context.pages, [fixture.anchor])
        fixture.anchor.close.assert_not_awaited()
        self.assertNotIn("Target.closeTarget", fixture.events)

    async def test_cancellation_during_detach_closes_page_before_it_can_be_returned(self):
        fixture = self.make_context(has_anchor=True)
        detach_started = asyncio.Event()
        release_detach = asyncio.Event()

        async def delay_detach():
            detach_started.set()
            await release_detach.wait()

        fixture.session.detach.side_effect = delay_detach
        task = asyncio.create_task(self.browser._new_page(fixture.context))
        await asyncio.wait_for(detach_started.wait(), timeout=1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assert_background_target(fixture)
        self.assertTrue(fixture.page.is_closed())
        self.assertEqual(fixture.context.pages, [fixture.anchor])
        fixture.anchor.close.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
