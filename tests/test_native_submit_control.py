"""Exercise localized submit preflight in Chromium using only an offline DOM."""

import unittest

from playwright.async_api import async_playwright

from src.services.captcha_errors import BrowserCaptchaError
from src.services.native_image_submission import _prepare_submit_control


STYLE_AND_EVENTS = """<!doctype html><style>
button { margin: 20px; padding: 12px; }
#blocker { position: fixed; inset: 0; z-index: 100; background: white; }
</style><script>
window.clicks = 0;
window.dispatched = [];
for (const type of ['pointerdown', 'mousedown', 'mouseup', 'click']) {
    document.addEventListener(type, event => dispatched.push({type, id: event.target.id}));
}
</script>"""


class NativeSubmitControlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.context = await self.browser.new_context()
        # The test surface is always an about:blank document. Deny even an
        # accidental external resource request; no account or service is used.
        await self.context.route("**/*", lambda route: route.abort())
        self.page = await self.context.new_page()

    async def asyncTearDown(self):
        await self.context.close()
        await self.browser.close()
        await self.playwright.stop()

    async def assert_no_submit_events(self):
        self.assertEqual(await self.page.evaluate("clicks"), 0)
        self.assertEqual(await self.page.evaluate("dispatched"), [])

    async def test_each_supported_locale_preflights_without_dispatch_then_clicks_once(self):
        for label in ("Start generation", "开始生成", "開始生成"):
            with self.subTest(label=label):
                await self.page.set_content(STYLE_AND_EVENTS + (
                    f'<button id="submit" aria-label="{label}" onclick="clicks++">Generate</button>'
                ))
                control = await _prepare_submit_control(self.page)
                self.assertEqual(await control.get_attribute("aria-label"), label)
                await self.assert_no_submit_events()

                await control.click(timeout=1000)
                self.assertEqual(await self.page.evaluate("clicks"), 1)
                clicks = await self.page.evaluate("dispatched.filter(event => event.type === 'click')")
                self.assertEqual(clicks, [{"type": "click", "id": "submit"}])

    async def test_hidden_stale_control_does_not_shadow_visible_localized_control(self):
        await self.page.set_content(STYLE_AND_EVENTS + """
            <button id=hidden aria-label="Start generation" style="display:none" onclick="clicks+=100">Old</button>
            <button id=submit aria-label="开始生成" onclick="clicks++">Generate</button>
        """)
        control = await _prepare_submit_control(self.page)
        self.assertEqual(await control.get_attribute("id"), "submit")
        await self.assert_no_submit_events()
        await control.click(timeout=1000)
        self.assertEqual(await self.page.evaluate("clicks"), 1)

    async def test_unrelated_labels_text_and_non_button_are_rejected(self):
        await self.page.set_content(STYLE_AND_EVENTS + """
            <button id=prefix aria-label="Start generation preview" onclick="clicks++">Generate</button>
            <button id=text onclick="clicks++">开始生成</button>
            <div id=nonbutton role=button aria-label="Start generation" onclick="clicks++">Generate</div>
        """)
        with self.assertRaises(BrowserCaptchaError) as raised:
            await _prepare_submit_control(self.page)
        self.assertEqual((raised.exception.stage, raised.exception.reason), (
            "native_submit_prepare", "submit_control_missing",
        ))
        await self.assert_no_submit_events()

    async def test_disabled_control_trial_fails_without_dispatch(self):
        await self.page.set_content(STYLE_AND_EVENTS + """
            <button id=submit aria-label="开始生成" disabled onclick="clicks++">Generate</button>
        """)
        with self.assertRaises(BrowserCaptchaError) as raised:
            await _prepare_submit_control(self.page)
        self.assertEqual((raised.exception.stage, raised.exception.reason), (
            "native_submit_prepare", "submit_control_not_ready",
        ))
        await self.assert_no_submit_events()

    async def test_overlay_blocked_control_trial_fails_without_dispatch(self):
        await self.page.set_content(STYLE_AND_EVENTS + """
            <button id=submit aria-label="開始生成" onclick="clicks++">Generate</button>
            <div id=blocker></div>
        """)
        with self.assertRaises(BrowserCaptchaError) as raised:
            await _prepare_submit_control(self.page)
        self.assertEqual((raised.exception.stage, raised.exception.reason), (
            "native_submit_prepare", "submit_control_not_ready",
        ))
        await self.assert_no_submit_events()


if __name__ == "__main__":
    unittest.main()
