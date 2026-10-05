"""Exercise Chromium's real contenteditable behavior with all networking blocked."""

import unittest

from playwright.async_api import async_playwright

from src.services.native_prompt import read_native_prompt


class NativePromptTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.context = await self.browser.new_context()
        await self.context.route("**/*", lambda route: route.abort())
        self.page = await self.context.new_page()
        await self.page.set_content(
            '<div class="ProseMirror" contenteditable="true" '
            'style="white-space:pre-wrap;min-height:100px;width:500px"><p><br></p></div>'
        )
        self.editor = self.page.locator('.ProseMirror')

    async def asyncTearDown(self):
        await self.context.close()
        await self.browser.close()
        await self.playwright.stop()

    async def test_fill_double_newline_has_css_spacing_but_exact_logical_text(self):
        prompt = 'Keep the original architecture.\n\n镜头缓慢向前移动。'
        await self.editor.fill(prompt)
        # Reproduces the production bug: innerText includes paragraph margins.
        self.assertNotEqual(await self.editor.inner_text(), prompt)
        self.assertEqual(await read_native_prompt(self.editor), prompt)

    async def test_fill_preserves_line_count_unicode_and_edge_newlines(self):
        for prompt in ('one line', '一\n二', '一\n\n\n二🙂', '\nstart', 'end\n', '\na\n\n'):
            for initial in ('<p><br></p>', ''):
                with self.subTest(prompt=repr(prompt), initial=initial):
                    await self.editor.evaluate('(ed, html) => ed.innerHTML=html', initial)
                    await self.editor.fill(prompt)
                    self.assertEqual(await read_native_prompt(self.editor), prompt)

    async def test_hard_breaks_inline_marks_and_caret_placeholder(self):
        await self.editor.evaluate("""ed => ed.innerHTML =
            '<p><strong>Keep</strong> <span>this</span><br>line<br><br class="ProseMirror-trailingBreak"></p>'
        """)
        self.assertEqual(await read_native_prompt(self.editor), 'Keep this\nline\n')

    async def test_actual_whitespace_is_not_folded_or_trimmed(self):
        prompt = '  spaces\tand\u00a0NBSP\u200b\n\nend  '
        await self.editor.evaluate('(ed, text) => ed.textContent=text', prompt)
        self.assertEqual(await read_native_prompt(self.editor), prompt)
        self.assertNotEqual(await read_native_prompt(self.editor), prompt.strip())
        self.assertNotEqual(await read_native_prompt(self.editor), prompt.replace('\n\n', '\n'))
        self.assertNotEqual(await read_native_prompt(self.editor), prompt.replace('\u00a0', ' '))

    async def test_missing_text_and_unknown_content_cannot_pass_as_requested_prompt(self):
        await self.editor.fill('Keep all requested words.\n\nSecond paragraph.')
        await self.editor.evaluate("ed => ed.querySelector('p').firstChild.deleteData(0, 1)")
        self.assertNotEqual(
            await read_native_prompt(self.editor), 'Keep all requested words.\n\nSecond paragraph.'
        )
        for extra in ('<img alt="hidden text">', '<span contenteditable="false">chip</span>', '<section>text</section>'):
            await self.editor.evaluate('(ed, html) => ed.innerHTML="<p>text</p>"+html', extra)
            self.assertIsNone(await read_native_prompt(self.editor))


if __name__ == '__main__':
    unittest.main()
