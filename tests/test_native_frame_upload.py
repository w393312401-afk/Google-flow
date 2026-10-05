"""Offline browser checks for explicit first/last file chooser ownership."""
import unittest
from unittest.mock import AsyncMock, patch

from playwright.async_api import async_playwright

from src.services.captcha_errors import BrowserCaptchaError
from src.services.native_frame_upload import (
    upload_native_frames, validate_frame_images, _mount_uploaded_asset, _accept_upload_rights,
)
from tests.test_native_frame_submission import png_bytes

HTML = """<!doctype html><style>img{width:24px;height:24px}</style>
<input type=file id=unrelated hidden>
<flow-ingredient-bar><div class=frame-trigger><button onclick="openSlot(0)">Start</button></div>
<div class=frame-trigger><button onclick="openSlot(1)">End</button></div></flow-ingredient-bar>
<div id=menu class=cdk-overlay-pane hidden><button onclick="document.querySelector('#framefile').click()"><span>upload</span><span>Upload media</span></button></div>
<input type=file id=framefile hidden><script>
window.ids=['11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222'];
window.currentSlot=0;window.wrongSlot=false;window.staleEnd=false;window.files=[];window.confirmed=[];
window.rightsDialog=false;window.pendingFile=null;window.agreed=[];window.cancelled=false;window.uploadLabel='Upload media';
function openSlot(index){ currentSlot=index; const menu=document.querySelector('#menu');
menu.innerHTML=`<button onclick="document.querySelector('#framefile').click()">${uploadLabel}</button>`; menu.hidden=false; }
function chooseUpload(){
 confirmed.push(currentSlot);
 const index=wrongSlot ? 1-currentSlot:currentSlot;
 document.querySelectorAll('.frame-trigger')[index].innerHTML=`<button><img src="https://example.test/image/${ids[currentSlot]}"></button>`;
 document.querySelector('#menu').hidden=true;
}
function showPicker(file){
 document.querySelector('#menu').innerHTML=`<div class=asset-list-viewport role=listbox><div role=option><img src="https://example.test/image/${ids[currentSlot]}"><span>${file.name}</span></div></div><img src="https://example.test/image/${ids[currentSlot]}"><button onclick="chooseUpload()">Add to prompt</button>`;
}
function acceptRights(){ agreed.push(currentSlot); document.querySelector('#rights').remove(); showPicker(pendingFile); }
function cancelRights(){ cancelled=true; document.querySelector('#rights').remove(); }
document.querySelector('#framefile').addEventListener('change',e=>{
 const file=e.target.files[0]; files.push({name:file.name, size:file.size, role:currentSlot});
 if(staleEnd && currentSlot===1) document.querySelectorAll('.frame-trigger')[1].innerHTML=`<button><img src="https://example.test/image/${ids[0]}"></button>`;
 if(rightsDialog){
  pendingFile=file;
  document.body.insertAdjacentHTML('beforeend','<div id=rights role=dialog><h2>Rights to use this image</h2><p>Make sure you have the necessary rights.</p><button onclick="cancelRights()">Cancel</button><button onclick="acceptRights()">I agree</button></div>');
 } else showPicker(file);
});</script>"""


class NativeFrameUploadTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.context = await self.browser.new_context()
        await self.context.route('**/*', lambda route: route.fulfill(content_type='image/png', body=png_bytes('red')))
        self.page = await self.context.new_page()
        await self.page.set_content(HTML)
        self.enterContext(patch('src.services.native_frame_upload._record_upload_diagnostic', new_callable=AsyncMock))

    async def asyncTearDown(self):
        await self.context.close()
        await self.browser.close()
        await self.playwright.stop()

    async def test_uploads_exact_files_in_order_through_each_explicit_slot(self):
        frames = [png_bytes('red'), png_bytes('blue')]
        spec = {'frame_files': validate_frame_images(frames, 'start_end')}
        await upload_native_frames(self.page, spec)
        self.assertEqual(spec['frame_media_ids'], await self.page.evaluate('ids'))
        uploads = await self.page.evaluate('files')
        self.assertEqual([row['role'] for row in uploads], [0, 1])
        self.assertEqual([row['size'] for row in uploads], [len(value) for value in frames])
        self.assertIn('-first-', uploads[0]['name'])
        self.assertIn('-last-', uploads[1]['name'])
        self.assertEqual(await self.page.locator('#unrelated').evaluate('el=>el.files.length'), 0)

    async def test_nonempty_stale_last_frame_does_not_bypass_upload_identity(self):
        await self.page.evaluate('staleEnd=true')
        frames = [png_bytes('red'), png_bytes('blue')]
        spec = {'frame_files': validate_frame_images(frames, 'start_end')}
        await upload_native_frames(self.page, spec)
        self.assertEqual(spec['frame_media_ids'], await self.page.evaluate('ids'))
        self.assertEqual(await self.page.evaluate('confirmed'), [0, 1])

    async def test_picker_selects_exact_uploaded_filename_before_confirming(self):
        await self.page.set_content("""<style>img{width:24px;height:24px}</style>
            <div class=cdk-overlay-pane><div class=asset-list-viewport role=listbox>
              <div role=option><img src='https://example.test/11111111-1111-1111-1111-111111111111'>
                <span onclick="document.querySelector('#preview').src=this.previousElementSibling.src">flow2api-first-unique.png</span></div>
              <div role=option><img src='https://example.test/22222222-2222-2222-2222-222222222222'>
                <span>old green mug</span></div></div>
              <img id=preview src='https://example.test/22222222-2222-2222-2222-222222222222'>
              <button onclick="window.chosen=document.querySelector('#preview').src">Add to prompt</button>
            </div>""")
        blocked = await _mount_uploaded_asset(self.page, {'name': 'flow2api-first-unique.png'}, forbidden_ids=['11111111-1111-1111-1111-111111111111'])
        self.assertIsNone(blocked)
        self.assertIsNone(await self.page.evaluate('window.chosen'))
        result = await _mount_uploaded_asset(self.page, {'name': 'flow2api-first-unique.png'})
        self.assertEqual(result, '11111111-1111-1111-1111-111111111111')
        self.assertIn(result, await self.page.evaluate('chosen'))

    async def test_picker_direct_binding_closes_without_waiting_for_removed_viewport(self):
        await self.page.set_content("""<style>img{width:24px;height:24px}</style>
            <flow-ingredient-bar><div class=frame-trigger><button>Start</button></div><div class=frame-trigger id=target><button>End</button></div></flow-ingredient-bar>
            <div class=cdk-overlay-pane><div class=asset-list-viewport role=listbox>
              <div role=option><img src='https://example.test/11111111-1111-1111-1111-111111111111'>
                <span onclick="document.querySelector('#target').replaceChildren(this.previousElementSibling.cloneNode()); document.querySelector('.cdk-overlay-pane').remove()">flow2api-last-unique.png</span></div></div>
              <img id=preview src='https://example.test/22222222-2222-2222-2222-222222222222'>
              <button onclick="window.chosen=true">Add to prompt</button>
            </div>""")
        import asyncio
        result = await asyncio.wait_for(_mount_uploaded_asset(self.page, {'name': 'flow2api-last-unique.png'}, target_index=1), timeout=3)
        self.assertEqual(result, '11111111-1111-1111-1111-111111111111')
        self.assertIsNone(await self.page.evaluate('window.chosen'))

    async def test_picker_does_not_confirm_when_preview_stays_on_old_asset(self):
        await self.page.set_content("""<style>img{width:24px;height:24px}</style>
            <div class=cdk-overlay-pane><div class=asset-list-viewport role=listbox>
              <div role=option><img src='https://example.test/11111111-1111-1111-1111-111111111111'>
                <span>flow2api-first-unique.png</span></div></div>
              <img id=preview src='https://example.test/22222222-2222-2222-2222-222222222222'>
              <button onclick="window.chosen=true">Add to prompt</button>
            </div>""")
        result = await _mount_uploaded_asset(self.page, {'name': 'flow2api-first-unique.png'})
        self.assertIsNone(result)
        self.assertIsNone(await self.page.evaluate('window.chosen'))

    async def test_broken_thumbnail_does_not_hide_the_exact_uploaded_asset(self):
        # This mirrors the failure screenshots: upload is in the picker but
        # its thumbnail has failed while an older asset remains previewed.
        await self.context.route('https://broken.test/**', lambda route: route.abort())
        await self.page.set_content("""<style>img{width:24px;height:24px}</style>
            <flow-ingredient-bar><div class=frame-trigger id=target><button>Start</button></div>
            <div class=frame-trigger><button>End</button></div></flow-ingredient-bar>
            <div class=cdk-overlay-pane><div class=asset-list-viewport role=listbox>
              <flow-add-menu-asset-item>
                <img id=broken src='https://broken.test/image/11111111-1111-1111-1111-111111111111'>
                <span onclick="document.querySelector('#preview').src=this.previousElementSibling.src">flow2api-first-new.png</span>
              </flow-add-menu-asset-item></div>
              <img id=preview src='https://example.test/image/22222222-2222-2222-2222-222222222222'>
              <button onclick="window.chosen=true; document.querySelector('#target').replaceChildren(document.querySelector('#preview').cloneNode()); document.querySelector('.cdk-overlay-pane').remove()">Add to prompt</button>
            </div>""")
        await self.page.wait_for_function("document.querySelector('#broken').complete")
        self.assertEqual(await self.page.locator('#broken').evaluate('el=>el.naturalWidth'), 0)
        result = await _mount_uploaded_asset(self.page, {'name': 'flow2api-first-new.png'})
        self.assertEqual(result, '11111111-1111-1111-1111-111111111111')
        self.assertTrue(await self.page.evaluate('window.chosen'))

    async def test_recycled_thumbnail_with_stale_current_source_is_not_selected(self):
        await self.page.set_content("""<style>img{width:24px;height:24px}</style>
            <div class=cdk-overlay-pane><div class=asset-list-viewport role=listbox>
              <div role=option><img id=stale src='https://example.test/image/11111111-1111-1111-1111-111111111111'>
              <span onclick="window.chosen=true">flow2api-first-new.png</span></div></div>
              <button onclick="window.chosen=true">Add to prompt</button>
            </div>""")
        await self.page.locator('#stale').evaluate("el=>Object.defineProperty(el,'currentSrc',{get:()=> 'https://example.test/image/22222222-2222-2222-2222-222222222222'})")
        result = await _mount_uploaded_asset(self.page, {'name': 'flow2api-first-new.png'})
        self.assertIsNone(result)
        self.assertIsNone(await self.page.evaluate('window.chosen'))

    async def test_similarly_named_old_upload_is_not_the_requested_file(self):
        await self.page.set_content("""<style>img{width:24px;height:24px}</style>
            <div class=cdk-overlay-pane><div class=asset-list-viewport role=listbox>
              <div role=option><img src='https://example.test/image/11111111-1111-1111-1111-111111111111'>
              <span onclick="window.chosen=true">flow2api-first-new-old.png</span></div></div>
              <img src='https://example.test/image/11111111-1111-1111-1111-111111111111'>
              <button onclick="window.chosen=true">Add to prompt</button>
            </div>""")
        result = await _mount_uploaded_asset(self.page, {'name': 'flow2api-first-new.png'})
        self.assertIsNone(result)
        self.assertIsNone(await self.page.evaluate('window.chosen'))

    async def test_changed_other_slot_is_rejected_without_uploading_second_file(self):
        await self.page.evaluate('wrongSlot=true')
        spec = {'frame_files': validate_frame_images([png_bytes('red'), png_bytes('blue')], 'start_end')}
        with self.assertRaises(BrowserCaptchaError) as error:
            await upload_native_frames(self.page, spec)
        self.assertEqual(error.exception.reason, 'other_slot_changed')
        self.assertEqual(len(await self.page.evaluate('files')), 1)
        self.assertNotIn('frame_media_ids', spec)

    async def test_localized_upload_action_labels_open_the_chooser(self):
        # The Chinese picker labels its action "上传媒体内容"; Material icons add a
        # leading "upload" ligature to the button text.
        for label in ('Upload media', '上传媒体', '上传媒体内容', '<span>upload</span>上传媒体内容'):
            with self.subTest(label=label):
                await self.page.evaluate('label => { uploadLabel = label; files.length = 0; }', label)
                await self.page.evaluate("""() => document.querySelectorAll('.frame-trigger').forEach(
                    (slot, index) => slot.innerHTML = `<button onclick="openSlot(${index})">slot</button>`)""")
                spec = {'frame_files': validate_frame_images([png_bytes('red'), png_bytes('blue')], 'start_end')}
                await upload_native_frames(self.page, spec)
                self.assertEqual(spec['frame_media_ids'], await self.page.evaluate('ids'))
                self.assertEqual(len(await self.page.evaluate('files')), 2)

    async def test_upload_rights_dialog_is_accepted_so_the_upload_can_bind(self):
        # Failure screenshots showed the first upload held behind this dialog
        # with an empty picker until "I agree" was clicked.
        await self.page.evaluate('rightsDialog=true')
        spec = {'frame_files': validate_frame_images([png_bytes('red'), png_bytes('blue')], 'start_end')}
        await upload_native_frames(self.page, spec)
        self.assertEqual(spec['frame_media_ids'], await self.page.evaluate('ids'))
        self.assertEqual(await self.page.evaluate('agreed'), [0, 1])
        self.assertFalse(await self.page.evaluate('cancelled'))

    async def test_rights_acceptance_only_clicks_the_exact_visible_enabled_agree_action(self):
        dialog = ("<div role=dialog{attrs}><h2>{title}</h2>"
                  "<button onclick=\"window.cancelled=true\">Cancel</button>"
                  "<button{disabled} onclick=\"window.agreed=(window.agreed||0)+1\">{agree}</button></div>")
        title = 'Rights to use this image'
        cases = [
            ('other title', dialog.format(attrs='', title='Terms of service', disabled='', agree='I agree'), False),
            ('hidden', dialog.format(attrs=' hidden', title=title, disabled='', agree='I agree'), False),
            ('disabled', dialog.format(attrs='', title=title, disabled=' disabled', agree='I agree'), False),
            ('near-miss label', dialog.format(attrs='', title=title, disabled='', agree='I agree and share'), False),
            ('exact', dialog.format(attrs='', title=title, disabled='', agree='I agree'), True),
        ]
        for name, html, expected in cases:
            with self.subTest(name):
                await self.page.set_content(html)
                # set_content keeps the window, so drop the shared page's counters.
                await self.page.evaluate('window.agreed=0; window.cancelled=false')
                self.assertIs(await _accept_upload_rights(self.page), expected)
                self.assertEqual(await self.page.evaluate('window.agreed||0'), 1 if expected else 0)
                self.assertFalse(await self.page.evaluate('!!window.cancelled'))


if __name__ == '__main__':
    unittest.main()
