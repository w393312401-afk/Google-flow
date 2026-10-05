"""Offline DOM behavior tests; no Flow/Ads connection or generation requests."""

import ast
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from playwright.async_api import async_playwright

from src.services.captcha_errors import BrowserCaptchaError
from src.services.native_generation_setup import configure_native_generation


def catalog_image_ratios():
    # Read the API catalog without importing its generation services or runtime state.
    source = Path(__file__).resolve().parents[1] / "src/services/generation_handler.py"
    for node in ast.parse(source.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "MODEL_CONFIG"
            for target in node.targets
        ):
            catalog = ast.literal_eval(node.value)
            return {entry["aspect_ratio"] for entry in catalog.values() if entry["type"] == "image"}
    raise AssertionError("API model catalog was not found")


HTML = """<!doctype html><body>
<button id="summary" onclick="openSettings()">Image crop_9_16 x2</button>
<div role="menu" data-state="open" id="unrelated"><button role="menuitem">Omni 1.1 Flash</button></div>
<flow-prompt-box-settings class="settings-content-overlay" hidden></flow-prompt-box-settings>
<div role="menu" id="models" aria-labelledby="family" hidden>
  <button role="menuitem" onclick="chooseModel()">Omni 1.1 Flash</button>
</div>
<script>
window.events=[];
window.options={ignoreSave:false, ignoreModel:false, missingRatio:false, legacy:false, localized:false, compactSummary:false};
window.saved={mode:'IMAGE', ratio:'PORTRAIT', count:'2', model:'Veo 3.1 - Fast', duration:'8'};
window.pending={...saved};
var panel=document.querySelector('flow-prompt-box-settings');
function group(name,key,values) {
 return `<flow-toggles aria-label="${name}">`+values.map(([value,text]) =>
 `<button role="radio" aria-checked="${pending[key]===value}" onclick="setValue('${key}','${value}')"><span class="toggle-text">${text}</span></button>`).join('')+'</flow-toggles>';
}
function render() {
 panel.innerHTML='<div class="settings-content">'+
 group('Mode','mode',[['IMAGE','Image'],['VIDEO','Video']])+
 `<button id="family" aria-label="Select model family" aria-haspopup="menu" aria-controls="models" onclick="document.querySelector('#models').hidden=false"><span class="model-select-trigger-content">${pending.model}</span><span>arrow_drop_down</span></button>`+
 (pending.mode==='VIDEO' && pending.model.includes('Omni') ? group(options.localized?'时长':'Duration','duration', ['4','6','8','10'].map(v=>[v,options.localized?v+' 秒':v+'s'])):'')+
 group('Aspect ratio','ratio',(options.missingRatio ? [['PORTRAIT','9:16'],['LANDSCAPE_4_3','4:3']] : [['PORTRAIT','9:16'],['LANDSCAPE','16:9'],['LANDSCAPE_4_3','4:3'],['PORTRAIT_3_4','3:4'],['SQUARE','1:1']]))+
 group('Output count','count',[['1','x1'],['2','x2']])+
 (options.legacy?'':'<button onclick="save()">Save</button>')+'</div>';
}
function setValue(key,value) { events.push(key+':'+value); pending[key]=value; render(); }
function chooseModel() { events.push('model:Omni'); if(!options.ignoreModel) pending.model='Omni 1.1 Flash'; document.querySelector('#models').hidden=true; render(); }
function openSettings() { events.push('open'); pending={...saved}; render(); panel.hidden=false; }
function closeSettings() { panel.hidden=true; document.querySelector('#models').hidden=true; }
function save() { events.push('save'); if(!options.ignoreSave) saved={...pending};
 if(options.compactSummary) document.querySelector('#summary').innerHTML='<span>Video</span><span>crop_16_9</span><span>x1</span><span>expand_more</span>';
 closeSettings(); }
document.addEventListener('keydown',e=>{ if(e.key==='Escape') { if(options.legacy) saved={...pending}; closeSettings(); }});
</script></body>"""


class NativeGenerationSetupTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        self.context = await self.browser.new_context()
        await self.context.route("**/*", lambda route: route.abort())
        self.page = await self.context.new_page()
        await self.page.set_content(HTML)
        self.wait_patch = patch("src.services.native_generation_setup._CONTROL_WAIT_SECONDS", 0.4)
        self.wait_patch.start()
        self.diagnostic_patch = patch("src.services.native_generation_setup._record_setup_diagnostic", new_callable=AsyncMock)
        self.diagnostic_mock = self.diagnostic_patch.start()

    async def asyncTearDown(self):
        self.wait_patch.stop()
        self.diagnostic_patch.stop()
        await self.context.close()
        await self.browser.close()
        await self.playwright.stop()

    async def configure(self, **kwargs):
        await configure_native_generation(self.page, **kwargs)

    async def test_video_selects_omni_before_each_supported_duration_and_persists(self):
        for duration in (4, 6, 8, 10):
            with self.subTest(duration=duration):
                await self.page.set_content(HTML)
                await self.configure(kind="VIDEO", aspect_ratio="VIDEO_ASPECT_RATIO_LANDSCAPE",
                                     model_key=f"abra_t2v_{duration}s")
                state = await self.page.evaluate("saved")
                self.assertEqual(state, dict(mode="VIDEO", ratio="LANDSCAPE", count="1",
                                             model="Omni 1.1 Flash", duration=str(duration)))
                events = await self.page.evaluate("events")
                self.assertLess(events.index("mode:VIDEO"), events.index("model:Omni"))
                if duration != 8:
                    self.assertLess(events.index("model:Omni"), events.index(f"duration:{duration}"))
                self.assertEqual(events.count("save"), 1)
                self.assertEqual(events.count("open"), 1)
                self.assertTrue(await self.page.locator("flow-prompt-box-settings").is_hidden())

    async def test_image_after_video_changes_mode_and_preserves_model_for_request_hook(self):
        await self.page.evaluate("saved={mode:'VIDEO',ratio:'LANDSCAPE',count:'2',model:'Omni 1.1 Flash',duration:'4'}")
        await self.configure(kind="IMAGE", aspect_ratio="IMAGE_ASPECT_RATIO_PORTRAIT")
        state = await self.page.evaluate("saved")
        self.assertEqual(state["mode"], "IMAGE")
        self.assertEqual(state["ratio"], "PORTRAIT")
        self.assertEqual(state["count"], "1")
        self.assertEqual(state["model"], "Omni 1.1 Flash")
        self.assertNotIn("model:Omni", await self.page.evaluate("events"))

    async def test_additional_image_ratios_are_exact_not_landscape_fallback(self):
        for ratio, wanted in (("1:1", "SQUARE"), ("IMAGE_ASPECT_RATIO_FOUR_THREE", "LANDSCAPE_4_3"),
                              ("IMAGE_ASPECT_RATIO_THREE_FOUR", "PORTRAIT_3_4")):
            with self.subTest(ratio=ratio):
                await self.page.set_content(HTML)
                await self.configure(kind="IMAGE", aspect_ratio=ratio)
                self.assertEqual(await self.page.evaluate("saved.ratio"), wanted)

    async def test_every_api_image_ratio_selects_and_saves_the_exact_ui_ratio(self):
        expected = {
            "IMAGE_ASPECT_RATIO_LANDSCAPE": "LANDSCAPE",
            "IMAGE_ASPECT_RATIO_PORTRAIT": "PORTRAIT",
            "IMAGE_ASPECT_RATIO_SQUARE": "SQUARE",
            "IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE": "LANDSCAPE_4_3",
            "IMAGE_ASPECT_RATIO_PORTRAIT_THREE_FOUR": "PORTRAIT_3_4",
        }
        self.assertEqual(catalog_image_ratios(), set(expected))
        for ratio, wanted in expected.items():
            with self.subTest(api_ratio=ratio):
                await self.page.set_content(HTML)
                await self.configure(kind="IMAGE", aspect_ratio=ratio)
                state = await self.page.evaluate("saved")
                self.assertEqual(state["ratio"], wanted)
                self.assertEqual(state["mode"], "IMAGE")
                self.assertEqual(state["count"], "1")
                events = await self.page.evaluate("events")
                self.assertEqual(events.count("save"), 1)
                self.assertTrue(all(event == f"ratio:{wanted}" for event in events if event.startswith("ratio:")))

    async def test_missing_api_four_three_or_three_four_fails_without_ratio_fallback(self):
        for ratio, absent_option in (
            ("IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE", "['LANDSCAPE_4_3','4:3'],"),
            ("IMAGE_ASPECT_RATIO_PORTRAIT_THREE_FOUR", "['PORTRAIT_3_4','3:4'],"),
        ):
            with self.subTest(api_ratio=ratio):
                await self.page.set_content(HTML.replace(absent_option, ""))
                with self.assertRaises(BrowserCaptchaError) as failure:
                    await self.configure(kind="IMAGE", aspect_ratio=ratio)
                self.assertEqual(failure.exception.reason, "ratio_failed")
                events = await self.page.evaluate("events")
                self.assertFalse(any(event.startswith("ratio:") for event in events))
                self.assertNotIn("save", events)

    async def test_localized_duration_and_already_open_panel(self):
        await self.page.evaluate("options.localized=true; openSettings()")
        await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s", duration="4s")
        self.assertEqual(await self.page.evaluate("saved.duration"), "4")
        self.assertEqual((await self.page.evaluate("events")).count("open"), 1)

    async def localized_mode(self, *, group_label="Mode", icons=True, owner_state=False):
        """Model the icon + Chinese labels captured in the failed Flow panel."""
        await self.page.evaluate("""({groupLabel, icons, ownerState}) => {
            const originalGroup = group;
            group = (name, key, values) => {
                if (key !== 'mode') return originalGroup(name, key, values);
                const groupAttribute = groupLabel === null ? '' : ` aria-label="${groupLabel}"`;
                return `<flow-toggles${groupAttribute}><mat-button-toggle-group role="radiogroup">` + values.map(([value]) => {
                    const icon = value === 'IMAGE' ? 'image' : 'videocam';
                    const label = value === 'IMAGE' ? '图片' : '视频';
                    const content = icons ? `<mat-icon class="google-symbols">${icon}</mat-icon><span>${label}</span>` : icon+' '+label;
                    const selected = pending.mode === value;
                    const button = `<button ${ownerState ? '' : `role="radio" aria-checked="${selected}"`}
                        onclick="setValue('mode','${value}')"><span class="mat-button-toggle-label-content">${content}</span></button>`;
                    return `<mat-button-toggle ${ownerState ? `aria-pressed="${selected}"` : ''}
                        class="${selected ? 'mat-button-toggle-checked' : ''}">${button}</mat-button-toggle>`;
                }).join('') + '</mat-button-toggle-group></flow-toggles>';
            };
        }""", dict(groupLabel=group_label, icons=icons, ownerState=owner_state))

    async def test_chinese_icon_mode_labels_select_video_and_image(self):
        for kind in ("VIDEO", "IMAGE"):
            with self.subTest(kind=kind):
                await self.page.set_content(HTML)
                await self.localized_mode(group_label="模式")
                await self.page.evaluate("saved.mode='VIDEO'" if kind == "IMAGE" else "saved.mode='IMAGE'")
                await self.configure(kind=kind, aspect_ratio="16:9", **(
                    dict(model_key="abra_t2v_4s") if kind == "VIDEO" else {}))
                self.assertEqual(await self.page.evaluate("saved.mode"), kind)
                self.assertEqual((await self.page.evaluate("events")).count("mode:" + kind), 1)
                self.assertEqual((await self.page.evaluate("events")).count("save"), 1)

    async def test_plain_mode_ligatures_and_unlabelled_exact_pair(self):
        await self.localized_mode(group_label=None, icons=False)
        await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertEqual(await self.page.evaluate("saved.mode"), "VIDEO")

    async def test_mode_selection_on_owning_toggle_is_confirmed(self):
        await self.localized_mode(owner_state=True)
        await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertEqual(await self.page.evaluate("saved.mode"), "VIDEO")
        self.assertEqual((await self.page.evaluate("events")).count("mode:VIDEO"), 1)

    async def test_false_aria_state_does_not_trust_stale_selected_class(self):
        await self.page.evaluate("""() => {
            const originalRender = render;
            render = () => {
                originalRender();
                panel.querySelectorAll('[aria-label="Mode"] button').forEach(button => button.classList.add('selected'));
            };
            setValue = (key, value) => events.push(key+':'+value);
        }""")
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertEqual(failure.exception.reason, "mode_failed")
        self.assertNotIn("save", await self.page.evaluate("events"))
        self.assertEqual(failure.exception.stage, "native_generation_setup")
        self.diagnostic_mock.assert_awaited_once_with(self.page, "mode", "selection_not_confirmed")

    async def test_disabled_mode_has_fixed_diagnostic_reason_and_never_clicks(self):
        await self.page.evaluate("""() => {
            const originalRender = render;
            render = () => {
                originalRender();
                panel.querySelector('[aria-label="Mode"] button:last-child').disabled = true;
            };
        }""")
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertEqual(failure.exception.reason, "mode_failed")
        self.assertNotIn("mode:VIDEO", await self.page.evaluate("events"))
        self.assertNotIn("save", await self.page.evaluate("events"))
        self.diagnostic_mock.assert_awaited_once_with(self.page, "mode", "control_disabled")

    async def test_owner_false_state_wins_over_stale_button_class(self):
        await self.localized_mode(owner_state=True)
        await self.page.evaluate("""() => {
            const originalRender = render;
            render = () => {
                originalRender();
                panel.querySelectorAll('[aria-label="Mode"] button').forEach(button => button.classList.add('selected'));
            };
            setValue = (key, value) => events.push(key+':'+value);
        }""")
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertEqual(failure.exception.reason, "mode_failed")
        self.assertNotIn("save", await self.page.evaluate("events"))
        self.diagnostic_mock.assert_awaited_once_with(self.page, "mode", "selection_not_confirmed")

    async def test_mode_does_not_match_longer_label_or_unrelated_group(self):
        await self.page.evaluate("""() => {
            const originalGroup = group;
            group = (name, key, values) => key === 'mode'
                ? `<flow-toggles aria-label="Other"><button onclick="events.push('wrong-mode')">Image to Video</button><button>Image</button></flow-toggles>`
                : originalGroup(name, key, values);
        }""")
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertEqual(failure.exception.reason, "mode_failed")
        self.assertNotIn("wrong-mode", await self.page.evaluate("events"))
        self.assertNotIn("save", await self.page.evaluate("events"))

    async def test_ambiguous_mode_groups_fail_without_picking_first(self):
        await self.page.evaluate("""() => {
            const originalGroup = group;
            group = (name, key, values) => originalGroup(name, key, values).repeat(key === 'mode' ? 2 : 1);
        }""")
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertEqual(failure.exception.reason, "mode_failed")
        self.assertNotIn("mode:VIDEO", await self.page.evaluate("events"))
        self.assertNotIn("save", await self.page.evaluate("events"))

    async def test_saved_video_summary_is_not_reopened(self):
        await self.page.evaluate("options.compactSummary=true")
        await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertEqual(await self.page.locator('#summary').text_content(), "Videocrop_16_9x1expand_more")
        self.assertEqual((await self.page.evaluate("events")).count("open"), 1)
        self.assertEqual(await self.page.evaluate("saved.duration"), "4")

    async def test_save_that_does_not_close_settings_fails_before_submission(self):
        await self.page.evaluate("save=()=>events.push('save')")
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.configure(kind="IMAGE", aspect_ratio="16:9")
        self.assertEqual(failure.exception.reason, "save_failed")
        self.assertEqual((await self.page.evaluate("events")).count("open"), 1)

    async def test_model_click_without_actual_selection_fails_before_save(self):
        await self.page.evaluate("options.ignoreModel=true")
        with self.assertRaises(BrowserCaptchaError):
            await self.configure(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s")
        self.assertNotIn("save", await self.page.evaluate("events"))

    async def test_missing_landscape_does_not_select_four_three(self):
        await self.page.evaluate("options.missingRatio=true")
        with self.assertRaises(BrowserCaptchaError):
            await self.configure(kind="IMAGE", aspect_ratio="16:9")
        self.assertNotIn("ratio:LANDSCAPE_4_3", await self.page.evaluate("events"))
        self.assertNotIn("save", await self.page.evaluate("events"))

    async def test_legacy_immediate_settings_close_with_escape(self):
        await self.page.evaluate("options.legacy=true")
        await self.configure(kind="IMAGE", aspect_ratio="16:9")
        self.assertEqual(await self.page.evaluate("saved.ratio"), "LANDSCAPE")
        self.assertNotIn("save", await self.page.evaluate("events"))

    async def test_frames_sets_submode_resolution_and_portrait_before_save(self):
        for resolution in ("360p", "720p"):
            with self.subTest(resolution=resolution):
                await self.page.set_content(HTML)
                await self.page.evaluate("""() => {
                    saved.submode='Ingredients'; saved.resolution='720p';
                    const baseRender=render;
                    render=()=>{baseRender(); panel.insertAdjacentHTML('beforeend',
                        group('Video type','submode',[['Ingredients','Ingredients'],['Frames','Frames']])+
                        group('Video resolution','resolution',[['360p','360p info'],['720p','720p']]));};
                }""")
                await self.configure(kind="VIDEO", aspect_ratio="9:16", model_key="abra_i2v_10s",
                                     resolution=resolution, frames=True)
                state = await self.page.evaluate("saved")
                self.assertEqual(state["submode"], "Frames")
                self.assertEqual(state["resolution"], resolution)
                self.assertEqual(state["duration"], "10")
                self.assertEqual(state["ratio"], "PORTRAIT")
                self.assertEqual(state["count"], "1")

    async def test_complete_chinese_angular_settings_configure_and_verify_all_fields(self):
        for traditional in (False, True):
            with self.subTest(traditional=traditional):
                await self.page.set_content(HTML)
                await self.page.evaluate("""traditional => {
                    saved.submode='Ingredients'; saved.resolution='720p'; saved.ratio='LANDSCAPE';
                    const groupLabels = traditional ? {
                        mode:'模式', ratio:'寬高比', count:'輸出數量', duration:'時長',
                        submode:'視頻類型', resolution:'視頻分辨率'
                    } : {
                        mode:'模式', ratio:'宽高比', count:'输出数量', duration:'时长',
                        submode:'视频类型', resolution:'视频分辨率'
                    };
                    group = (name, key, values) => `<flow-toggles aria-label="${groupLabels[key]}">
                        <mat-button-toggle-group role="radiogroup">` + values.map(([value, text]) => {
                        const selected = pending[key] === value;
                        let icon = '', label = text;
                        if (key === 'mode') {
                            icon = value === 'IMAGE' ? 'image' : 'videocam';
                            label = value === 'IMAGE' ? (traditional ? '圖片' : '图片') : (traditional ? '視頻' : '视频');
                        } else if (key === 'ratio') {
                            icon = 'crop_'+text.replace(':','_');
                        } else if (key === 'submode') {
                            icon = value === 'Frames' ? 'view_agenda' : 'developer_board';
                            label = value === 'Frames' ? (traditional ? '幀' : '帧') : '素材';
                        } else if (key === 'resolution') {
                            label = value; icon = value === '360p' ? 'info' : '';
                        } else if (key === 'duration') {
                            label = value+' 秒';
                        }
                        return `<mat-button-toggle class="${selected ? 'mat-button-toggle-checked' : ''}">
                            <button role="radio" aria-checked="${selected}" onclick="setValue('${key}','${value}')">
                                <span class="mat-button-toggle-label-content"><span class="toggle-label">
                                    ${icon ? `<mat-icon class="google-symbols">${icon}</mat-icon>` : ''}
                                    <span class="toggle-text">${label}</span>
                                </span></span>
                            </button></mat-button-toggle>`;
                    }).join('')+'</mat-button-toggle-group></flow-toggles>';
                    const originalRender = render;
                    render = () => {
                        originalRender();
                        panel.querySelector('button[onclick="save()"]').textContent = '保存';
                        panel.insertAdjacentHTML('beforeend',
                            group('Video type','submode',[['Ingredients','Ingredients'],['Frames','Frames']])+
                            group('Video resolution','resolution',[['360p','360p info'],['720p','720p']]));
                    };
                }""", traditional)
                await self.configure(kind="VIDEO", aspect_ratio="9:16", model_key="abra_i2v_10s",
                                     resolution="360p", frames=True)
                state = await self.page.evaluate("saved")
                self.assertEqual(state, dict(mode="VIDEO", ratio="PORTRAIT", count="1",
                                             model="Omni 1.1 Flash", duration="10", submode="Frames",
                                             resolution="360p"))
                events = await self.page.evaluate("events")
                for event in ("mode:VIDEO", "model:Omni", "duration:10", "submode:Frames",
                              "resolution:360p", "ratio:PORTRAIT", "count:1", "save"):
                    self.assertEqual(events.count(event), 1)
                self.assertTrue(await self.page.locator("flow-prompt-box-settings").is_hidden())

    async def test_missing_frames_control_fails_before_save(self):
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.configure(kind="VIDEO", aspect_ratio="9:16", model_key="abra_i2v_10s",
                                 resolution="360p", frames=True)
        self.assertEqual(failure.exception.reason, "submode_failed")
        self.assertNotIn("save", await self.page.evaluate("events"))

    async def test_unrelated_menu_and_invalid_spec_never_count_as_configured(self):
        for kwargs in (
            dict(kind="VIDEO", aspect_ratio="16:9", model_key="abra_t2v_4s", duration=8),
            dict(kind="IMAGE", aspect_ratio="secret-token-account@example.com"),
        ):
            with self.assertRaises(BrowserCaptchaError) as failure:
                await self.configure(**kwargs)
            self.assertEqual(failure.exception.reason, "invalid_spec")
            self.assertNotIn("secret", str(failure.exception))
        self.assertEqual(await self.page.evaluate("events"), [])
        await self.page.locator("#summary").evaluate("el=>el.remove()")
        with self.assertRaises(BrowserCaptchaError) as failure:
            await self.configure(kind="IMAGE", aspect_ratio="16:9")
        self.assertEqual(failure.exception.reason, "summary_find_failed")


if __name__ == "__main__":
    unittest.main()
