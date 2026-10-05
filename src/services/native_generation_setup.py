"""Configure Flow's visible controls before permitting a native generation."""

import asyncio
import json
import os
import re
import time
from pathlib import Path

from .captcha_errors import BrowserCaptchaError


_TIMEOUT_SECONDS = 25
_CONTROL_WAIT_SECONDS = 4
_CONTROLS = "button, [role='tab'], [role='radio'], mat-button-toggle"
_ICONS = (
    "mat-icon, svg, .material-icons, .material-icons-outlined, "
    ".material-symbols-outlined, .material-symbols-rounded, .google-symbols, "
    "[aria-hidden='true']"
)
_MODE_LABELS = {
    "IMAGE": ("Image", "图片", "圖片"),
    "VIDEO": ("Video", "视频", "視頻", "影片"),
}
_RATIOS = {
    "LANDSCAPE": ("LANDSCAPE", "16:9", "Landscape", "crop_16_9", "crop_landscape"),
    "PORTRAIT": ("PORTRAIT", "9:16", "Portrait", "crop_9_16", "crop_portrait"),
    "SQUARE": ("SQUARE", "1:1", "Square", "crop_square", "crop_1_1"),
    "FOUR_THREE": ("LANDSCAPE_4_3", "4:3"),
    "THREE_FOUR": ("PORTRAIT_3_4", "3:4"),
}
_GROUPS = {
    "mode": ", ".join(
        f"{tag}[aria-label='{label}' i]"
        for tag in ("flow-toggles", "[role='radiogroup']", "[role='tablist']")
        for label in ("Mode", "模式", "生成模式")
    ),
    "ratio": "flow-toggles[aria-label*='ratio' i], flow-toggles[aria-label*='aspect' i], "
             "flow-toggles[aria-label='宽高比'], flow-toggles[aria-label='寬高比']",
    "count": "flow-toggles[aria-label*='count' i], [role='radiogroup'][aria-label*='count' i], "
             "flow-toggles[aria-label='输出数量'], flow-toggles[aria-label='輸出數量']",
    "submode": "flow-toggles[aria-label='Video type'], flow-toggles[aria-label='视频类型'], "
               "flow-toggles[aria-label='視頻類型']",
    "resolution": "flow-toggles[aria-label='Video resolution'], [role='radiogroup'][aria-label*='resolution' i], "
                  "flow-toggles[aria-label='视频分辨率'], flow-toggles[aria-label='視頻分辨率']",
    "duration": "[aria-label*='duration' i], [aria-label*='时长'], [aria-label*='時長']",
}
_OMNI = re.compile(r"^Omni(?:[\s-]+1\.1)?\s+Flash$", re.I)


class _ControlFailure(ValueError):
    """A fixed diagnostic reason; never includes page or Playwright text."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _spec(kind, aspect_ratio, model_key, duration):
    kind = str(getattr(kind, "value", kind)).upper()
    ratio = str(getattr(aspect_ratio, "value", aspect_ratio)).upper()
    ratio = re.sub(r"^(?:IMAGE|VIDEO)_ASPECT_RATIO_", "", ratio)
    ratio = {"16:9": "LANDSCAPE", "9:16": "PORTRAIT", "1:1": "SQUARE",
             "4:3": "FOUR_THREE", "3:4": "THREE_FOUR",
             "LANDSCAPE_FOUR_THREE": "FOUR_THREE", "PORTRAIT_THREE_FOUR": "THREE_FOUR",
             "LANDSCAPE_4_3": "FOUR_THREE", "PORTRAIT_3_4": "THREE_FOUR"}.get(ratio, ratio)
    if kind not in {"IMAGE", "VIDEO"} or ratio not in _RATIOS:
        raise ValueError
    seconds = None
    if kind == "VIDEO":
        match = re.fullmatch(r"abra_(?:t2v|i2v)_(4|6|8|10)s", str(model_key))
        if not match:
            raise ValueError
        seconds = match[1]
        if duration is not None and str(duration).lower().removesuffix("s") != seconds:
            raise ValueError
    return kind, ratio, seconds


async def _visible(locator):
    for index in range(min(await locator.count(), 40)):
        item = locator.nth(index)
        if await item.is_visible():
            return item
    return None


async def _panel(page):
    # A model named Omni in an upload/account menu is not a settings panel.
    shell = await _visible(page.locator("flow-prompt-box-settings, .settings-content"))
    if shell is not None:
        return shell
    menus = page.locator("[role='menu'][data-state='open']")
    for index in range(min(await menus.count(), 12)):
        menu = menus.nth(index)
        if (await menu.is_visible()
                and await menu.locator("[aria-controls$='-VIDEO'], [aria-controls$='-IMAGE']").count()
                and await menu.locator("button[aria-haspopup='menu']").count()):
            return menu
    return None


async def _wait(find):
    deadline = time.monotonic() + _CONTROL_WAIT_SECONDS
    while True:
        result = await find()
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            raise ValueError
        await asyncio.sleep(0.1)


async def _open(page, mark=None, prefix=""):
    if mark:
        mark(prefix + "summary_find")
    panel = await _panel(page)
    if panel is not None:
        return panel
    summaries = page.locator("button").filter(
        has_text=re.compile(r"Banana|Nano|Imagen|Image|Video|Veo|Omni|图片|视频", re.I)
    # Angular's neighboring spans/icon ligatures can concatenate to
    # "Videocrop_16_9x1expand_more". Word boundaries reject that real toolbar;
    # numeric boundaries still exclude x10 without requiring whitespace.
    ).filter(has_text=re.compile(r"(?:x[1-4](?!\d)|(?<!\d)[1-4]x)", re.I))
    summary = await _wait(lambda: _visible(summaries))
    if mark:
        mark(prefix + "summary_click")
    await summary.click(timeout=4000)
    if mark:
        mark(prefix + "panel_wait")
    return await _wait(lambda: _panel(page))


async def _label(control):
    labels = control.locator(".toggle-text, .model-select-trigger-content")
    source = labels.first if await labels.count() else control
    # Icon fonts contribute ligature text such as image/videocam to innerText.
    # Read the visible text nodes without decoration rather than loosening the
    # exact business-label match to arbitrary substrings.
    text = await source.evaluate("""(el, icons) => {
        const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
        const parts = [];
        while (walker.nextNode()) {
            const node = walker.currentNode, parent = node.parentElement;
            if (!parent || parent.closest(icons) || parent.closest('[hidden]')) continue;
            const style = getComputedStyle(parent);
            if (style.display === 'none' || style.visibility === 'hidden') continue;
            parts.push(node.textContent);
        }
        return parts.join(' ');
    }""", _ICONS)
    return re.sub(r"\s+", " ", re.sub(r"\b(?:check|done|arrow_drop_down)\b", "", text)).strip()


async def _selected(control):
    return await control.evaluate("""el => {
        const owner = el.parentElement?.closest('mat-button-toggle, [role="radio"], [role="tab"]');
        const nodes = [el, owner].filter(Boolean);
        for (const node of nodes) {
            const states = ['aria-checked', 'aria-selected', 'aria-pressed']
                .map(a => node.getAttribute(a)).filter(v => v === 'true' || v === 'false');
            // Explicit ARIA/data state wins over stale visual classes.
            if (states.length) return states.includes('true') && !states.includes('false');
            const state = node.getAttribute('data-state');
            if (['active', 'checked', 'on'].includes(state)) return true;
            if (['inactive', 'unchecked', 'off'].includes(state)) return false;
        }
        return nodes.some(node => ['active', 'selected', 'mat-button-toggle-checked']
            .some(c => node.classList.contains(c)));
    }""")


def _mode_name(label):
    for name, labels in _MODE_LABELS.items():
        pattern = "(?:" + "|".join(re.escape(value) for value in labels) + ")"
        # Some pages emit ligatures as plain text without an icon element.
        icon = "image" if name == "IMAGE" else "videocam"
        if re.fullmatch(rf"(?:{icon}\s*)?{pattern}", label, re.I):
            return name
    return None


async def _mode_candidates(group):
    controls = group.locator(_CONTROLS)
    candidates = []
    for offset in range(min(await controls.count(), 24)):
        control = controls.nth(offset)
        if not await control.is_visible():
            continue
        # A mat-button-toggle and its inner button are one control. Prefer the
        # actual click target and read its owning toggle's state when necessary.
        if await control.locator(_CONTROLS).count():
            continue
        name = _mode_name(await _label(control))
        candidates.append((name, control))
    return candidates


async def _mode_control(panel, wanted):
    groups = panel.locator(_GROUPS["mode"])
    matches = []
    for index in range(min(await groups.count(), 16)):
        group = groups.nth(index)
        if (await group.is_visible() and not await group.evaluate(
                "(el, selector) => !!el.parentElement?.closest(selector)", _GROUPS["mode"])):
            matches.extend(control for name, control in await _mode_candidates(group) if name == wanted)
    if len(matches) > 1:
        raise _ControlFailure("control_ambiguous")
    if matches:
        return matches[0]

    # A localized/unlabelled group must contain exactly the Image/Video pair.
    # Restrict this to toggle groups in the confirmed settings panel.
    groups = panel.locator("flow-toggles, [role='radiogroup'], [role='tablist']")
    for index in range(min(await groups.count(), 16)):
        group = groups.nth(index)
        if not await group.is_visible():
            continue
        if await group.evaluate("el => !!el.parentElement?.closest('flow-toggles, [role=\"radiogroup\"], [role=\"tablist\"]')"):
            continue
        candidates = await _mode_candidates(group)
        if len(candidates) == 2 and {name for name, _ in candidates} == set(_MODE_LABELS):
            matches.extend(control for name, control in candidates if name == wanted)
    if len(matches) > 1:
        raise _ControlFailure("control_ambiguous")
    return matches[0] if matches else None


async def _control(panel, field, labels, suffix):
    if field == "mode":
        mode = await _mode_control(panel, suffix)
        if mode is not None:
            return mode
    pattern = re.compile(r"^(?:" + "|".join(re.escape(v) for v in labels) + r")$", re.I)
    groups = panel.locator(_GROUPS[field])
    for index in range(min(await groups.count(), 16)):
        group = groups.nth(index)
        if not await group.is_visible():
            continue
        controls = group.locator(_CONTROLS)
        for offset in range(min(await controls.count(), 24)):
            control = controls.nth(offset)
            if (await control.is_visible() and not await control.locator(_CONTROLS).count()
                    and pattern.fullmatch(await _label(control))):
                return control
    # Stable legacy business suffix, never a substring (4:3 also says LANDSCAPE).
    if suffix:
        return await _visible(panel.locator(f"[aria-controls$='-{suffix}']"))
    # Some localized duration groups have unknown labels; retain panel scope.
    if field == "duration":
        controls = panel.locator(_CONTROLS)
        for index in range(min(await controls.count(), 40)):
            control = controls.nth(index)
            if (await control.is_visible() and not await control.locator(_CONTROLS).count()
                    and pattern.fullmatch(await _label(control))):
                return control
    return None


async def _toggle(panel, field, labels, suffix=None, *, verify=False):
    find = lambda: _control(panel, field, labels, suffix)
    try:
        control = await _wait(find)
    except _ControlFailure:
        raise
    except ValueError:
        raise _ControlFailure("control_not_found") from None
    if not await _selected(control):
        if verify:
            raise _ControlFailure("selection_lost")
        if not await control.is_enabled():
            raise _ControlFailure("control_disabled")
        try:
            await control.click(timeout=3000)
        except Exception:
            raise _ControlFailure("control_click_failed") from None

        async def selected():
            current = await find()
            return current if current is not None and await _selected(current) else None

        try:
            await _wait(selected)
        except _ControlFailure:
            raise
        except ValueError:
            raise _ControlFailure("selection_not_confirmed") from None


async def _model(page, panel, *, verify=False):
    dropdown = await _wait(lambda: _visible(panel.locator(
        "button[aria-label='Select model family'], button[aria-haspopup='menu']"
    ).filter(has_text=re.compile(r"Omni|Veo|Banana|Imagen", re.I))))
    if _OMNI.fullmatch(await _label(dropdown)):
        return
    if verify:
        raise ValueError
    await dropdown.click(timeout=3000)

    async def option():
        controlled = await dropdown.get_attribute("aria-controls")
        trigger_id = await dropdown.get_attribute("id")
        menus = page.locator("[role='menu'], [role='listbox']")
        candidates = []
        for index in range(min(await menus.count(), 12)):
            menu = menus.nth(index)
            if not await menu.is_visible():
                continue
            if controlled and await menu.get_attribute("id") != controlled:
                continue
            if not controlled and trigger_id and await menu.get_attribute("aria-labelledby") != trigger_id:
                continue
            items = menu.locator("[role='menuitem'], [role='option'], button")
            for offset in range(min(await items.count(), 30)):
                item = items.nth(offset)
                if await item.is_visible() and _OMNI.fullmatch(await _label(item)):
                    candidates.append(item)
        # With no ARIA relationship, ambiguous menus must not choose arbitrarily.
        return candidates[0] if len(candidates) == 1 else None

    await (await _wait(option)).click(timeout=3000)

    async def confirmed():
        return dropdown if _OMNI.fullmatch(await _label(dropdown)) else None

    await _wait(confirmed)


async def _settings(page, panel, kind, ratio, seconds, mark, *, resolution=None, frames=False, verify=False):
    mark("verify_mode" if verify else "mode")
    await _toggle(panel, "mode", _MODE_LABELS[kind], kind, verify=verify)
    if kind == "VIDEO":
        # Omni renders the duration controls; changing duration before model cannot work.
        mark("verify_model" if verify else "model")
        await _model(page, panel, verify=verify)
        labels = [f"{seconds}{unit}" for unit in ("s", " sec", " seconds", "秒", " 秒", "秒钟", " 秒钟")]
        mark("verify_duration" if verify else "duration")
        await _toggle(panel, "duration", labels, verify=verify)
        if frames:
            mark("submode")
            await _toggle(panel, "submode", ["Frames", "帧", "幀", "首尾帧", "首尾幀"], "VIDEO_FRAMES", verify=verify)
        if resolution:
            mark("resolution")
            await _toggle(panel, "resolution", [resolution, resolution + " info"], verify=verify)
    values = _RATIOS[ratio]
    mark("verify_ratio" if verify else "ratio")
    await _toggle(panel, "ratio", list(values), values[0], verify=verify)
    mark("verify_count" if verify else "count")
    await _toggle(panel, "count", ["x1", "1x"], "content-1", verify=verify)


async def _record_setup_diagnostic(page, phase, failure_reason=None):
    """Record only known UI words/lengths, never original toolbar or page text."""
    snapshot = await page.evaluate(r"""() => {
        const visible = el => !!(el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden');
        const buttons = [...document.querySelectorAll('button')].filter(el => visible(el) &&
            /Video|Image|Omni|Veo|Banana|Imagen|图片|视频/i.test(el.innerText || '')).slice(0, 16);
        const words = /Omni(?:[\s-]+1\.1)?\s+Flash|Nano\s+Banana(?:\s+(?:2|Pro|Lite))?|Video|Image|Veo|Imagen|图片|视频|crop_(?:16_9|9_16|landscape|portrait|square)|arrow_drop_down|expand_more|(?:16:9|9:16|4:3|3:4|1:1)|(?:x[1-4]|[1-4]x)|(?:360|720|1080)p|(?:10|[468])\s*(?:seconds|sec|s|秒钟|秒)/gi;
        return {
            settings_visible: [...document.querySelectorAll('flow-prompt-box-settings, .settings-content')].filter(visible).length,
            panels: [...document.querySelectorAll('flow-prompt-box-settings, .settings-content, .cdk-overlay-pane, [role="menu"], [role="dialog"], [role="listbox"]')].filter(visible).slice(0, 16).map(el => ({
                tag: el.tagName.toLowerCase(),
                classes: [...el.classList].slice(0, 12).map(c => /^[a-z][a-z0-9_-]{0,79}$/i.test(c) ? c : `<class:${c.length}>`),
                role: ['menu','dialog','listbox','radiogroup','tablist'].includes(el.getAttribute('role')) ? el.getAttribute('role') : null,
                expanded: ['true','false'].includes(el.getAttribute('aria-expanded')) ? el.getAttribute('aria-expanded') : null,
                hidden: ['true','false'].includes(el.getAttribute('aria-hidden')) ? el.getAttribute('aria-hidden') : null,
                state: ['open','closed','active','inactive'].includes(el.getAttribute('data-state')) ? el.getAttribute('data-state') : null
            })),
            candidates: buttons.map(el => {
                const text = el.innerText || '', shape = [], sample = text.slice(0, 2000);
                let end = 0;
                for (const match of sample.matchAll(words)) {
                    if (match.index > end) shape.push(`<string:${match.index-end}>`);
                    shape.push(match[0].toLowerCase().replace(/\s+/g, ' '));
                    end = match.index + match[0].length;
                }
                if (end < text.length) shape.push(`<string:${text.length-end}>`);
                return {text_shape: shape.join(''), text_length: text.length,
                    count_word_match: /(?:\bx[1-4]\b|\b[1-4]x\b)/i.test(text),
                    count_numeric_match: /(?:x[1-4](?!\d)|(?<!\d)[1-4]x)/i.test(text)};
            })
        };
    }""")
    directory = Path(__file__).resolve().parents[2] / "local"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    # The caller supplies a page owned by this service, never an AdsPower tab.
    # Screenshots stay local because account UI can be present in the viewport.
    try:
        screenshot = await page.screenshot(timeout=1500)
        screenshot_path = directory / f"native-generation-setup-{phase}-{time.time_ns()}.png"
        descriptor = os.open(screenshot_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(screenshot)
        snapshot["screenshot"] = screenshot_path.name
    except Exception:
        snapshot["screenshot"] = None
    path = directory / "native-generation-setup-diagnostics.jsonl"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(json.dumps({"time": time.time(), "phase": phase, "failure_reason": failure_reason,
                                 **snapshot}, ensure_ascii=False) + "\n")


async def configure_native_generation(page, *, kind, aspect_ratio, model_key=None, duration=None, resolution=None, frames=False) -> None:
    """Confirm selected controls and save; the native request guard verifies the wire spec."""
    try:
        kind, ratio, seconds = _spec(kind, aspect_ratio, model_key, duration)
        if resolution is not None and resolution not in {"360p", "720p"}:
            raise ValueError
        if frames and kind != "VIDEO":
            raise ValueError
    except Exception:
        raise BrowserCaptchaError("native_generation_setup", "invalid_spec") from None

    phase = "open"

    def mark(value):
        nonlocal phase
        phase = value

    async def configure():
        panel = await _open(page, mark)
        await _settings(page, panel, kind, ratio, seconds, mark, resolution=resolution, frames=frames)
        # Later controls can reset an earlier choice. Verify all selected states
        # together before Save, without reopening the transient panel afterward.
        await _settings(page, panel, kind, ratio, seconds, mark, resolution=resolution, frames=frames, verify=True)
        mark("save")
        save = await _visible(panel.locator("button").filter(
            has_text=re.compile(r"^\s*(?:Save|保存|应用|Simpan)\s*$", re.I)))
        if save is not None:
            await save.click(timeout=3000)
        else:
            await page.keyboard.press("Escape")

        async def closed():
            return True if await _panel(page) is None else None

        await _wait(closed)

    try:
        await asyncio.wait_for(configure(), timeout=_TIMEOUT_SECONDS)
    except Exception as error:
        # Selector diagnostics can contain page URLs/account names; never return them.
        try:
            await asyncio.wait_for(_record_setup_diagnostic(
                page, phase, error.reason if isinstance(error, _ControlFailure) else None,
            ), timeout=2)
        except Exception:
            pass
        raise BrowserCaptchaError("native_generation_setup", f"{phase}_failed") from None
