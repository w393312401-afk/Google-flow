"""Upload supplied bytes through the owned Flow page's explicit frame slots."""

import asyncio
import hashlib
import io
import re
import time
import uuid
import os
import json
from pathlib import Path

from PIL import Image

from .captcha_errors import BrowserCaptchaError
from .native_generation_setup import _record_setup_diagnostic, _visible


_FRAME_STATE = """() => {
    const visible = el => !!(el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden');
    const slots = [...document.querySelectorAll('flow-ingredient-bar .frame-trigger')].filter(visible);
    if (slots.length !== 2) return null;
    return slots.map(slot => {
        const imgs = [...slot.querySelectorAll('img')].filter(visible);
        if (!imgs.length) return '';
        const ids = [...new Set(imgs.map(img => (img.currentSrc || img.src || '').match(
            /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i)?.[1] || '').filter(Boolean))];
        return ids.length === 1 ? ids[0] : null;
    });
}"""


def validate_frame_images(images, mode):
    expected = {"text": 0, "start": 1, "start_end": 2}.get(mode)
    if expected is None or not isinstance(images, list) or len(images) != expected:
        raise BrowserCaptchaError("native_frame_prepare", "frame_count_invalid")
    files = []
    for index, content in enumerate(images):
        try:
            if not isinstance(content, bytes) or not 0 < len(content) <= 20 * 1024 * 1024:
                raise ValueError
            with Image.open(io.BytesIO(content)) as image:
                fmt = image.format
                if fmt not in {"PNG", "JPEG", "WEBP"}:
                    raise ValueError
                image.verify()
            mime, extension = {"PNG": ("image/png", "png"), "JPEG": ("image/jpeg", "jpg"),
                               "WEBP": ("image/webp", "webp")}[fmt]
            role = "first" if index == 0 else "last"
            files.append({"name": f"flow2api-{role}-{hashlib.sha256(content).hexdigest()[:16]}-{uuid.uuid4().hex[:8]}.{extension}",
                          "mimeType": mime, "buffer": content})
        except Exception:
            raise BrowserCaptchaError("native_frame_prepare", "frame_image_invalid") from None
    return files


async def _state(page):
    state = await page.evaluate(_FRAME_STATE)
    if not isinstance(state, list) or len(state) != 2 or any(value is None for value in state):
        return None
    return state


async def _confirm_crop(page):
    # An upload may ask the user to crop before it binds to the selected slot.
    # Only a visible dialog's exact confirmation action is eligible.
    dialogs = page.locator("[role='dialog'], mat-dialog-container")
    for index in range(min(await dialogs.count(), 8)):
        dialog = dialogs.nth(index)
        if not await dialog.is_visible():
            continue
        action = await _visible(dialog.locator("button").filter(
            has_text=re.compile(r"^\s*(?:Save|Crop and save|Crop|Done|保存|裁剪并保存|完成)\s*$", re.I)))
        if action is not None and await action.is_enabled():
            await action.click(timeout=2500)
            return True
    return False


async def _accept_upload_rights(page):
    # An account's first upload is held behind a rights attestation and never
    # reaches the picker until it is accepted. Only a visible dialog with this
    # exact title is eligible, and only its exact agree action.
    dialogs = page.locator("[role='dialog'], mat-dialog-container, .cdk-overlay-pane").filter(
        has_text=re.compile(r"Rights to use this image", re.I))
    action = await _visible(dialogs.locator("button").filter(
        has_text=re.compile(r"^\s*I agree\s*$", re.I)))
    if action is None or not await action.is_enabled():
        return False
    try:
        await action.click(timeout=2500)
    except Exception:
        # The dialog can close between the visibility check and the click. The
        # binding loop looks again on its next pass.
        return False
    return True


async def _mount_uploaded_asset(page, file, target_index=0, forbidden_ids=None):
    """Select this upload by its unique filename, then verify the preview UUID."""
    stem = file["name"].rsplit(".", 1)[0]
    viewports = page.locator(".asset-list-viewport:visible")
    if await viewports.count() != 1:
        return None
    viewport = viewports.first
    # Flow can omit the extension in its asset title. Both accepted names are
    # exact: a recycled virtual row with this name plus a suffix is not ours.
    candidates = viewport.get_by_text(re.compile(
        r"^\s*(?:" + re.escape(file["name"]) + "|" + re.escape(stem) + r")\s*$"
    ))
    visible = []
    for index in range(min(await candidates.count(), 8)):
        candidate = candidates.nth(index)
        if await candidate.is_visible():
            visible.append(candidate)
    if len(visible) != 1:
        return None
    candidate = visible[0]
    media_id = await candidate.evaluate("""el => {
        const viewport=el.closest('.asset-list-viewport');
        let row=el;
        while(row && row!==viewport) {
            const ids=[...new Set([...row.querySelectorAll('img')].map(img => {
                const uuid=/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
                const requested=(img.src || '').match(uuid)?.[1], current=(img.currentSrc || '').match(uuid)?.[1];
                // A failed thumbnail fetch must not hide a uniquely named
                // uploaded asset. Identity comes from its stable URL, not image
                // decoding. Still reject a virtual row showing an older src.
                return requested && requested===current ? current:null;
            }).filter(Boolean))];
            if(ids.length===1) return ids[0];
            if(ids.length>1) return null;
            row=row.parentElement;
        }
        return null;
    }""")
    if not media_id or media_id in set(forbidden_ids or []):
        return None
    async def bound():
        state = await _state(page)
        return bool(state and state[target_index] == media_id)

    async def preview_state():
        # This is deliberately a document read. locator.evaluate waits up to
        # 30 seconds when the picker closes during a successful direct binding.
        return await page.evaluate("""() => {
            const visible=el=>!!(el.getClientRects().length && getComputedStyle(el).visibility!=='hidden');
            const viewports=[...document.querySelectorAll('.asset-list-viewport')].filter(visible);
            if(viewports.length!==1) return null;
            const viewport=viewports[0], overlay=viewport.closest('.cdk-overlay-pane, [role="dialog"]');
            if(!overlay) return null;
            const images=[...overlay.querySelectorAll('img')].filter(img=>!viewport.contains(img) && visible(img));
            return [...new Set(images.map(img => (img.currentSrc || img.src || '').match(
                /([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i)?.[1]).filter(Boolean))];
        }""")

    selected = await preview_state()
    if selected != [media_id]:
        await candidate.click(timeout=2500)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if await bound():
                return media_id
            selected = await preview_state()
            if selected == [media_id]:
                break
            if selected is None:
                return None
            await asyncio.sleep(0.1)
        else:
            return None
    if await bound():
        return media_id
    # A still-open picker must display this exact upload before confirmation.
    if selected != [media_id]:
        return None
    overlays = page.locator(".cdk-overlay-pane:visible, [role='dialog']:visible").filter(has=viewport)
    overlay = await _visible(overlays)
    if overlay is None:
        return media_id if await bound() else None
    add = await _visible(overlay.get_by_role("button", name=re.compile(r"^Add to prompt$|^添加到提示词$", re.I)))
    if add is None or not await add.is_enabled():
        return media_id if await bound() else None
    try:
        await add.click(timeout=3000)
    except Exception:
        if not await bound():
            raise
    return media_id

async def upload_native_frames(page, spec, progress=None):
    """Bind one file at a time and retain its semantic first/last media ID."""
    files = spec["frame_files"]
    phase = "frame_slots"
    file = None
    def mark(value):
        nonlocal phase
        phase = value
        if callable(progress):
            progress("native_" + value)
    try:
        before = await _state(page)
        if before != ["", ""]:
            raise BrowserCaptchaError("native_frame_upload", "initial_slots_not_empty")
        expected = list(before)
        for index, file in enumerate(files):
            mark(f"frame_{index + 1}_open")
            slots = page.locator("flow-ingredient-bar .frame-trigger:visible")
            if await slots.count() != 2:
                raise ValueError
            await slots.nth(index).locator("button").first.click(timeout=4000)
            mark(f"frame_{index + 1}_chooser")
            actions = page.locator("flow-menu-item, [role='menuitem'], button[mat-menu-item], button").filter(
                has_text=re.compile(r"^\s*(?:upload\s*)?(?:Upload|Upload image|Upload media|上传|上传图片|上传媒体|上传媒体内容)\s*$", re.I))
            deadline = time.monotonic() + 5
            action = None
            while time.monotonic() < deadline and action is None:
                action = await _visible(actions)
                if action is None:
                    await asyncio.sleep(0.1)
            if action is None:
                raise ValueError
            # The chooser comes only from this explicit slot menu. Never use a
            # global file input, which can belong to canvas or another frame.
            existing_ids = await page.evaluate("""() => [...new Set([...document.querySelectorAll('img')].flatMap(img =>
                [...(img.src || '').matchAll(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ig)].map(m=>m[0])))]""")
            async with page.expect_file_chooser(timeout=5000) as chooser:
                await action.click(timeout=4000)
            await (await chooser.value).set_files(file, timeout=15000)
            mark(f"frame_{index + 1}_binding")
            deadline = time.monotonic() + 100
            mounted_media = None
            while time.monotonic() < deadline:
                current = await _state(page)
                if current is not None:
                    other = 1 - index
                    if current[other] != expected[other]:
                        raise BrowserCaptchaError("native_frame_upload", "other_slot_changed")
                    if current[index] and mounted_media:
                        if current[index] != mounted_media:
                            raise BrowserCaptchaError("native_frame_upload", "uploaded_asset_mismatch")
                        expected[index] = current[index]
                        mark(f"frame_{index + 1}_bound")
                        try:
                            await _record_frame_identity(page, file, index, mounted_media, spec)
                        except Exception:
                            pass
                        break
                await _accept_upload_rights(page)
                await _confirm_crop(page)
                if mounted_media is None:
                    forbidden = set(existing_ids)
                    if index and file["buffer"] == files[0]["buffer"]:
                        # Exact same user bytes may legitimately deduplicate.
                        forbidden.discard(expected[0])
                    elif index:
                        forbidden.add(expected[0])
                    mounted_media = await _mount_uploaded_asset(page, file, target_index=index, forbidden_ids=forbidden)
                await asyncio.sleep(0.2)
            else:
                raise ValueError
        if await _state(page) != expected:
            raise BrowserCaptchaError("native_frame_upload", "frame_binding_changed")
        spec["frame_media_ids"] = expected[:len(files)]
    except BrowserCaptchaError:
        try:
            await _record_upload_diagnostic(page, phase, file)
        except Exception:
            pass
        raise
    except Exception:
        try:
            await _record_upload_diagnostic(page, phase, file)
        except Exception:
            pass
        raise BrowserCaptchaError("native_frame_upload", f"{phase}_failed") from None


async def _record_upload_diagnostic(page, phase, file):
    await _record_setup_diagnostic(page, phase)
    stem = file["name"].rsplit(".", 1)[0] if file else ""
    data = await page.evaluate("""stem => {
        const visible=el=>!!(el.getClientRects().length && getComputedStyle(el).visibility!=='hidden');
        const uuid=/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
        const image=img=>({visible:visible(img), has_uuid:uuid.test(img.currentSrc || img.src || ''),
            source_type:(img.currentSrc || img.src || '').split(':')[0]});
        const info=el=>({tag:el.tagName.toLowerCase(),role:el.getAttribute('role'),
            classes:[...el.classList].filter(x=>/^[a-z0-9_-]{1,80}$/i.test(x)),
            images:[...el.querySelectorAll('img')].slice(0,4).map(image)});
        const viewports=[...document.querySelectorAll('.asset-list-viewport')].filter(visible);
        return {viewport_count:viewports.length, viewports:viewports.map(viewport=>({
            matches:[...viewport.querySelectorAll('*')].filter(el=>visible(el) && stem &&
                (el.textContent || '').includes(stem) && ![...el.children].some(c=>(c.textContent || '').includes(stem)))
                .slice(0,4).map(el=>({parents:[el,el.parentElement,el.parentElement?.parentElement].filter(Boolean).map(info)})),
            preview_images:[...(viewport.closest('.cdk-overlay-pane, [role="dialog"]')?.querySelectorAll('img') || [])]
                .filter(img=>!viewport.contains(img)).slice(0,8).map(image)
        }))};
    }""", stem)
    path = Path(__file__).resolve().parents[2] / "local" / "native-frame-upload-diagnostics.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "a") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(json.dumps({"time": time.time(), "phase": phase, **data}) + "\n")


async def _record_frame_identity(page, file, index, media_id, spec):
    """Capture URL structure and equality facts, never signed URLs or IDs."""
    if not spec.get("_project_id"):
        return
    data = await page.evaluate("""({project,id}) => {
        const uuid=/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ig;
        const inspect=img=>{
            const raw=img.currentSrc || img.src || '', matches=[...raw.matchAll(uuid)].map(m=>m[0]);
            let path='', keys=[];
            try{const url=new URL(raw); path=url.pathname.split('/').map(part=>
                /^(?:content|image|video|media|projects|v1|v2)$/.test(part)?part:
                (/^[0-9a-f-]{36}$/i.test(part)?'<uuid>':(part?'<segment:'+part.length+'>':''))).join('/');
                keys=[...url.searchParams.keys()].map(key=>/^[a-zA-Z0-9_-]{1,50}$/.test(key)?key:'<key>');}catch{}
            const current=(img.currentSrc || '').match(uuid)||[], source=(img.src || '').match(uuid)||[];
            return {uuid_count:matches.length, first_uuid_is_project:matches[0]===project,
                chosen_uuid_occurrences:matches.filter(value=>value===id).length,
                current_source_uuid_match:JSON.stringify(current)===JSON.stringify(source),
                complete:img.complete, width:img.naturalWidth, path, query_keys:keys};
        };
        return {slots:[...document.querySelectorAll('flow-ingredient-bar .frame-trigger')].slice(0,2)
            .map(slot=>[...slot.querySelectorAll('img')].slice(0,2).map(inspect))};
    }""", {"project": spec.get("_project_id"), "id": media_id})
    path = Path(__file__).resolve().parents[2] / "local" / "native-frame-identity-diagnostics.jsonl"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "a") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(json.dumps({"time": time.time(), "frame": index + 1,
                                "input_hash": hashlib.sha256(file["buffer"]).hexdigest()[:16], **data}) + "\n")
