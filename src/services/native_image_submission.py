"""Submit one generation through the original Flow page and its native request."""

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from .captcha_errors import BrowserCaptchaError
from .flow_frontend import FlowFrontendMixin
from .native_prompt import read_native_prompt


_FLOW_ROUTE = "https://flow.google.com/**"
_NATIVE_FLOW_ROUTE = re.compile(r"^https://flow\.google\.com/")
_GENERATION_RPCS = frozenset(
    {"ogiZ0b", "YhhmEf", "MZZa6b", "nprQif", "eb1hJf", "fZytfe", "p0UkFb", "SPrCad"}
)
_SUBMISSION_DIAGNOSTIC_PATH = (
    Path(__file__).resolve().parents[2] / "local" / "native-submission-diagnostics.jsonl"
)


def _browser_failure_kind(error: Exception) -> str:
    """Inspect private browser text only to select a fixed, safe category."""
    message = str(error).lower()
    for needle, category in (
        ("target page, context or browser has been closed", "browser_closed"),
        ("target closed", "browser_closed"),
        ("page has been closed", "browser_closed"),
        ("not attached", "element_detached"),
        ("element was detached", "element_detached"),
        ("intercepts pointer events", "click_intercepted"),
        ("not enabled", "submit_disabled"),
        ("trusted", "trusted_types"),
        ("content security policy", "content_security_policy"),
    ):
        if needle in message:
            return category
    # Playwright's TimeoutError is not the built-in/asyncio TimeoutError.
    if (isinstance(error, (asyncio.TimeoutError, TimeoutError))
            or type(error).__name__ == "TimeoutError" or "timeout" in message):
        return "timeout"
    return "browser_operation_failed"


def _safe_error_kind(error: Exception) -> str:
    name = type(error).__name__
    return name if name in {
        "TimeoutError", "Error", "TargetClosedError", "RuntimeError", "TypeError", "ValueError",
        "BrowserCaptchaError",
    } else "other"


def _browser_failure(stage: str, reason: str, error: Exception) -> BrowserCaptchaError:
    failure = BrowserCaptchaError(stage, reason)
    failure.native_error_kind = _safe_error_kind(error)
    failure.native_failure_kind = _browser_failure_kind(error)
    return failure


def _record_submission_diagnostic(diagnostic: dict) -> None:
    """Persist only our fixed fields, with owner-only access and bounded history."""
    try:
        directory = _SUBMISSION_DIAGNOSTIC_PATH.parent
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
        if _SUBMISSION_DIAGNOSTIC_PATH.exists() and _SUBMISSION_DIAGNOSTIC_PATH.stat().st_size > 256_000:
            os.replace(_SUBMISSION_DIAGNOSTIC_PATH, _SUBMISSION_DIAGNOSTIC_PATH.with_suffix(".previous"))
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(_SUBMISSION_DIAGNOSTIC_PATH, flags, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(json.dumps({"time": time.time(), **diagnostic}, ensure_ascii=True) + "\n")
    except OSError:
        # Diagnostics cannot replace the original submission failure.
        pass


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_spec(spec: dict) -> dict:
    try:
        if not isinstance(spec, dict) or not all(
            _nonempty_string(spec.get(key)) for key in ("prompt", "model_name", "website_key")
        ):
            raise ValueError
        ratio = FlowFrontendMixin._map_frontend_image_aspect_ratio(spec.get("aspect_ratio"))
        inputs = spec.get("image_inputs")
        if inputs is None:
            inputs = []
        if not isinstance(inputs, list):
            raise ValueError
        references = []
        for item in inputs:
            if not isinstance(item, dict):
                raise ValueError
            name = item.get("name") or item.get("mediaId")
            if not _nonempty_string(name):
                raise ValueError
            references.append([name.strip(), None, None, None, 1])
        return dict(spec, ratio=ratio, references=references or None)
    except Exception:
        raise BrowserCaptchaError("native_request_prepare", "image_spec_invalid") from None


def _request_rpcs(url: str, post_data: str) -> set[str]:
    parsed = urlparse(url)
    if "StreamChat" in parsed.path:
        return {"StreamChat"}
    if not parsed.path.endswith("/batchexecute"):
        return set()
    rpc_ids = {
        rpc for group in parse_qs(parsed.query).get("rpcids", [])
        for rpc in group.split(",") if rpc
    }
    try:
        payload = json.loads(parse_qs(post_data, keep_blank_values=True)["f.req"][0])
        for batch in payload:
            for row in batch:
                if isinstance(row, list) and row and isinstance(row[0], str):
                    rpc_ids.add(row[0])
    except Exception:
        # No opaque batchexecute request may slip through an armed submitter.
        rpc_ids.add("unrecognized_batch")
    return rpc_ids


def _patch_image_request(post_data: str, project_id: str, spec: dict) -> tuple[str, str]:
    """Patch the observed 14-field request, preserving its native auth envelope."""
    reason = "image_form_invalid"
    try:
        fields = parse_qs(post_data, keep_blank_values=True)
        if len(fields.get("f.req", [])) != 1 or len(fields.get("at", [])) != 1:
            raise ValueError
        if not _nonempty_string(fields["at"][0]):
            raise ValueError
        reason = "rpc_envelope_invalid"
        envelope = json.loads(fields["f.req"][0])
        if not isinstance(envelope, list) or len(envelope) != 1:
            raise ValueError
        batch = envelope[0]
        if not isinstance(batch, list) or len(batch) != 1:
            raise ValueError
        rpc = batch[0]
        if not isinstance(rpc, list) or len(rpc) != 4 or rpc[0] != "ogiZ0b":
            raise ValueError
        reason = "argument_shape_invalid"
        argument = json.loads(rpc[1])
        if not isinstance(argument, list) or len(argument) != 5 or argument[0] is not None:
            raise ValueError
        requests, count, context, sessions = argument[1:]
        reason = "request_list_invalid"
        if not isinstance(requests, list) or not requests or type(count) is not int:
            raise ValueError
        reason = "session_mismatch"
        if not isinstance(sessions, list) or len(sessions) != 1 or not _nonempty_string(sessions[0]):
            raise ValueError
        session_id = sessions[0]

        def valid_context(value):
            return (
                isinstance(value, list) and len(value) == 11
                and value[5] in {project_id, f"projects/{project_id}"}
                and isinstance(value[10], list) and len(value[10]) == 2
                and _nonempty_string(value[10][0]) and value[10][1] == 1
            )

        reason = "context_mismatch"
        if not valid_context(context):
            raise ValueError
        for request in requests:
            reason = "request_shape_invalid"
            if not isinstance(request, list) or len(request) != 14:
                raise ValueError
            if any(request[index] is not None for index in (0, 1, 6, 9, 10, 11)):
                raise ValueError
            if type(request[3]) is not int or type(request[4]) is not int:
                raise ValueError
            if not _nonempty_string(request[5]):
                raise ValueError
            reason = "context_mismatch"
            if not valid_context(request[7]) or request[7] != context:
                raise ValueError
            reason = "session_mismatch"
            if not _nonempty_string(request[12]):
                raise ValueError
            reason = "request_shape_invalid"
            if not _nonempty_string(request[13]):
                raise ValueError
            reason = "prompt_shape_invalid"
            prompt = request[8]
            for _ in range(3):
                if not isinstance(prompt, list) or len(prompt) != 1:
                    raise ValueError
                prompt = prompt[0]
            if not isinstance(prompt, str):
                raise ValueError
            reason = "reference_shape_invalid"
            if request[2] is not None and not isinstance(request[2], list):
                raise ValueError

        # Keep the native seed, client contexts, session, request UUID, transport
        # envelope and XSRF fields. The older 15-field builder is incompatible.
        first = requests[0]
        first[2] = spec["references"]
        first[4] = spec["ratio"]
        first[5] = spec["model_name"]
        first[8] = [[[spec["prompt"]]]]
        argument[1] = [first]
        rpc[1] = json.dumps(argument, ensure_ascii=False, separators=(",", ":"))
        fields["f.req"] = [json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))]
        return urlencode(fields, doseq=True), session_id
    except Exception:
        raise BrowserCaptchaError("native_request_parse", reason) from None


async def submit_native_image(
    browser, context, project_id: str, spec: dict, timeout: float, *, on_generation_sent=None,
) -> dict:
    return await _submit_native_generation(
        browser, context, project_id, _validate_spec(spec), timeout,
        kind="IMAGE", rpc_id="ogiZ0b", prepare_request=_patch_image_request,
        on_generation_sent=on_generation_sent,
    )


async def _configure_generation(page, *, kind, aspect_ratio, model_key=None, **options):
    from .native_generation_setup import configure_native_generation

    await configure_native_generation(
        page, kind=kind, aspect_ratio=aspect_ratio, model_key=model_key, **options,
    )


_SUBMIT_CONTROL = (
    "button[aria-label='Start generation']:visible, "
    "button[aria-label='开始生成']:visible, "
    "button[aria-label='開始生成']:visible"
)


async def _prepare_submit_control(page):
    """Prove the localized submit control is actionable before arming the guard."""
    control = page.locator(_SUBMIT_CONTROL).first
    try:
        await control.wait_for(state="visible", timeout=8000)
    except Exception as error:
        raise _browser_failure("native_submit_prepare", "submit_control_missing", error) from None
    try:
        # A trial click waits for enabled state and overlay/layout stability but
        # never dispatches the click. Failure here is still proven unsubmitted.
        await control.click(trial=True, timeout=8000)
    except Exception as error:
        raise _browser_failure("native_submit_prepare", "submit_control_not_ready", error) from None
    return control


async def _submit_native_generation(
    browser, context, project_id: str, spec: dict, timeout: float,
    *, kind: str, rpc_id: str, prepare_request, prepare_frames=None, on_generation_sent=None,
) -> dict:
    """Use one owned page; the caller owns browser/account locks and the context."""
    if not _nonempty_string(project_id):
        raise BrowserCaptchaError("native_request_prepare", "project_invalid")
    page = None
    stage = "native_page_creation"
    stopping = False
    armed = False
    admitted = False
    forwarding_started = False
    request_forwarded = False
    submit_attempts = 0
    failure = None
    click_warning = None
    started_at = time.monotonic()
    selected_request = None
    session_id = None
    route_failure = None
    request_ready = asyncio.Event()

    def set_stage(value):
        nonlocal stage
        stage = value
        browser._record_captcha_stage(value)

    def fail_route(reason, failure_stage="native_request_interception", payload_shape=None):
        nonlocal route_failure
        if route_failure is None:
            route_failure = BrowserCaptchaError(failure_stage, reason)
            if payload_shape:
                browser._record_captcha_stage(failure_stage, reason, payload_shape=payload_shape)
            else:
                browser._record_captcha_stage(failure_stage, reason)
        request_ready.set()

    async def abort(route):
        try:
            await route.abort()
        except Exception:
            fail_route("request_abort_failed")
            # A failed abort must never fall back to continuation.
            try:
                await asyncio.wait_for(page.close(), timeout=3)
            except Exception:
                pass

    async def native_route(route):
        nonlocal admitted, selected_request, session_id, stopping, forwarding_started, request_forwarded
        request = route.request
        if request.method != "POST":
            await route.continue_()
            return
        post_data = request.post_data or ""
        rpc_ids = _request_rpcs(request.url, post_data)
        generation = rpc_ids & (_GENERATION_RPCS | {"StreamChat", "unrecognized_batch"})
        if not generation:
            await route.continue_()
            return
        if stopping or not armed or admitted or route_failure is not None:
            await abort(route)
            return
        if rpc_ids != {rpc_id}:
            browser._record_captcha_stage("native_request_interception", "unexpected_generation_rpc",
                                          harvest_rpc=next(iter(rpc_ids)) if len(rpc_ids) == 1 else None)
            stopping = True
            await abort(route)
            fail_route("unexpected_generation_rpc")
            return
        try:
            body, session_id = prepare_request(post_data, project_id, spec)
        except BrowserCaptchaError as error:
            stopping = True
            await abort(route)
            fail_route(error.reason, error.stage, getattr(error, "payload_shape", None))
            return
        # Set the guard before the first await so simultaneous UI submissions
        # cannot admit a second billable request.
        admitted = True
        selected_request = request
        try:
            if on_generation_sent is not None:
                await on_generation_sent()
            # A click/deadline failure can close the owned page while the
            # callback is awaiting bookkeeping. Never forward after that stop.
            if stopping:
                await abort(route)
                return
            # continue_ can send the request and then raise on a disconnect.
            # Mark the uncertainty before awaiting it, never after success.
            forwarding_started = True
            if body is None:
                await route.continue_()
            else:
                await route.continue_(post_data=body)
            request_forwarded = True
        except Exception:
            await abort(route)
            fail_route("request_continue_failed")
            return
        request_ready.set()

    async def run():
        nonlocal page, armed, submit_attempts, click_warning
        set_stage("native_page_creation")
        page = await browser._new_page(context)
        await browser._apply_browser_environment_patch(page, label=f"native_{kind.lower()}_page")
        set_stage("native_page_prepare")
        for prepare_attempt in range(2):
            try:
                ready = await browser._prepare_flow_runtime_page(
                    page, project_id, spec["website_key"], f"{kind}_GENERATION",
                    context_label=f"native {kind.lower()} submission",
                )
                break
            except BrowserCaptchaError as error:
                # This only reloads the owned page before configuration, uploads,
                # or submission. Never retry a potentially billable request.
                retryable = error.reason in {
                    "proxy_connection_failed", "network_connection_failed", "network_empty_response",
                    "connection_closed", "navigation_failed", "recaptcha_unavailable",
                } or (error.stage == "navigation" and error.reason in {"navigation_interrupted", "timeout"})
                if prepare_attempt or not retryable:
                    raise
                set_stage("native_page_prepare_retry")
                await asyncio.sleep(1)

        if not ready:
            raise BrowserCaptchaError(stage, "flow_page_unavailable")

        set_stage("native_route_registration")
        # Install the new guard first. Its distinct matcher lets us remove only
        # this page's old harvest route without leaving an unguarded await gap.
        await page.route(_NATIVE_FLOW_ROUTE, native_route)
        await page.unroute(_FLOW_ROUTE)
        await browser._dismiss_flow_overlays(page)
        set_stage("native_generation_setup")
        setup_options = {}
        if spec.get("resolution"):
            setup_options["resolution"] = spec["resolution"]
        if spec.get("mode") in {"start", "start_end"}:
            setup_options["frames"] = True
        await _configure_generation(
            page, kind=kind, aspect_ratio=spec["aspect_ratio"],
            model_key=spec.get("model_key") if kind == "VIDEO" else None,
            **setup_options,
        )
        set_stage("native_editor_input")
        editor = page.locator(".ProseMirror:visible").first
        await editor.wait_for(timeout=15000)
        await editor.fill(spec["prompt"], timeout=4000)
        if await read_native_prompt(editor) != spec["prompt"]:
            raise BrowserCaptchaError(stage, "prompt_input_mismatch")
        if prepare_frames is not None:
            set_stage("native_frame_upload")
            spec["_project_id"] = project_id
            await prepare_frames(page, spec, progress=set_stage)
            # Uploading must not change the submitted prompt.
            if await read_native_prompt(editor) != spec["prompt"]:
                raise BrowserCaptchaError(stage, "prompt_changed_during_upload")
        for submit_attempts in range(1, 3):
            set_stage("native_submit_prepare")
            submit_control = await _prepare_submit_control(page)
            set_stage("native_submit")
            armed = True
            try:
                await submit_control.click(timeout=8000, no_wait_after=True)
                break
            except Exception as error:
                failure_kind = _browser_failure_kind(error)
                if admitted:
                    # Clicking can dispatch the generation and then fail while
                    # the UI rerenders/navigates. Observe that original request
                    # instead of losing its response or clicking a second time.
                    click_warning = _browser_failure("native_submit", failure_kind, error)
                    browser._record_captcha_stage("native_submit", failure_kind)
                    break
                # Reacquire and preflight once after an actionability race.
                # The same gate still permits at most one generation request.
                if (submit_attempts == 1 and not admitted and not forwarding_started
                        and route_failure is None and failure_kind in {
                            "timeout", "element_detached", "click_intercepted", "submit_disabled",
                        }):
                    armed = False
                    browser._record_captcha_stage("native_submit", failure_kind)
                    await browser._dismiss_flow_overlays(page)
                    continue
                raise _browser_failure("native_submit", failure_kind, error) from None
        set_stage("native_request_interception")
        await request_ready.wait()
        if route_failure:
            raise route_failure
        set_stage("native_response")
        response = await selected_request.response()
        if response is None:
            raise BrowserCaptchaError(stage, "response_missing")
        status = getattr(response, "status", 200)
        if type(status) is int and 400 <= status <= 599:
            raise BrowserCaptchaError(stage, f"upstream_http_{status}")
        response_text = await response.text()
        if route_failure:
            raise route_failure
        if not isinstance(response_text, str) or not response_text:
            raise BrowserCaptchaError(stage, "response_empty")
        set_stage("native_complete")
        return {"rpc": rpc_id, "response_text": response_text, "session_id": session_id}

    try:
        return await asyncio.wait_for(run(), timeout=max(0.001, float(timeout)))
    except BrowserCaptchaError as error:
        failure = error
        raise
    except Exception as error:
        failure = _browser_failure(stage, _browser_failure_kind(error), error)
        raise failure from None
    finally:
        stopping = True
        page_closed = page is None
        # Keep the rejecting route installed until the owned page is closed,
        # including during timeout/cancellation and response parsing failures.
        if page is not None:
            async def close_owned_page():
                nonlocal page_closed
                try:
                    await asyncio.wait_for(page.close(), timeout=3)
                    page_closed = True
                except Exception:
                    try:
                        page_closed = page.is_closed() is True
                    except Exception:
                        pass

            # A caller deadline can fire while the inner deadline is already
            # cleaning up. Do not cancel close or release the browser slot early.
            cleanup = asyncio.create_task(close_owned_page())
            cancelled = False
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    cancelled = True
        diagnostic_failure = failure or click_warning
        if diagnostic_failure is not None:
            # A button click is not acceptance evidence. Once cleanup has
            # closed the guarded page, no continue_ started means no billable
            # generation was sent. An uncertain close remains pending.
            if failure is not None:
                failure.submission_pending = False if not forwarding_started and page_closed else None
            diagnostic = {
                "stage": stage, "reason": diagnostic_failure.reason,
                "error_kind": getattr(diagnostic_failure, "native_error_kind", "BrowserCaptchaError"),
                "failure_kind": getattr(diagnostic_failure, "native_failure_kind", diagnostic_failure.reason),
                "armed": armed, "request_admitted": admitted,
                "forwarding_started": forwarding_started, "request_forwarded": request_forwarded,
                "page_closed": page_closed, "submit_attempts": submit_attempts,
                "elapsed_ms": round((time.monotonic() - started_at) * 1000),
            }
            token_id = getattr(browser, "token_id", None)
            if type(token_id) is int:
                diagnostic["token_id"] = token_id
            if failure is not None:
                failure.native_submission_diagnostic = diagnostic
            else:
                diagnostic["recovered"] = True
            _record_submission_diagnostic(diagnostic)
        if page is not None and cancelled:
            raise asyncio.CancelledError
