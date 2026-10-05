"""Validate and continue the page's single native text-to-video request."""

import json
import math
import hashlib
import re
import os
import time
from pathlib import Path
from urllib.parse import parse_qs

from .captcha_errors import BrowserCaptchaError
from .flow_frontend import FlowFrontendMixin
from .native_image_submission import _nonempty_string, _submit_native_generation
from .native_frame_upload import validate_frame_images, upload_native_frames


def _payload_shape(value, depth=5):
    """A bounded schema diagnostic containing no string values or identifiers."""
    if isinstance(value, list):
        if depth <= 0:
            return f"a{len(value)}"
        return (f"a{len(value)}[" + ",".join(_payload_shape(item, depth - 1) for item in value[:16]) + "]")[:600]
    if value is None:
        return "z"
    if isinstance(value, bool):
        return "b"
    if isinstance(value, str):
        return "s"
    if isinstance(value, (int, float)):
        return "n"
    return "o" if isinstance(value, dict) else "?"


def _validate_video_spec(spec):
    try:
        if not isinstance(spec, dict) or not all(
            _nonempty_string(spec.get(key)) for key in ("prompt", "model_key", "website_key", "aspect_ratio")
        ):
            raise ValueError
        mode = spec.get("mode", "text")
        family = "t2v" if mode == "text" else "i2v"
        if mode not in {"text", "start", "start_end"} or not re.fullmatch(rf"abra_{family}_(?:4|6|8|10)s", spec["model_key"]):
            raise ValueError
        resolution = spec.get("resolution")
        if resolution not in {None, "360p", "720p"}:
            raise ValueError
        frame_files = validate_frame_images(spec.get("frame_images", []), mode)
        aspect = spec["aspect_ratio"].strip().upper()
        aliases = {
            "16:9": "VIDEO_ASPECT_RATIO_LANDSCAPE", "LANDSCAPE": "VIDEO_ASPECT_RATIO_LANDSCAPE",
            "9:16": "VIDEO_ASPECT_RATIO_PORTRAIT", "PORTRAIT": "VIDEO_ASPECT_RATIO_PORTRAIT",
            "1:1": "VIDEO_ASPECT_RATIO_SQUARE", "SQUARE": "VIDEO_ASPECT_RATIO_SQUARE",
        }
        aspect = aliases.get(aspect, aspect)
        if aspect not in {
            "VIDEO_ASPECT_RATIO_LANDSCAPE", "VIDEO_ASPECT_RATIO_PORTRAIT", "VIDEO_ASPECT_RATIO_SQUARE",
        }:
            raise ValueError
        ratio = FlowFrontendMixin._map_frontend_video_aspect_ratio(aspect)
        return dict(spec, ratio=ratio, mode=mode, frame_files=frame_files, resolution=resolution)
    except BrowserCaptchaError:
        raise
    except Exception:
        raise BrowserCaptchaError("native_request_prepare", "video_spec_invalid") from None


def _expected_native_model(spec):
    """Map only the native key formats observed for the selected UI settings."""
    model = spec["model_key"]
    if spec.get("resolution") != "360p":
        return model, False
    mode = spec.get("mode", "text")
    if mode == "start_end":
        seconds = re.fullmatch(r"abra_i2v_(4|6|8|10)s", model).group(1)
        return f"omni_flash_i2v_{seconds}s_first_last_360p", True
    if mode in {"text", "start"}:
        return model + "_360p", True
    return model, False


def _verify_video_request(post_data, project_id, spec):
    """Recognize the known YhhmEf schema and preserve the original wire body."""
    reason = "video_form_invalid"
    argument = None
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
        mode = spec.get("mode", "text")
        rpc_id = {"text": "YhhmEf", "start": "eb1hJf", "start_end": "nprQif"}[mode]
        if not isinstance(rpc, list) or len(rpc) != 4 or rpc[0] != rpc_id:
            raise ValueError
        reason = "video_argument_shape_invalid"
        argument = json.loads(rpc[1])
        if mode != "text" or spec.get("resolution"):
            _record_wire_shape(argument, spec, rpc_id)
        if not isinstance(argument, list) or len(argument) != 3:
            raise ValueError
        requests, context, submission = argument
        reason = "video_count_mismatch"
        if not isinstance(requests, list) or len(requests) != 1:
            raise ValueError
        reason = "video_context_invalid"
        if (
            not isinstance(context, list) or len(context) != 11
            or context[5] not in {project_id, f"projects/{project_id}"}
            or not isinstance(context[10], list) or len(context[10]) != 2
            or not _nonempty_string(context[10][0]) or context[10][1] != 1
        ):
            raise ValueError
        reason = "video_submission_shape_invalid"
        if (
            not isinstance(submission, list) or len(submission) != 2
            or not _nonempty_string(submission[0]) or submission[1] != 2
        ):
            raise ValueError
        reason = "video_request_shape_invalid"
        request = requests[0]
        # Native requests observed on the wire omit the optional output tail.
        # Keep the known full form too; other lengths still require evidence.
        lengths = {"text": (5, 8), "start": (6, 10), "start_end": (7, 9)}[mode]
        if not isinstance(request, list) or len(request) not in lengths:
            raise ValueError
        if request[3] is not None or (mode == "text" and len(request) == 8 and request[5] is not None):
            raise ValueError
        # Metadata/output specification/resolution remain opaque and untouched.
        # In particular, their session IDs need not equal the submission ID.
        reason = "video_model_mismatch"
        expected_model, encoded_resolution = _expected_native_model(spec)
        if request[1] != expected_model:
            raise ValueError
        reason = "video_aspect_mismatch"
        if type(request[2]) is not int or request[2] != spec["ratio"]:
            raise ValueError
        reason = "video_prompt_shape_invalid"
        prompt_message = request[0]
        if (
            not isinstance(prompt_message, list) or len(prompt_message) != 3
            or prompt_message[0] is not None or prompt_message[1] is not None
        ):
            raise ValueError
        prompt = prompt_message[2]
        for _ in range(3):
            if not isinstance(prompt, list) or len(prompt) != 1:
                raise ValueError
            prompt = prompt[0]
        reason = "video_prompt_mismatch"
        if prompt != spec["prompt"]:
            raise ValueError
        if mode in {"start", "start_end"}:
            reason = "video_frame_binding_mismatch"
            frame_ids = spec.get("frame_media_ids", [])
            expected_count = 2 if mode == "start_end" else 1
            if len(frame_ids) != expected_count or not all(_nonempty_string(value) for value in frame_ids):
                raise ValueError
            images = spec.get("frame_images", [])
            if (expected_count == 2 and len(images) == 2 and images[0] != images[1]
                    and frame_ids[0] == frame_ids[1]):
                raise ValueError
            for index, media_id in enumerate(frame_ids):
                reference = request[4 + index]
                if (not isinstance(reference, list) or len(reference) not in {2, 6}
                        or reference[0] is not None or reference[1] != media_id):
                    raise ValueError
                if len(reference) == 6:
                    if reference[2:5] != [None, None, None]:
                        raise ValueError
                    crop = reference[5]
                    if not isinstance(crop, list) or len(crop) != 4:
                        raise ValueError
                    if any(value is not None and (type(value) not in {int, float}
                            or not math.isfinite(value) or not 0 <= value <= 1) for value in crop):
                        raise ValueError
        if encoded_resolution and mode in {"text", "start"}:
            reason = "video_resolution_shape_mismatch"
            tail = 7 if mode == "text" else 9
            nullable = (5, 6) if mode == "text" else (6, 7, 8)
            if len(request) != tail + 1 or request[tail] != [4] or any(request[index] is not None for index in nullable):
                raise ValueError
        if spec.get("resolution") and not encoded_resolution:
            reason = "video_resolution_mismatch"
            resolution_index = {"text": 7, "start": 9, "start_end": None}[mode]
            actual_resolution = request[resolution_index] if resolution_index is not None and len(request) > resolution_index else None
            expected_resolution = {"360p": 1, "720p": 2}[spec["resolution"]]
            # Native 720p omits the resolution tail; 360p must be explicit.
            if actual_resolution != expected_resolution and not (expected_resolution == 2 and actual_resolution is None):
                raise ValueError
        # None instructs the shared runner to call continue_() without overrides.
        return None, submission[0]
    except Exception:
        error = BrowserCaptchaError("native_request_parse", reason)
        error.payload_shape = _payload_shape(argument)
        raise error from None


async def submit_native_video(
    browser, context, project_id: str, spec: dict, timeout: float, *, on_generation_sent=None,
) -> dict:
    validated = _validate_video_spec(spec)
    mode = validated["mode"]
    return await _submit_native_generation(
        browser, context, project_id, validated, timeout,
        kind="VIDEO", rpc_id={"text": "YhhmEf", "start": "eb1hJf", "start_end": "nprQif"}[mode],
        prepare_request=_verify_video_request,
        prepare_frames=upload_native_frames if mode != "text" else None,
        on_generation_sent=on_generation_sent,
    )


def _record_wire_shape(argument, spec, rpc_id):
    """Private diagnostic strips all opaque strings, including auth and prompts."""
    def redact(value, depth=0):
        if depth > 10:
            return "<depth>"
        if isinstance(value, list):
            return [redact(item, depth + 1) for item in value[:40]]
        if isinstance(value, str):
            for index, media_id in enumerate(spec.get("frame_media_ids", [])):
                if value == media_id:
                    return f"<frame-{index + 1}>"
            if re.fullmatch(r"(?:abra|veo|omni|video|gemini)[a-zA-Z0-9_.:-]{1,100}", value, re.I):
                return value
            return "<string>"
        if value is None or isinstance(value, (int, float, bool)):
            return value
        return "<object>"
    directory = Path(__file__).resolve().parents[2] / "local"
    path = directory / "native-frame-wire-diagnostics.jsonl"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "a") as output:
            os.fchmod(output.fileno(), 0o600)
            native_key = argument[0][0][1] if (isinstance(argument, list) and argument and isinstance(argument[0], list) and argument[0] and isinstance(argument[0][0], list) and len(argument[0][0]) > 1) else None
            safe_key = native_key if isinstance(native_key, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", native_key) else None
            output.write(json.dumps({"time": time.time(), "rpc": rpc_id, "native_model_key": safe_key, "expected_native_model_key": _expected_native_model(spec)[0], "model_key_matches": native_key == _expected_native_model(spec)[0], "mode": spec.get("mode"),
                                     "resolution": spec.get("resolution"), "input_hashes": [hashlib.sha256(value).hexdigest()[:16] for value in spec.get("frame_images", [])], "same_frame_ids": len(set(spec.get("frame_media_ids", []))) < len(spec.get("frame_media_ids", [])), "argument": redact(argument)}) + "\n")
    except OSError:
        pass
