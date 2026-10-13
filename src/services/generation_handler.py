"""Generation handler for Flow2API"""

import asyncio
import base64
import json
import re
import time
from copy import deepcopy
from contextlib import aclosing
from pathlib import Path
from typing import Optional, AsyncGenerator, List, Dict, Any
from ..core.logger import debug_logger
from ..core.config import config
from ..core.monitoring import record_generation_result
from ..core.models import Task, RequestLog
from ..core.account_tiers import (
    PAYGATE_TIER_NOT_PAID,
    get_paygate_tier_label,
    get_required_paygate_tier_for_model,
    normalize_user_paygate_tier,
    supports_model_for_tier,
)
from .file_cache import FileCache
from .captcha_errors import BrowserCaptchaError
from .flow_frontend import FlowRPCRejected
from .submission_ledger import SubmissionLedger
from ..core.account_admission import AccountAdmissionBusy


# Model configuration
MODEL_CONFIG = {
    # 图片生成 - GEM_PIX_2 (Gemini 3.0 Pro)
    "gemini-3.0-pro-image-landscape": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE",
    },
    "gemini-3.0-pro-image-portrait": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT",
    },
    "gemini-3.0-pro-image-square": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_SQUARE",
    },
    "gemini-3.0-pro-image-four-three": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE",
    },
    "gemini-3.0-pro-image-three-four": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT_THREE_FOUR",
    },
    # 图片生成 - GEM_PIX_2 (Gemini 3.0 Pro) 2K 放大版
    "gemini-3.0-pro-image-landscape-2k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.0-pro-image-portrait-2k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.0-pro-image-square-2k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_SQUARE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.0-pro-image-four-three-2k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.0-pro-image-three-four-2k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT_THREE_FOUR",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    # 图片生成 - GEM_PIX_2 (Gemini 3.0 Pro) 4K 放大版
    "gemini-3.0-pro-image-landscape-4k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    "gemini-3.0-pro-image-portrait-4k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    "gemini-3.0-pro-image-square-4k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_SQUARE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    "gemini-3.0-pro-image-four-three-4k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    "gemini-3.0-pro-image-three-four-4k": {
        "type": "image",
        "model_name": "GEM_PIX_2",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT_THREE_FOUR",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    # 图片生成 - IMAGEN_3_5 (Imagen 4.0)
    "imagen-4.0-generate-preview-landscape": {
        "type": "image",
        "model_name": "IMAGEN_3_5",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE",
    },
    "imagen-4.0-generate-preview-portrait": {
        "type": "image",
        "model_name": "IMAGEN_3_5",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT",
    },
    # 图片生成 - NARWHAL (新版)
    "gemini-3.1-flash-image-landscape": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE",
    },
    "gemini-3.1-flash-image-portrait": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT",
    },
    "gemini-3.1-flash-image-square": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_SQUARE",
    },
    "gemini-3.1-flash-image-four-three": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE",
    },
    "gemini-3.1-flash-image-three-four": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT_THREE_FOUR",
    },
    "gemini-3.1-flash-image-landscape-2k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.1-flash-image-portrait-2k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.1-flash-image-square-2k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_SQUARE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.1-flash-image-four-three-2k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.1-flash-image-three-four-2k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT_THREE_FOUR",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_2K",
    },
    "gemini-3.1-flash-image-landscape-4k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    "gemini-3.1-flash-image-portrait-4k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    "gemini-3.1-flash-image-square-4k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_SQUARE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    "gemini-3.1-flash-image-four-three-4k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_LANDSCAPE_FOUR_THREE",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    "gemini-3.1-flash-image-three-four-4k": {
        "type": "image",
        "model_name": "NARWHAL",
        "aspect_ratio": "IMAGE_ASPECT_RATIO_PORTRAIT_THREE_FOUR",
        "upsample": "UPSAMPLE_IMAGE_RESOLUTION_4K",
    },
    # ========== 文生视频 (T2V - Text to Video) ==========
    # 不支持上传图片，只使用文本提示词生成
    # veo_3_1_t2v_fast_portrait (竖屏)
    # 上游模型名: veo_3_1_t2v_fast_portrait
    "veo_3_1_t2v_fast_portrait": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_portrait",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "use_v2_model_config": True,
    },
    # veo_3_1_t2v_fast_landscape (横屏)
    # 上游模型名: veo_3_1_t2v_fast
    "veo_3_1_t2v_fast_landscape": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "use_v2_model_config": True,
    },
    # veo_3_1_t2v_fast_ultra (横竖屏)
    "veo_3_1_t2v_fast_portrait_ultra": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_portrait_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "use_v2_model_config": True,
    },
    "veo_3_1_t2v_fast_ultra": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "use_v2_model_config": True,
    },
    # veo_3_1_t2v_fast_ultra_relaxed (横竖屏)
    "veo_3_1_t2v_fast_portrait_ultra_relaxed": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_portrait_ultra_relaxed",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "use_v2_model_config": True,
    },
    "veo_3_1_t2v_fast_ultra_relaxed": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_ultra_relaxed",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "use_v2_model_config": True,
    },
    # veo_3_1_t2v (横竖屏)
    "veo_3_1_t2v_portrait": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_portrait",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "use_v2_model_config": True,
    },
    "veo_3_1_t2v_landscape": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "use_v2_model_config": True,
    },
    # veo_3_1_t2v_lite（横竖屏）
    "veo_3_1_t2v_lite_portrait": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_lite",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "use_v2_model_config": True,
        "allow_tier_upgrade": False,
    },
    "veo_3_1_t2v_lite_landscape": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_lite",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "use_v2_model_config": True,
        "allow_tier_upgrade": False,
    },
    # ========== 首尾帧模型 (I2V - Image to Video) ==========
    # 支持1-2张图片：1张作为首帧，2张作为首尾帧
    # veo_3_1_i2v_s_fast_fl (需要新增横竖屏)
    "veo_3_1_i2v_s_fast_portrait_fl": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_portrait_fl",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
    },
    "veo_3_1_i2v_s_fast_fl": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_fl",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
    },
    # veo_3_1_i2v_s_fast_ultra (横竖屏)
    "veo_3_1_i2v_s_fast_portrait_ultra_fl": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_portrait_ultra_fl",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
    },
    "veo_3_1_i2v_s_fast_ultra_fl": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_ultra_fl",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
    },
    # veo_3_1_i2v_s_fast_ultra_relaxed (需要新增横竖屏)
    "veo_3_1_i2v_s_fast_portrait_ultra_relaxed": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_portrait_ultra_relaxed",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
    },
    "veo_3_1_i2v_s_fast_ultra_relaxed": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_ultra_relaxed",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
    },
    # veo_3_1_i2v_s (需要新增横竖屏)
    "veo_3_1_i2v_s_portrait": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
    },
    "veo_3_1_i2v_s_landscape": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
    },
    # veo_3_1_i2v_lite（横竖屏，仅首帧）
    "veo_3_1_i2v_lite_portrait": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_lite",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 1,
        "max_images": 1,
        "use_v2_model_config": True,
        "allow_tier_upgrade": False,
    },
    "veo_3_1_i2v_lite_landscape": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_lite",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 1,
        "max_images": 1,
        "use_v2_model_config": True,
        "allow_tier_upgrade": False,
    },
    # veo_3_1_interpolation_lite（横竖屏，首尾帧）
    "veo_3_1_interpolation_lite_portrait": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_interpolation_lite",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 2,
        "max_images": 2,
        "use_v2_model_config": True,
        "allow_tier_upgrade": False,
    },
    "veo_3_1_interpolation_lite_landscape": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_interpolation_lite",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 2,
        "max_images": 2,
        "use_v2_model_config": True,
        "allow_tier_upgrade": False,
    },
    # ========== 多图生成 (R2V - Reference Images to Video) ==========
    # 当前上游协议最多支持 3 张参考图
    # veo_3_1_r2v_fast (横竖屏)
    "veo_3_1_r2v_fast_portrait": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_portrait",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
    },
    "veo_3_1_r2v_fast": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_landscape",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
    },
    # veo_3_1_r2v_fast_ultra (横竖屏)
    "veo_3_1_r2v_fast_portrait_ultra": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_portrait_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
    },
    "veo_3_1_r2v_fast_ultra": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_landscape_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
    },
    # veo_3_1_r2v_fast_ultra_relaxed (横竖屏)
    "veo_3_1_r2v_fast_portrait_ultra_relaxed": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_portrait_ultra_relaxed",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
    },
    "veo_3_1_r2v_fast_ultra_relaxed": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_landscape_ultra_relaxed",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
    },
    # ========== 视频放大 (Video Upsampler) ==========
    # 仅 3.1 支持，需要先生成视频后再放大，可能需要 30 分钟
    # T2V 4K 放大版
    "veo_3_1_t2v_fast_portrait_4k": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_portrait",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_4K",
            "model_key": "veo_3_1_upsampler_4k",
        },
    },
    "veo_3_1_t2v_fast_4k": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_4K",
            "model_key": "veo_3_1_upsampler_4k",
        },
    },
    "veo_3_1_t2v_fast_portrait_ultra_4k": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_portrait_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_4K",
            "model_key": "veo_3_1_upsampler_4k",
        },
    },
    "veo_3_1_t2v_fast_ultra_4k": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_4K",
            "model_key": "veo_3_1_upsampler_4k",
        },
    },
    # T2V 1080P 放大版
    "veo_3_1_t2v_fast_portrait_1080p": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_portrait",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_1080P",
            "model_key": "veo_3_1_upsampler_1080p",
        },
    },
    "veo_3_1_t2v_fast_1080p": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_1080P",
            "model_key": "veo_3_1_upsampler_1080p",
        },
    },
    "veo_3_1_t2v_fast_portrait_ultra_1080p": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_portrait_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_1080P",
            "model_key": "veo_3_1_upsampler_1080p",
        },
    },
    "veo_3_1_t2v_fast_ultra_1080p": {
        "type": "video",
        "video_type": "t2v",
        "model_key": "veo_3_1_t2v_fast_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_1080P",
            "model_key": "veo_3_1_upsampler_1080p",
        },
    },
    # I2V 4K 放大版
    "veo_3_1_i2v_s_fast_portrait_ultra_fl_4k": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_portrait_ultra_fl",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_4K",
            "model_key": "veo_3_1_upsampler_4k",
        },
    },
    "veo_3_1_i2v_s_fast_ultra_fl_4k": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_ultra_fl",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_4K",
            "model_key": "veo_3_1_upsampler_4k",
        },
    },
    # I2V 1080P 放大版
    "veo_3_1_i2v_s_fast_portrait_ultra_fl_1080p": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_portrait_ultra_fl",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_1080P",
            "model_key": "veo_3_1_upsampler_1080p",
        },
    },
    "veo_3_1_i2v_s_fast_ultra_fl_1080p": {
        "type": "video",
        "video_type": "i2v",
        "model_key": "veo_3_1_i2v_s_fast_ultra_fl",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 1,
        "max_images": 2,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_1080P",
            "model_key": "veo_3_1_upsampler_1080p",
        },
    },
    # R2V 4K 放大版
    "veo_3_1_r2v_fast_portrait_ultra_4k": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_portrait_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_4K",
            "model_key": "veo_3_1_upsampler_4k",
        },
    },
    "veo_3_1_r2v_fast_ultra_4k": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_landscape_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_4K",
            "model_key": "veo_3_1_upsampler_4k",
        },
    },
    # R2V 1080P 放大版
    "veo_3_1_r2v_fast_portrait_ultra_1080p": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_portrait_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_1080P",
            "model_key": "veo_3_1_upsampler_1080p",
        },
    },
    "veo_3_1_r2v_fast_ultra_1080p": {
        "type": "video",
        "video_type": "r2v",
        "model_key": "veo_3_1_r2v_fast_landscape_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
        "upsample": {
            "resolution": "VIDEO_RESOLUTION_1080P",
            "model_key": "veo_3_1_upsampler_1080p",
        },
    },
    # ========== 视频续写 (Extend - Video Continuation) ==========
    # 基于已生成的视频续写7秒，最多续写20次（最长148秒）
    # 需要提供源视频的 mediaGenerationId
    # VEO 3.1 Extend (横竖屏)
    "veo_3_1_extend_portrait": {
        "type": "video",
        "video_type": "extend",
        "model_key": "veo_3_1_extend_fast_portrait_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": False,
        "requires_video_id": True,
    },
    "veo_3_1_extend": {
        "type": "video",
        "video_type": "extend",
        "model_key": "veo_3_1_extend_fast_ultra",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": False,
        "requires_video_id": True,
    },
    # ========== Gemini Omni Flash ==========
    # 2026-05-26 实测上游真实请求：
    # - 纯文本 -> YhhmEf, videoModelKey=abra_t2v_8s
    # - 参考图 -> MZZa6b, videoModelKey=abra_r2v_8s
    "omni": {
        "type": "video",
        "video_type": "omni",
        "model_key": "abra_t2v_8s",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_LANDSCAPE",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
        "use_v2_model_config": True,
        "allow_tier_upgrade": False,
        "reference_model_key": "abra_r2v_8s",
        "reference_duration": 8,
        "reference_model_display_name": "Omni Flash",
    },
    "omni_portrait": {
        "type": "video",
        "video_type": "omni",
        "model_key": "abra_t2v_8s",
        "aspect_ratio": "VIDEO_ASPECT_RATIO_PORTRAIT",
        "supports_images": True,
        "min_images": 0,
        "max_images": 3,
        "use_v2_model_config": True,
        "allow_tier_upgrade": False,
        "reference_model_key": "abra_r2v_8s",
        "reference_duration": 8,
        "reference_model_display_name": "Omni Flash",
    },
}


def _make_t2v_config(
    model_key: str,
    aspect_ratio: str,
    *,
    use_v2_model_config: bool = False,
    allow_tier_upgrade: bool = True,
    upsample: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "type": "video",
        "video_type": "t2v",
        "model_key": model_key,
        "aspect_ratio": aspect_ratio,
        "supports_images": False,
    }
    if use_v2_model_config:
        cfg["use_v2_model_config"] = True
    if not allow_tier_upgrade:
        cfg["allow_tier_upgrade"] = False
    if upsample:
        cfg["upsample"] = upsample
    return cfg


def _make_i2v_config(
    model_key: str,
    aspect_ratio: str,
    *,
    min_images: int = 1,
    max_images: int = 2,
    use_v2_model_config: bool = False,
    allow_tier_upgrade: bool = True,
    upsample: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "type": "video",
        "video_type": "i2v",
        "model_key": model_key,
        "aspect_ratio": aspect_ratio,
        "supports_images": True,
        "min_images": min_images,
        "max_images": max_images,
    }
    if use_v2_model_config:
        cfg["use_v2_model_config"] = True
    if not allow_tier_upgrade:
        cfg["allow_tier_upgrade"] = False
    if upsample:
        cfg["upsample"] = upsample
    return cfg


def _apply_veo_3_1_model_updates():
    """Keep the public aliases aligned with the current Veo 3.1 model families."""
    landscape = "VIDEO_ASPECT_RATIO_LANDSCAPE"
    portrait = "VIDEO_ASPECT_RATIO_PORTRAIT"

    def add_alias(alias: str, target: str):
        MODEL_CONFIG[alias] = dict(MODEL_CONFIG[target])

    def add_default_duration_aliases(
        base_alias: str,
        landscape_target: str,
        portrait_target: str,
        *,
        fl_suffix: bool = False,
    ):
        if fl_suffix:
            add_alias(f"{base_alias}_8s_fl", landscape_target)
            add_alias(f"{base_alias}_portrait_8s_fl", portrait_target)
            add_alias(f"{base_alias}_landscape_8s_fl", landscape_target)
            return

        add_alias(f"{base_alias}_8s", landscape_target)
        add_alias(f"{base_alias}_portrait_8s", portrait_target)
        add_alias(f"{base_alias}_landscape_8s", landscape_target)

    def add_default_duration_upsample_aliases(
        base_alias: str,
        resolution_name: str,
        landscape_target: str,
        portrait_target: str,
    ):
        add_alias(f"{base_alias}_8s_{resolution_name}", landscape_target)
        add_alias(f"{base_alias}_portrait_8s_{resolution_name}", portrait_target)
        add_alias(f"{base_alias}_landscape_8s_{resolution_name}", landscape_target)

    # Non-fast/non-lite Veo 3.1 aliases must call Quality upstream keys.
    MODEL_CONFIG["veo_3_1_t2v_landscape"].update({"model_key": "veo_3_1_t2v"})
    MODEL_CONFIG["veo_3_1_t2v_portrait"].update({"model_key": "veo_3_1_t2v_portrait"})
    MODEL_CONFIG["veo_3_1_i2v_s_landscape"].update({"model_key": "veo_3_1_i2v_s_fl"})
    MODEL_CONFIG["veo_3_1_i2v_s_portrait"].update(
        {"model_key": "veo_3_1_i2v_s_portrait_fl"}
    )
    MODEL_CONFIG["veo_3_1_extend"].update({"model_key": "veo_3_1_extend_landscape"})
    MODEL_CONFIG["veo_3_1_extend_portrait"].update(
        {"model_key": "veo_3_1_extend_portrait"}
    )

    for seconds in (4, 6):
        suffix = f"{seconds}s"

        # T2V duration variants.
        MODEL_CONFIG[f"veo_3_1_t2v_fast_{suffix}"] = _make_t2v_config(
            f"veo_3_1_t2v_fast_{suffix}", landscape
        )
        MODEL_CONFIG[f"veo_3_1_t2v_fast_portrait_{suffix}"] = _make_t2v_config(
            f"veo_3_1_t2v_fast_{suffix}", portrait
        )
        MODEL_CONFIG[f"veo_3_1_t2v_lite_{suffix}_landscape"] = _make_t2v_config(
            f"veo_3_1_t2v_lite_{suffix}",
            landscape,
            use_v2_model_config=True,
            allow_tier_upgrade=False,
        )
        MODEL_CONFIG[f"veo_3_1_t2v_lite_{suffix}_portrait"] = _make_t2v_config(
            f"veo_3_1_t2v_lite_{suffix}",
            portrait,
            use_v2_model_config=True,
            allow_tier_upgrade=False,
        )
        MODEL_CONFIG[f"veo_3_1_t2v_{suffix}"] = _make_t2v_config(
            f"veo_3_1_t2v_quality_{suffix}", landscape
        )
        MODEL_CONFIG[f"veo_3_1_t2v_portrait_{suffix}"] = _make_t2v_config(
            f"veo_3_1_t2v_quality_{suffix}", portrait
        )

        # I2V duration variants. FL keys are used for 2 images; the single-image path strips "_fl".
        MODEL_CONFIG[f"veo_3_1_i2v_s_fast_{suffix}_fl"] = _make_i2v_config(
            f"veo_3_1_i2v_s_fast_{suffix}_fl", landscape
        )
        MODEL_CONFIG[f"veo_3_1_i2v_s_fast_portrait_{suffix}_fl"] = _make_i2v_config(
            f"veo_3_1_i2v_s_fast_{suffix}_fl", portrait
        )
        MODEL_CONFIG[f"veo_3_1_i2v_lite_{suffix}_landscape"] = _make_i2v_config(
            f"veo_3_1_i2v_s_lite_{suffix}",
            landscape,
            min_images=1,
            max_images=1,
            use_v2_model_config=True,
            allow_tier_upgrade=False,
        )
        MODEL_CONFIG[f"veo_3_1_i2v_lite_{suffix}_portrait"] = _make_i2v_config(
            f"veo_3_1_i2v_s_lite_{suffix}",
            portrait,
            min_images=1,
            max_images=1,
            use_v2_model_config=True,
            allow_tier_upgrade=False,
        )
        MODEL_CONFIG[f"veo_3_1_interpolation_lite_{suffix}_landscape"] = (
            _make_i2v_config(
            f"veo_3_1_i2v_s_lite_{suffix}_fl",
            landscape,
            min_images=2,
            max_images=2,
            use_v2_model_config=True,
            allow_tier_upgrade=False,
        )
        )
        MODEL_CONFIG[f"veo_3_1_interpolation_lite_{suffix}_portrait"] = (
            _make_i2v_config(
            f"veo_3_1_i2v_s_lite_{suffix}_fl",
            portrait,
            min_images=2,
            max_images=2,
            use_v2_model_config=True,
            allow_tier_upgrade=False,
        )
        )
        MODEL_CONFIG[f"veo_3_1_i2v_s_{suffix}"] = _make_i2v_config(
            f"veo_3_1_i2v_s_quality_{suffix}_fl", landscape
        )
        MODEL_CONFIG[f"veo_3_1_i2v_s_portrait_{suffix}"] = _make_i2v_config(
            f"veo_3_1_i2v_s_quality_{suffix}_fl", portrait
        )

        for resolution_name, resolution, upsampler_model_key in (
            ("4k", "VIDEO_RESOLUTION_4K", "veo_3_1_upsampler_4k"),
            ("1080p", "VIDEO_RESOLUTION_1080P", "veo_3_1_upsampler_1080p"),
        ):
            upsample = {"resolution": resolution, "model_key": upsampler_model_key}
            MODEL_CONFIG[f"veo_3_1_t2v_{suffix}_{resolution_name}"] = _make_t2v_config(
                f"veo_3_1_t2v_quality_{suffix}", landscape, upsample=upsample
            )
            MODEL_CONFIG[f"veo_3_1_t2v_portrait_{suffix}_{resolution_name}"] = (
                _make_t2v_config(
                f"veo_3_1_t2v_quality_{suffix}", portrait, upsample=upsample
            )
            )
            MODEL_CONFIG[f"veo_3_1_i2v_s_{suffix}_{resolution_name}"] = (
                _make_i2v_config(
                f"veo_3_1_i2v_s_quality_{suffix}_fl", landscape, upsample=upsample
            )
            )
            MODEL_CONFIG[f"veo_3_1_i2v_s_portrait_{suffix}_{resolution_name}"] = (
                _make_i2v_config(
                f"veo_3_1_i2v_s_quality_{suffix}_fl", portrait, upsample=upsample
            )
            )

    for resolution_name, resolution, upsampler_model_key in (
        ("4k", "VIDEO_RESOLUTION_4K", "veo_3_1_upsampler_4k"),
        ("1080p", "VIDEO_RESOLUTION_1080P", "veo_3_1_upsampler_1080p"),
    ):
        upsample = {"resolution": resolution, "model_key": upsampler_model_key}
        MODEL_CONFIG[f"veo_3_1_t2v_{resolution_name}"] = _make_t2v_config(
            "veo_3_1_t2v", landscape, upsample=upsample
        )
        MODEL_CONFIG[f"veo_3_1_t2v_portrait_{resolution_name}"] = _make_t2v_config(
            "veo_3_1_t2v_portrait", portrait, upsample=upsample
        )
        MODEL_CONFIG[f"veo_3_1_i2v_s_{resolution_name}"] = _make_i2v_config(
            "veo_3_1_i2v_s_fl", landscape, upsample=upsample
        )
        MODEL_CONFIG[f"veo_3_1_i2v_s_portrait_{resolution_name}"] = _make_i2v_config(
            "veo_3_1_i2v_s_portrait_fl", portrait, upsample=upsample
        )

    for seconds in (4, 6):
        suffix = f"{seconds}s"

        # Explicit landscape names for /v1/models; short landscape names remain compatible.
        add_alias(f"veo_3_1_t2v_fast_landscape_{suffix}", f"veo_3_1_t2v_fast_{suffix}")
        add_alias(f"veo_3_1_t2v_landscape_{suffix}", f"veo_3_1_t2v_{suffix}")
        add_alias(
            f"veo_3_1_i2v_s_fast_landscape_{suffix}_fl",
            f"veo_3_1_i2v_s_fast_{suffix}_fl",
        )
        add_alias(f"veo_3_1_i2v_s_landscape_{suffix}", f"veo_3_1_i2v_s_{suffix}")

        add_alias(
            f"veo_3_1_t2v_lite_landscape_{suffix}",
            f"veo_3_1_t2v_lite_{suffix}_landscape",
        )
        add_alias(
            f"veo_3_1_t2v_lite_portrait_{suffix}", f"veo_3_1_t2v_lite_{suffix}_portrait"
        )
        add_alias(
            f"veo_3_1_i2v_lite_landscape_{suffix}",
            f"veo_3_1_i2v_lite_{suffix}_landscape",
        )
        add_alias(
            f"veo_3_1_i2v_lite_portrait_{suffix}", f"veo_3_1_i2v_lite_{suffix}_portrait"
        )
        add_alias(
            f"veo_3_1_interpolation_lite_landscape_{suffix}",
            f"veo_3_1_interpolation_lite_{suffix}_landscape",
        )
        add_alias(
            f"veo_3_1_interpolation_lite_portrait_{suffix}",
            f"veo_3_1_interpolation_lite_{suffix}_portrait",
        )

        for resolution_name in ("4k", "1080p"):
            add_alias(
                f"veo_3_1_t2v_landscape_{suffix}_{resolution_name}",
                f"veo_3_1_t2v_{suffix}_{resolution_name}",
            )
            add_alias(
                f"veo_3_1_i2v_s_landscape_{suffix}_{resolution_name}",
                f"veo_3_1_i2v_s_{suffix}_{resolution_name}",
            )

    for resolution_name in ("4k", "1080p"):
        add_alias(
            f"veo_3_1_t2v_landscape_{resolution_name}", f"veo_3_1_t2v_{resolution_name}"
        )
        add_alias(
            f"veo_3_1_i2v_s_landscape_{resolution_name}",
            f"veo_3_1_i2v_s_{resolution_name}",
        )

    add_alias("veo_3_1_r2v_fast_landscape", "veo_3_1_r2v_fast")
    add_alias("veo_3_1_r2v_fast_landscape_ultra", "veo_3_1_r2v_fast_ultra")
    add_alias(
        "veo_3_1_r2v_fast_landscape_ultra_relaxed", "veo_3_1_r2v_fast_ultra_relaxed"
    )
    add_alias("veo_3_1_r2v_fast_landscape_ultra_4k", "veo_3_1_r2v_fast_ultra_4k")
    add_alias("veo_3_1_r2v_fast_landscape_ultra_1080p", "veo_3_1_r2v_fast_ultra_1080p")

    add_default_duration_aliases(
        "veo_3_1_t2v_fast",
        "veo_3_1_t2v_fast_landscape",
        "veo_3_1_t2v_fast_portrait",
    )
    add_default_duration_aliases(
        "veo_3_1_t2v",
        "veo_3_1_t2v_landscape",
        "veo_3_1_t2v_portrait",
    )
    add_default_duration_aliases(
        "veo_3_1_i2v_s_fast",
        "veo_3_1_i2v_s_fast_fl",
        "veo_3_1_i2v_s_fast_portrait_fl",
        fl_suffix=True,
    )
    add_default_duration_aliases(
        "veo_3_1_i2v_s",
        "veo_3_1_i2v_s_landscape",
        "veo_3_1_i2v_s_portrait",
    )
    add_default_duration_aliases(
        "veo_3_1_r2v_fast",
        "veo_3_1_r2v_fast",
        "veo_3_1_r2v_fast_portrait",
    )
    add_alias("veo_3_1_r2v_fast_ultra_8s", "veo_3_1_r2v_fast_ultra")
    add_alias("veo_3_1_r2v_fast_portrait_ultra_8s", "veo_3_1_r2v_fast_portrait_ultra")
    add_alias("veo_3_1_r2v_fast_landscape_ultra_8s", "veo_3_1_r2v_fast_ultra")
    add_alias(
        "veo_3_1_r2v_fast_ultra_relaxed_8s",
        "veo_3_1_r2v_fast_ultra_relaxed",
    )
    add_alias(
        "veo_3_1_r2v_fast_portrait_ultra_relaxed_8s",
        "veo_3_1_r2v_fast_portrait_ultra_relaxed",
    )
    add_alias(
        "veo_3_1_r2v_fast_landscape_ultra_relaxed_8s",
        "veo_3_1_r2v_fast_ultra_relaxed",
    )

    add_alias("veo_3_1_t2v_lite_8s_landscape", "veo_3_1_t2v_lite_landscape")
    add_alias("veo_3_1_t2v_lite_8s_portrait", "veo_3_1_t2v_lite_portrait")
    add_alias("veo_3_1_t2v_lite_landscape_8s", "veo_3_1_t2v_lite_landscape")
    add_alias("veo_3_1_t2v_lite_portrait_8s", "veo_3_1_t2v_lite_portrait")
    add_alias("veo_3_1_i2v_lite_8s_landscape", "veo_3_1_i2v_lite_landscape")
    add_alias("veo_3_1_i2v_lite_8s_portrait", "veo_3_1_i2v_lite_portrait")
    add_alias("veo_3_1_i2v_lite_landscape_8s", "veo_3_1_i2v_lite_landscape")
    add_alias("veo_3_1_i2v_lite_portrait_8s", "veo_3_1_i2v_lite_portrait")
    add_alias(
        "veo_3_1_interpolation_lite_8s_landscape",
        "veo_3_1_interpolation_lite_landscape",
    )
    add_alias(
        "veo_3_1_interpolation_lite_8s_portrait",
        "veo_3_1_interpolation_lite_portrait",
    )
    add_alias(
        "veo_3_1_interpolation_lite_landscape_8s",
        "veo_3_1_interpolation_lite_landscape",
    )
    add_alias(
        "veo_3_1_interpolation_lite_portrait_8s",
        "veo_3_1_interpolation_lite_portrait",
    )

    for resolution_name in ("4k", "1080p"):
        add_default_duration_upsample_aliases(
            "veo_3_1_t2v",
            resolution_name,
            f"veo_3_1_t2v_{resolution_name}",
            f"veo_3_1_t2v_portrait_{resolution_name}",
        )
        add_default_duration_upsample_aliases(
            "veo_3_1_i2v_s",
            resolution_name,
            f"veo_3_1_i2v_s_{resolution_name}",
            f"veo_3_1_i2v_s_portrait_{resolution_name}",
        )


_apply_veo_3_1_model_updates()


def _apply_current_flow_model_catalog():
    """Expose the current Flow model families while retaining hidden legacy aliases."""
    landscape = "VIDEO_ASPECT_RATIO_LANDSCAPE"
    portrait = "VIDEO_ASPECT_RATIO_PORTRAIT"

    for config_entry in MODEL_CONFIG.values():
        config_entry["listed"] = False

    # NARWHAL remains the current image-generation RPC model. Older image
    # aliases continue to resolve but no longer clutter the public catalog.
    for model_id, config_entry in MODEL_CONFIG.items():
        if (
            config_entry.get("type") == "image"
            and config_entry.get("model_name") == "NARWHAL"
        ):
            config_entry["listed"] = True
            config_entry["display_name"] = "Flow Image - NARWHAL"

    def register(model_id: str, config_entry: Dict[str, Any], display_name: str):
        config_entry = dict(config_entry)
        config_entry["listed"] = True
        config_entry["display_name"] = display_name
        MODEL_CONFIG[model_id] = config_entry

    def t2v(model_key: str, aspect_ratio: str) -> Dict[str, Any]:
        return _make_t2v_config(
            model_key,
            aspect_ratio,
            use_v2_model_config=True,
            allow_tier_upgrade=False,
        )

    def i2v(model_key: str, aspect_ratio: str, max_images: int = 2) -> Dict[str, Any]:
        return _make_i2v_config(
            model_key,
            aspect_ratio,
            min_images=1,
            max_images=max_images,
            use_v2_model_config=True,
            allow_tier_upgrade=False,
        )

    def r2v(model_key: str, aspect_ratio: str) -> Dict[str, Any]:
        return {
            "type": "video",
            "video_type": "r2v",
            "model_key": model_key,
            "aspect_ratio": aspect_ratio,
            "supports_images": True,
            "min_images": 1,
            "max_images": 3,
            "use_v2_model_config": True,
            "allow_tier_upgrade": False,
        }

    def extend(model_key: str, aspect_ratio: str) -> Dict[str, Any]:
        return {
            "type": "video",
            "video_type": "extend",
            "model_key": model_key,
            "aspect_ratio": aspect_ratio,
            "supports_images": False,
            "use_v2_model_config": True,
            "allow_tier_upgrade": False,
        }

    # Veo 3.1 Lite. 实测 2026-09：Pro 账号对 lite 全系（含 *_low_priority 变体）
    # 均返回 MODEL_ACCESS_DENIED，veo 系需更高级别订阅；key 保持上游默认值。
    for seconds, key in (
        (4, "veo_3_1_t2v_lite_4s"),
        (6, "veo_3_1_t2v_lite_6s"),
        (8, "veo_3_1_t2v_lite"),
    ):
        for orientation, ratio in (("landscape", landscape), ("portrait", portrait)):
            register(
                f"veo-3.1-lite-{seconds}s-{orientation}",
                t2v(key, ratio),
                f"Veo 3.1 - Lite · {seconds}s · {orientation}",
            )

    # Veo 3.1 Fast. Current 4s/6s consumer access uses relaxed usage keys.
    for seconds, landscape_key, portrait_key in (
        (4, "veo_3_1_t2v_fast_4s_relaxed", "veo_3_1_t2v_fast_4s_relaxed"),
        (6, "veo_3_1_t2v_fast_6s_relaxed", "veo_3_1_t2v_fast_6s_relaxed"),
        (8, "veo_3_1_t2v_fast", "veo_3_1_t2v_fast_portrait"),
    ):
        register(
            f"veo-3.1-fast-{seconds}s-landscape",
            t2v(landscape_key, landscape),
            f"Veo 3.1 - Fast · {seconds}s · landscape",
        )
        register(
            f"veo-3.1-fast-{seconds}s-portrait",
            t2v(portrait_key, portrait),
            f"Veo 3.1 - Fast · {seconds}s · portrait",
        )

    # Veo 3.1 Quality.
    for seconds, landscape_key, portrait_key in (
        (4, "veo_3_1_t2v_quality_4s", "veo_3_1_t2v_quality_4s"),
        (6, "veo_3_1_t2v_quality_6s", "veo_3_1_t2v_quality_6s"),
        (8, "veo_3_1_t2v", "veo_3_1_t2v_portrait"),
    ):
        register(
            f"veo-3.1-quality-{seconds}s-landscape",
            t2v(landscape_key, landscape),
            f"Veo 3.1 - Quality · {seconds}s · landscape",
        )
        register(
            f"veo-3.1-quality-{seconds}s-portrait",
            t2v(portrait_key, portrait),
            f"Veo 3.1 - Quality · {seconds}s · portrait",
        )

    # Omni 1.1 Flash (upstream family key: abra). This is verified by a live
    # generation using abra_t2v_4s.
    for seconds in (4, 6, 8, 10):
        for orientation, ratio in (("landscape", landscape), ("portrait", portrait)):
            register(
                f"omni-1.1-flash-{seconds}s-{orientation}",
                {
                    "type": "video",
                    "video_type": "omni",
                    "model_key": f"abra_t2v_{seconds}s",
                    "reference_model_key": f"abra_r2v_{seconds}s",
                    "reference_duration": seconds,
                    "aspect_ratio": ratio,
                    "supports_images": True,
                    "min_images": 0,
                    "max_images": 3,
                    "use_v2_model_config": True,
                    "allow_tier_upgrade": False,
                },
                f"Omni 1.1 Flash · {seconds}s · {orientation}",
            )

    # Explicit native Frames models keep first/last semantics separate from
    # Omni Ingredients/R2V, and expose the requested resolution without defaults.
    for seconds in (4, 6, 8, 10):
        for orientation, ratio in (("landscape", landscape), ("portrait", portrait)):
            for resolution in ("360p", "720p"):
                register(
                    f"omni-1.1-flash-frames-{seconds}s-{orientation}-{resolution}",
                    {**i2v(f"abra_i2v_{seconds}s", ratio), "native_frames": True,
                     "resolution": resolution},
                    f"Omni 1.1 Flash · Frames · {seconds}s · {orientation} · {resolution}",
                )
                register(
                    f"omni-1.1-flash-{seconds}s-{orientation}-{resolution}",
                    {**t2v(f"abra_t2v_{seconds}s", ratio), "resolution": resolution},
                    f"Omni 1.1 Flash · Text · {seconds}s · {orientation} · {resolution}",
                )

    # Current image-to-video and reference-video variants.
    for seconds, lite_key, fast_key, quality_key in (
        (
            4,
            "veo_3_1_i2v_s_lite_4s_fl",
            "veo_3_1_i2v_s_fast_4s_fl_relaxed",
            "veo_3_1_i2v_s_quality_4s_fl",
        ),
        (
            6,
            "veo_3_1_i2v_s_lite_6s_fl",
            "veo_3_1_i2v_s_fast_6s_fl_relaxed",
            "veo_3_1_i2v_s_quality_6s_fl",
        ),
    ):
        for family, key in (
            ("lite", lite_key),
            ("fast", fast_key),
            ("quality", quality_key),
        ):
            for orientation, ratio in (
                ("landscape", landscape),
                ("portrait", portrait),
            ):
                register(
                    f"veo-3.1-{family}-i2v-{seconds}s-{orientation}",
                    i2v(key, ratio),
                    f"Veo 3.1 - {family.title()} I2V · {seconds}s · {orientation}",
                )

    for orientation, ratio, fast_key in (
        ("landscape", landscape, "veo_3_1_r2v_fast_landscape"),
        ("portrait", portrait, "veo_3_1_r2v_fast_portrait"),
    ):
        register(
            f"veo-3.1-fast-r2v-8s-{orientation}",
            r2v(fast_key, ratio),
            f"Veo 3.1 - Fast R2V · 8s · {orientation}",
        )
        register(
            f"veo-3.1-lite-r2v-8s-{orientation}",
            r2v("veo_3_1_r2v_lite", ratio),
            f"Veo 3.1 - Lite R2V · 8s · {orientation}",
        )

    for orientation, ratio, fast_key, quality_key in (
        (
            "landscape",
            landscape,
            "veo_3_1_extend_fast_landscape_ultra_relaxed",
            "veo_3_1_extend_landscape",
        ),
        (
            "portrait",
            portrait,
            "veo_3_1_extend_fast_portrait_ultra_relaxed",
            "veo_3_1_extend_portrait",
        ),
    ):
        register(
            f"veo-3.1-fast-extend-8s-{orientation}",
            extend(fast_key, ratio),
            f"Veo 3.1 - Fast Extend · {orientation}",
        )
        register(
            f"veo-3.1-quality-extend-8s-{orientation}",
            extend(quality_key, ratio),
            f"Veo 3.1 - Quality Extend · {orientation}",
        )
        register(
            f"veo-3.1-lite-extend-8s-{orientation}",
            extend("veo_3_1_extension_lite", ratio),
            f"Veo 3.1 - Lite Extend · {orientation}",
        )

    register(
        "veo-3.1-lite",
        t2v("veo_3_1_t2v_lite", landscape),
        "Veo 3.1 - Lite · 8s · landscape",
    )
    register(
        "veo-3.1-fast",
        t2v("veo_3_1_t2v_fast", landscape),
        "Veo 3.1 - Fast · 8s · landscape",
    )
    register(
        "veo-3.1-quality",
        t2v("veo_3_1_t2v", landscape),
        "Veo 3.1 - Quality · 8s · landscape",
    )
    register(
        "omni-1.1-flash",
        {
            "type": "video",
            "video_type": "omni",
            "model_key": "abra_t2v_8s",
            "reference_model_key": "abra_r2v_8s",
            "reference_duration": 8,
            "aspect_ratio": landscape,
            "supports_images": True,
            "min_images": 0,
            "max_images": 3,
            "use_v2_model_config": True,
            "allow_tier_upgrade": False,
        },
        "Omni 1.1 Flash · 8s · landscape",
    )


_apply_current_flow_model_catalog()


def _known_video_model_keys() -> set[str]:
    return {
        cfg["model_key"]
        for cfg in MODEL_CONFIG.values()
        if cfg.get("type") == "video" and cfg.get("model_key")
    }


def _resolve_tier_two_model_key(model_key: str) -> str:
    """Only upgrade to an ultra key when that exact upstream key is known valid."""
    if "ultra" in model_key:
        return model_key
    if "_fl" in model_key:
        candidate = model_key.replace("_fl", "_ultra_fl")
    else:
        candidate = model_key + "_ultra"
    return candidate if candidate in _known_video_model_keys() else model_key


class GenerationHandler:
    """统一生成处理器"""

    def __init__(
        self,
        flow_client,
        token_manager,
        load_balancer,
        db,
        concurrency_manager,
        proxy_manager,
    ):
        cache_dir = Path(__file__).resolve().parents[2] / "tmp"
        self.flow_client = flow_client
        self.token_manager = token_manager
        self.load_balancer = load_balancer
        self.db = db
        self.concurrency_manager = concurrency_manager
        self.proxy_manager = proxy_manager
        self.file_cache = FileCache(
            cache_dir=str(cache_dir),
            default_timeout=config.cache_timeout,
            proxy_manager=proxy_manager,
            flow_client=flow_client,
        )

    def _create_generation_result(self) -> Dict[str, Any]:
        """????????????????"""
        return dict(success=False, error_message=None, error_emitted=False)

    def _create_response_state(self) -> Dict[str, Any]:
        """为单次请求创建独立的响应状态，避免并发请求互相污染。"""
        return {
            "url": None,
            "generated_assets": None,
            "base_url": None,
        }

    def _mark_generation_failed(
        self, generation_result: Optional[Dict[str, Any]], error_message: str
    ):
        """????????????????????"""
        if isinstance(generation_result, dict):
            generation_result["success"] = False
            generation_result["error_message"] = error_message
            generation_result["error_emitted"] = True

    def _mark_generation_succeeded(self, generation_result: Optional[Dict[str, Any]]):
        """???????"""
        if isinstance(generation_result, dict):
            generation_result["success"] = True
            generation_result["error_message"] = None
            generation_result["error_emitted"] = False

    async def _resolve_video_asset(
        self,
        token,
        operation: Dict[str, Any],
    ) -> Dict[str, Any]:
        """按当前上游逻辑解析视频资产：状态由 media 决定，URL 通过 redirect 二段获取。"""
        metadata = (operation.get("operation") or {}).get("metadata", {}) or {}
        video_info = (
            metadata.get("video", {}) if isinstance(metadata.get("video"), dict) else {}
        )
        project_id = (
            str(operation.get("projectId") or video_info.get("projectId") or "").strip()
            or None
        )
        media_name = (
            operation.get("mediaName")
            or video_info.get("mediaName")
        )
        # as29s indexes by generation operation id, not mediaName; the two are
        # distinct UUIDs and the wrong one comes back as code=[5] (NOT_FOUND).
        media_generation_id = (
            video_info.get("mediaGenerationId")
            or operation.get("name")
            or (operation.get("operation") or {}).get("name")
        )
        media_lookup_id = media_generation_id or media_name

        # jwpduf 轮询响应可能已携带带签名的 flow-content 直链（与图片路径一致），
        # 直接复用；仅在没有直链时才通过 as29s 换取（部分模型如 abra 的
        # media 名不被 as29s 接受，会返回 code=[5]）。
        video_url = str(video_info.get("fifeUrl") or "").strip()
        if not video_url and media_lookup_id:
            video_url = (
                await self.flow_client.get_media_url_redirect(
                    getattr(token, "st", ""),
                    media_lookup_id,
                    media_url_type="MEDIA_URL_TYPE_FULL_MEDIA",
                    google_cookies=getattr(token, "google_cookies", None),
                    token_id=getattr(token, "id", None),
                    project_id=project_id,
                )
                or ""
            )

        import re as _re

        uuid_match = _re.search(r"/video/([0-9a-f-]{36})", video_url or "")
        video_media_id = (
            uuid_match.group(1)
            if uuid_match
            else str(media_generation_id or media_lookup_id or "")
        )

        return {
            "media_name": media_name or media_generation_id,
            "video_url": video_url,
            "video_media_id": video_media_id,
            "aspect_ratio": video_info.get("aspectRatio", "VIDEO_ASPECT_RATIO_LANDSCAPE"),
            "model": video_info.get("model"),
            "duration": video_info.get("duration"),
            "metadata": metadata,
            "video_info": video_info,
        }

    def _normalize_error_message(self, error_message: Any, max_length: int = 1000) -> str:
        """归一化错误文本，避免写入超长内容。"""
        text = str(error_message or "").strip() or "未知错误"
        if len(text) <= max_length:
            return text
        return f"{text[:max_length - 3]}..."

    def _resolve_video_model_key_for_tier(self, model_config: Dict[str, Any], user_tier: str) -> tuple[str, Optional[str]]:
        """根据账号层级调整视频模型 key。"""
        model_key = model_config["model_key"]
        allow_tier_upgrade = bool(model_config.get("allow_tier_upgrade", True))

        if user_tier == "PAYGATE_TIER_TWO":
            if allow_tier_upgrade and "ultra" not in model_key:
                upgraded_model_key = _resolve_tier_two_model_key(model_key)
                if upgraded_model_key != model_key:
                    return (
                        upgraded_model_key,
                        f"TIER_TWO 账号自动切换到 ultra 模型: {upgraded_model_key}",
                    )
            return model_key, None

        if user_tier == "PAYGATE_TIER_ONE" and "ultra" in model_key:
            model_key = model_key.replace("_ultra_fl", "_fl").replace("_ultra", "")
            return model_key, f"TIER_ONE 账号自动切换到标准模型: {model_key}"

        return model_key, None

    async def _fail_video_task(
        self, operations: Optional[List[Dict[str, Any]]], error_message: str
    ):
        """将视频任务收口到失败态，避免残留 processing。"""
        if not operations:
            return

        operation = operations[0] if operations else {}
        task_id = (operation.get("operation") or {}).get("name")
        if not task_id:
            return

        try:
            await self.db.update_task(
                task_id,
                status="failed",
                error_message=self._normalize_error_message(error_message),
                completed_at=time.time(),
            )
        except Exception as exc:
            debug_logger.log_error(f"[VIDEO] 更新任务失败状态失败: {exc}")

    async def _video_status_unknown(
        self, token, operations, generation_result, request_log_state, *, reason="poll_failed",
    ) -> str:
        """Persist an unresolved submitted operation before the client sees an error."""
        message = "视频已提交，但状态查询未完成；生成结果尚未确认，请勿重复提交"
        operation = operations[0] if operations else {}
        task_id = (operation.get("operation") or {}).get("name") or operation.get("name")
        payload = {
            "message": message, "type": "server_error", "code": "video_status_unknown",
            "status_code": 502, "submission_pending": True, "upstream_accepted": True,
            "reason": reason, "task_id": task_id,
        }
        self._mark_generation_failed(generation_result, message)
        if isinstance(generation_result, dict):
            generation_result["submission_pending"] = True
        persist = getattr(self.db, "persist_interrupted_video_request", None)
        if task_id and callable(persist):
            await persist(task_id=task_id, token_id=token.id,
                log_id=(request_log_state or {}).get("id"), payload=payload,
                client_submission_id=(request_log_state or {}).get("client_submission_id"),
                operations=operations, progress=(request_log_state or {}).get("progress", 45))
        elif task_id:
            await self.db.update_task(
                task_id, status="status_unknown", error_message=message, completed_at=None,
            )
        if not callable(persist) and isinstance(request_log_state, dict) and request_log_state.get("id"):
            await self.db.update_request_log(
                request_log_state["id"], token_id=token.id,
                response_body=json.dumps({"error": payload}, ensure_ascii=False),
                status_code=502, status_text="video_status_unknown",
                progress=request_log_state.get("progress", 45),
            )
        if isinstance(generation_result, dict):
            generation_result["video_interruption_persisted"] = True
        return json.dumps({"error": payload}, ensure_ascii=False)

    async def _preserve_interrupted_video(self, token, generation_result, request_log_state, *, reason):
        """Finish local observation while keeping the original accepted receipt."""
        if not isinstance(generation_result, dict) or generation_result.get("video_interruption_persisted"):
            return
        receipt = generation_result.get("submitted_video")
        if not receipt or not receipt.get("operations"):
            return
        operations = receipt["operations"]
        operation = operations[0]
        task_id = (operation.get("operation") or {}).get("name") or operation.get("name")
        if not task_id:
            return
        payload = {"message": "视频已提交，但本地查询已中断；生成结果尚未确认，请查询原提交，勿重复提交",
            "type": "server_error", "code": "video_status_unknown", "status_code": 502,
            "submission_pending": True, "upstream_accepted": True, "reason": reason, "task_id": task_id}

        async def persist():
            task = Task(task_id=task_id, token_id=token.id, model=receipt.get("model", "video"),
                prompt=receipt.get("prompt", ""), scene_id=receipt.get("scene_id"), status="status_unknown")
            status = await self.db.persist_interrupted_video_request(
                task_id=task_id, token_id=token.id, log_id=(request_log_state or {}).get("id"),
                payload=payload, task=task, project_id=receipt.get("project_id"), operations=operations,
                client_submission_id=(request_log_state or {}).get("client_submission_id"),
                progress=(request_log_state or {}).get("progress", 45))
            if status == "status_unknown":
                self._mark_generation_failed(generation_result, payload["message"])
                generation_result["submission_pending"] = True
            generation_result["video_interruption_persisted"] = True

        cleanup = generation_result.get("video_interruption_task")
        if cleanup is None:
            cleanup = asyncio.create_task(persist())
            generation_result["video_interruption_task"] = cleanup
        # Repeated disconnect cancellation must not interrupt the transaction
        # that clears the 102 log, nor release the account before it finishes.
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                continue
        cleanup.result()

    async def check_token_availability(self, is_image: bool, is_video: bool) -> bool:
        """检查Token可用性

        Args:
            is_image: 是否检查图片生成Token
            is_video: 是否检查视频生成Token

        Returns:
            True表示有可用Token, False表示无可用Token
        """
        token_obj = await self.load_balancer.select_token(
            for_image_generation=is_image, for_video_generation=is_video
        )
        return token_obj is not None

    async def handle_generation(
        self,
        model: str,
        prompt: str,
        images: Optional[List[bytes]] = None,
        stream: bool = False,
        base_url_override: Optional[str] = None,
        video_media_id: Optional[str] = None,
        client_submission_id: Optional[str] = None,
    ) -> AsyncGenerator:
        """统一生成入口

        视频在某个账号上确认尚未提交上游（且该账号已因此进入冷却）时，换另一个账号
        再试一次，调用方只会看到最终结果；没有其它账号可用时，返回第一次的原始错误。

        Args:
            model: 模型名称
            prompt: 提示词
            images: 图片列表 (bytes格式)
            stream: 是否流式输出
        """
        extra_attempts = max(0, int(getattr(config, "flow_account_retries", 1)))
        excluded = set()
        fallback = None
        attempt = 0
        while True:
            attempt += 1
            state = {"allow": attempt <= extra_attempts, "attempt": attempt, "fallback": fallback}
            async with aclosing(self._generate_once(
                model, prompt, images, stream, base_url_override, video_media_id,
                client_submission_id, exclude_token_ids=excluded, retry_state=state,
            )) as chunks:
                async for chunk in chunks:
                    yield chunk
            if not state.get("retry"):
                return
            excluded.add(state["token_id"])
            fallback = state["tail"]
            debug_logger.log_info(
                f"[GENERATION] Token {state['token_id']} 尚未提交上游，换用其他账号重试 "
                f"({attempt}/{extra_attempts + 1})"
            )
            if stream:
                yield self._create_stream_chunk("该账号暂时无法提交，正在换用其他账号重试...\n")

    async def _generate_once(
        self,
        model: str,
        prompt: str,
        images: Optional[List[bytes]] = None,
        stream: bool = False,
        base_url_override: Optional[str] = None,
        video_media_id: Optional[str] = None,
        client_submission_id: Optional[str] = None,
        *,
        exclude_token_ids=None,
        retry_state: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator:
        """一次生成尝试。

        retry_state 由 handle_generation 提供：确认未提交的失败交还给它（retry/token_id/tail），
        本次不向调用方输出错误；fallback 是上一次失败的错误输出，没有其它账号时原样返回。
        """
        start_time = time.time()
        routing_started_at = time.monotonic()
        attempt = (retry_state or {}).get("attempt", 1)
        token = None
        generation_type = None
        pending_token_state = {"active": False}
        concurrency_slot_acquired = False
        account_generation_lease = None
        selected_token_id = None
        exit_rotation = getattr(self, "exit_rotation", None)
        rotation_lease_acquired = False
        sent_callback_context = None
        sent_callback_bound = False
        rotation_error_marked = False
        request_id = f"gen-{int(start_time * 1000)}-{id(asyncio.current_task())}"

        async def mark_rotation_error():
            nonlocal rotation_error_marked
            if exit_rotation is not None and selected_token_id is not None and not rotation_error_marked:
                rotation_error_marked = True
                try:
                    await exit_rotation.note_error(selected_token_id, request_id)
                except Exception as exc:
                    # Rotation bookkeeping cannot turn an accepted operation's
                    # unknown status into an ordinary failed generation.
                    debug_logger.log_warning(
                        f"[EXIT_ROTATION] Token {selected_token_id}: error state write failed ({type(exc).__name__})"
                    )
        perf_trace: Dict[str, Any] = {
            "request_id": request_id,
            "model": model,
            "status": "processing",
        }
        generation_result = self._create_generation_result()
        generation_result["routing_started_at"] = routing_started_at
        response_state = self._create_response_state()
        response_state["base_url"] = (base_url_override or "").strip().rstrip(
            "/"
        ) or None
        request_log_state: Dict[str, Any] = {"id": None, "progress": 0, "client_submission_id": client_submission_id}

        # 防止并发链路复用到上一次请求的指纹上下文
        if hasattr(self.flow_client, "clear_request_fingerprint"):
            self.flow_client.clear_request_fingerprint()

        # 1. 验证模型
        if model not in MODEL_CONFIG:
            error_msg = f"不支持的模型: {model}"
            debug_logger.log_error(error_msg)
            record_generation_result("unknown", "invalid", time.time() - start_time)
            yield self._create_error_response(error_msg, status_code=400, code='submission_not_started', submission_pending=False, upstream_accepted=False)
            return

        model_config = MODEL_CONFIG[model]
        generation_type = model_config["type"]
        video_type_for_op = model_config.get("video_type", "")
        request_operation = (
            "extend_video"
            if video_type_for_op == "extend"
            else f"generate_{generation_type}"
        )
        prompt_for_log = (
            prompt if len(prompt) <= 2000 else f"{prompt[:2000]}...(truncated)"
        )
        request_payload = {
            "model": model,
            "prompt": prompt_for_log,
            "has_images": images is not None and len(images) > 0,
        }
        if client_submission_id:
            request_payload['client_submission_id'] = client_submission_id
        debug_logger.log_info(
            f"[GENERATION] 开始生成 - 模型: {model}, 类型: {generation_type}, Prompt: {prompt[:50]}..."
        )

        # 向用户展示开始信息（重试时由 handle_generation 另行提示，拿到账号后再记日志）
        if stream and attempt == 1:
            yield self._create_stream_chunk(
                f"✨ {'视频' if generation_type == 'video' else '图片'}生成任务已启动\n",
                role="assistant",
            )

        # 2. 选择Token
        debug_logger.log_info(f"[GENERATION] 正在选择可用Token...")
        token_select_started_at = time.time()

        # Only a retry names accounts to avoid, so ordinary selection is unchanged.
        avoid = {"exclude_token_ids": exclude_token_ids} if exclude_token_ids else {}
        if generation_type == "image":
            token = await self.load_balancer.select_token(
                for_image_generation=True,
                model=model,
                reserve=False,
                enforce_concurrency_filter=False,
                track_pending=True,
                **avoid,
            )
        else:
            token = await self.load_balancer.select_token(
                for_video_generation=True,
                model=model,
                reserve=False,
                enforce_concurrency_filter=False,
                track_pending=True,
                **avoid,
            )
        perf_trace["token_select_ms"] = int(
            (time.time() - token_select_started_at) * 1000
        )

        if not token:
            fallback = (retry_state or {}).get("fallback")
            if fallback:
                # A retry with no other account to try: the first attempt's error
                # stays the answer, and nothing new is logged for this attempt.
                for chunk in fallback:
                    yield chunk
                return
            error_msg = None
            if self.load_balancer and hasattr(
                self.load_balancer, "get_unavailable_reason"
            ):
                error_msg = await self.load_balancer.get_unavailable_reason(
                    for_image_generation=(generation_type == "image"),
                    for_video_generation=(generation_type == "video"),
                    model=model,
                )
            if not error_msg:
                error_msg = self._get_no_token_error_message(generation_type)
            debug_logger.log_error(f"[GENERATION] {error_msg}")
            record_generation_result(
                generation_type, "no_token", time.time() - start_time
            )
            await self._log_request(
                token_id=None,
                operation=request_operation,
                request_data=request_payload,
                response_data={"error": error_msg, "performance": perf_trace},
                status_code=503,
                duration=time.time() - start_time,
                log_id=request_log_state.get("id"),
                status_text="failed",
                progress=request_log_state.get("progress", 0),
            )
            if stream:
                yield self._create_stream_chunk(f"错误: {error_msg}\n")
            yield self._create_error_response(
                error_msg, status_code=503, code="no_available_token", submission_pending=False, upstream_accepted=False
            )
            return

        debug_logger.log_info(f"[GENERATION] 已选择Token: {token.id} ({token.email})")
        selected_token_id = token.id
        pending_token_state["active"] = True
        try:
            admission = getattr(self.token_manager, "account_admission", None)
            if admission is not None:
                try:
                    account_generation_lease = admission.generation(token.id)
                except AccountAdmissionBusy:
                    message = "账号正在维护登录凭证，尚未提交生成，请稍后重试"
                    await self._log_request(token.id, request_operation, request_payload,
                        {"error": message, "code": "submission_not_started", "submission_pending": False,
                         "upstream_accepted": False}, 503, time.time() - start_time, status_text="failed")
                    yield self._create_error_response(message, status_code=503, code="submission_not_started",
                        submission_pending=False, upstream_accepted=False)
                    return
            # The shared lease covers both response modes, independently of
            # progress logging. A stream creates its row only after admission;
            # an unassigned waiter cannot falsely own every browser account.
            if stream and attempt == 1:
                request_log_state["id"] = await self._log_request(
                    token_id=token.id, operation=request_operation, request_data=request_payload,
                    response_data={"status": "processing", "request_id": request_id},
                    status_code=102, duration=0, status_text="token_selected", progress=8,
                )
            if client_submission_id:
                await SubmissionLedger(self.db).update(client_submission_id, account_id=token.id)
            await self._update_request_log_progress(
                request_log_state,
                token_id=token.id,
                status_text="token_selected",
                progress=8,
                response_extra={"token_email": token.email},
            )
            concurrency_manager = getattr(self, "concurrency_manager", None)
            if concurrency_manager is not None:
                await self._update_request_log_progress(
                    request_log_state, token_id=token.id,
                    status_text="waiting_account_slot", progress=8,
                )
                wait_acquire = (
                    concurrency_manager.wait_acquire_image
                    if generation_type == "image"
                    else concurrency_manager.wait_acquire_video
                )
                acquired, waited_ms = await wait_acquire(
                    selected_token_id,
                    timeout_seconds=(
                        config.flow_image_slot_wait_timeout if generation_type == "image"
                        else config.flow_video_slot_wait_timeout
                    ),
                )
                perf_trace["account_slot_wait_ms"] = waited_ms
                if not acquired:
                    error_msg = "账号生成并发槽位等待超时，尚未提交上游生成"
                    await self._log_request(
                        selected_token_id, request_operation, request_payload,
                        {"error": error_msg, "code": "submission_not_started",
                         "submission_pending": False, "upstream_accepted": False,
                         "performance": perf_trace},
                        503, time.time() - start_time,
                        log_id=request_log_state.get("id"), status_text="failed", progress=8,
                    )
                    yield self._create_error_response(
                        error_msg, status_code=503, code="submission_not_started",
                        submission_pending=False, upstream_accepted=False,
                    )
                    return
                concurrency_slot_acquired = True
                await self.load_balancer.release_pending(
                    selected_token_id,
                    for_image_generation=(generation_type == "image"),
                    for_video_generation=(generation_type == "video"),
                )
                pending_token_state["active"] = False
            if exit_rotation is not None:
                # Hold the account route through submission and polling. A waiting
                # request reloads the account after any due rotation finishes.
                token = await exit_rotation.acquire(token, request_id)
                rotation_lease_acquired = True

                async def note_generation_sent():
                    await exit_rotation.note_sent(selected_token_id, request_id)

                sent_callback_context = self.flow_client.set_generation_sent_callback(note_generation_sent)
                sent_callback_bound = True
                self.flow_client._set_request_fingerprint({"proxy_url": token.proxy_url})
            # 3. 确保AT有效
            debug_logger.log_info(f"[GENERATION] 检查Token AT有效性...")
            if stream:
                yield self._create_stream_chunk("初始化生成环境...\n")

            await self._update_request_log_progress(
                request_log_state,
                token_id=token.id,
                status_text="token_ready",
                progress=15,
            )
            ensure_at_started_at = time.time()
            token = await self.token_manager.ensure_valid_token(token)
            perf_trace["ensure_at_ms"] = int(
                (time.time() - ensure_at_started_at) * 1000
            )
            if not token:
                await mark_rotation_error()
                error_msg = "Token AT无效或刷新失败"
                debug_logger.log_error(f"[GENERATION] {error_msg}")
                record_generation_result(
                    generation_type, "failed", time.time() - start_time
                )
                if stream:
                    yield self._create_stream_chunk(f"错误: {error_msg}\n")
                yield self._create_error_response(
                    error_msg, status_code=503, code="no_available_token", submission_pending=False, upstream_accepted=False
                )
                return

            # 4. 确保Project存在
            debug_logger.log_info(f"[GENERATION] 检查/创建Project...")

            if not supports_model_for_tier(model, token.user_paygate_tier):
                required_tier = get_required_paygate_tier_for_model(model)
                error_msg = (
                    "当前模型需要 "
                    + get_paygate_tier_label(required_tier)
                    + " 账号: "
                    + model
                )
                debug_logger.log_error(f"[GENERATION] {error_msg}")
                record_generation_result(
                    generation_type, "failed", time.time() - start_time
                )
                if stream:
                    yield self._create_stream_chunk(f"错误: {error_msg}\n")
                yield self._create_error_response(error_msg, status_code=403)
                return

            ensure_project_started_at = time.time()
            project_id = await self.token_manager.ensure_project_exists(token.id)
            perf_trace["ensure_project_ms"] = int(
                (time.time() - ensure_project_started_at) * 1000
            )
            debug_logger.log_info(f"[GENERATION] Project ID: {project_id}")
            await self._update_request_log_progress(
                request_log_state,
                token_id=token.id,
                status_text="project_ready",
                progress=22,
                response_extra={"project_id": project_id},
            )
            prefill_action = (
                "IMAGE_GENERATION" if generation_type == "image" else "VIDEO_GENERATION"
            )
            await self.flow_client.prefill_remote_browser_pool(
                project_id=project_id,
                action=prefill_action,
                token_id=token.id,
            )

            # 5. 根据类型处理
            generation_pipeline_started_at = time.time()
            if generation_type == "image":
                debug_logger.log_info(f"[GENERATION] 开始图片生成流程...")
                async for chunk in self._handle_image_generation(
                    token,
                    project_id,
                    model_config,
                    prompt,
                    images,
                    stream,
                    perf_trace=perf_trace,
                    generation_result=generation_result,
                    response_state=response_state,
                    request_log_state=request_log_state,
                    pending_token_state=pending_token_state,
                ):
                    yield chunk
            else:  # video
                debug_logger.log_info(f"[GENERATION] 开始视频生成流程...")
                async with aclosing(self._handle_video_generation(
                    token,
                    project_id,
                    model_config,
                    prompt,
                    images,
                    stream,
                    perf_trace=perf_trace,
                    generation_result=generation_result,
                    response_state=response_state,
                    request_log_state=request_log_state,
                    pending_token_state=pending_token_state,
                    video_media_id=video_media_id,
                )) as chunks:
                    async for chunk in chunks:
                        yield chunk
            perf_trace["generation_pipeline_ms"] = int(
                (time.time() - generation_pipeline_started_at) * 1000
            )

            # A submitted operation with unknown status must remain recoverable.
            # Its state was persisted before yielding the error, because clients
            # commonly close the stream immediately on an error event.
            if generation_result.get("submission_pending"):
                await mark_rotation_error()
                return

            # 6. 记录使用
            if not generation_result.get("success"):
                await mark_rotation_error()
                error_msg = generation_result.get("error_message") or "生成未成功完成"
                debug_logger.log_warning(
                    f"[GENERATION] 生成未成功，不扣次数: {error_msg}"
                )
                if token:
                    await self.token_manager.record_error(token.id)
                duration = time.time() - start_time
                record_generation_result(generation_type, "failed", duration)
                perf_trace["status"] = "failed"
                perf_trace["total_ms"] = int(duration * 1000)
                perf_trace["error"] = error_msg
                prompt_for_log = (
                    prompt if len(prompt) <= 2000 else f"{prompt[:2000]}...(truncated)"
                )
                await self._log_request(
                    token.id if token else None,
                    request_operation,
                    request_payload,
                    {"error": error_msg, "performance": perf_trace},
                    500,
                    duration,
                    log_id=request_log_state.get("id"),
                    status_text="failed",
                    progress=request_log_state.get("progress", 0),
                )
                if not generation_result.get("error_emitted"):
                    if stream:
                        yield self._create_stream_chunk(f"错误: {error_msg}\n")
                    yield self._create_error_response(error_msg, status_code=500)
                return

            is_video = generation_type == "video"
            if not generation_result.get("usage_recorded"):
                await self.token_manager.record_usage(token.id, is_video=is_video)
                await self.token_manager.record_success(token.id)
                generation_result["usage_recorded"] = True
            self._record_routing_success(
                token, generation_type, model, started_at=generation_result.get("routing_started_at"),
            )

            debug_logger.log_info(f"[GENERATION] ✅ 生成成功完成")

            # 7. 记录成功日志
            duration = time.time() - start_time
            record_generation_result(generation_type, "success", duration)
            perf_trace["status"] = "success"
            perf_trace["total_ms"] = int(duration * 1000)
            # 日志中保留更完整的 prompt，避免管理页只看到过短内容
            prompt_for_log = (
                prompt if len(prompt) <= 2000 else f"{prompt[:2000]}...(truncated)"
            )

            # 构建响应数据，包含生成的URL
            response_data = {
                "status": "success",
                "model": model,
                "prompt": prompt_for_log,
                "performance": perf_trace,
            }

            # 添加生成的URL（如果有）
            if response_state.get("url"):
                response_data["url"] = response_state["url"]
            if response_state.get("generated_assets"):
                response_data["generated_assets"] = response_state["generated_assets"]
            image_perf = (
                perf_trace.get("image_generation", {})
                if isinstance(perf_trace, dict)
                else {}
            )
            video_perf = (
                perf_trace.get("video_generation", {})
                if isinstance(perf_trace, dict)
                else {}
            )
            debug_logger.log_info(
                f"[PERF] [{request_id}] total={perf_trace.get('total_ms', 0)}ms, "
                f"select={perf_trace.get('token_select_ms', 0)}ms, "
                f"ensure_at={perf_trace.get('ensure_at_ms', 0)}ms, "
                f"project={perf_trace.get('ensure_project_ms', 0)}ms, "
                f"pipeline={perf_trace.get('generation_pipeline_ms', 0)}ms, "
                f"slot_wait={image_perf.get('slot_wait_ms', 0)}ms, "
                f"launch_queue={image_perf.get('launch_queue_wait_ms', 0)}ms, "
                f"launch_stagger={image_perf.get('launch_stagger_wait_ms', 0)}ms, "
                f"video_slot_wait={video_perf.get('slot_wait_ms', 0)}ms"
            )

            await self._log_request(
                token.id,
                request_operation,
                request_payload,
                response_data,
                200,
                duration,
                log_id=request_log_state.get("id"),
                status_text="completed",
                progress=100,
            )

        except (asyncio.CancelledError, GeneratorExit) as interruption:
            if not generation_result.get("success"):
                await mark_rotation_error()
            if generation_type == "video" and generation_result.get("submitted_video"):
                await self._preserve_interrupted_video(
                    token, generation_result, request_log_state,
                    reason="client_disconnected" if isinstance(interruption, asyncio.CancelledError) else "generator_closed")
                raise
            if generation_result.get("success"):
                raise
            error_msg = "生成已取消: 客户端连接已断开"
            debug_logger.log_warning(f"[GENERATION] ⚠️ {error_msg}")
            duration = time.time() - start_time
            record_generation_result(
                generation_type or "unknown", "cancelled", duration
            )
            perf_trace["status"] = "failed"
            perf_trace["total_ms"] = int(duration * 1000)
            perf_trace["error"] = error_msg
            prompt_for_log = (
                prompt if len(prompt) <= 2000 else f"{prompt[:2000]}...(truncated)"
            )
            await self._log_request(
                token.id if token else None,
                request_operation if generation_type else "generate_unknown",
                request_payload if "request_payload" in locals() else {"model": model},
                {"error": error_msg, "performance": perf_trace},
                499,
                duration,
                log_id=request_log_state.get("id"),
                status_text="failed",
                progress=request_log_state.get("progress", 0),
            )
            raise
        except Exception as e:
            await mark_rotation_error()
            error_msg = f"生成失败: {str(e)}"
            # Only the native runner's guarded request/cleanup evidence proves
            # non-submission. A button click or stage name alone cannot do so.
            rejected = isinstance(e, FlowRPCRejected) and e.submission_rejected
            unsubmitted = rejected or (
                isinstance(e, BrowserCaptchaError)
                and e.submission_pending is False
            )
            error_code = "submission_rejected" if rejected else ("submission_not_started" if unsubmitted else "generation_failed")
            native_diagnostic = self._safe_native_submission_diagnostic(
                getattr(e, "native_submission_diagnostic", None)
            ) if isinstance(e, BrowserCaptchaError) else None
            debug_logger.log_error(f"[GENERATION] 生成失败: {error_msg}")
            routing_opened = False
            if token:
                routing_failure = getattr(self.load_balancer, "record_generation_failure", None)
                if callable(routing_failure):
                    try:
                        routing_opened = await routing_failure(
                            token.id, e, for_image_generation=generation_type == "image",
                            for_video_generation=generation_type == "video", model=model, token=token,
                        ) is True
                    except Exception as routing_error:
                        # Routing bookkeeping must not replace the original
                        # submission evidence or its response to the caller.
                        debug_logger.log_warning(
                            f"[GENERATION] 路由冷却登记失败: token_id={token.id}, "
                            f"error_type={type(routing_error).__name__}"
                        )
                if self._should_count_token_error(e):
                    await self.token_manager.record_error(token.id)
                else:
                    debug_logger.log_info(
                        f"[GENERATION] 跳过 token 错误计数: token_id={token.id}, reason={str(e)[:200]}"
                    )

            # 先将最终失败状态落库，再返回错误响应，避免日志停在 102。
            duration = time.time() - start_time
            record_generation_result(generation_type or "unknown", "failed", duration)
            perf_trace["status"] = "failed"
            perf_trace["total_ms"] = int(duration * 1000)
            perf_trace["error"] = error_msg
            prompt_for_log = (
                prompt if len(prompt) <= 2000 else f"{prompt[:2000]}...(truncated)"
            )
            error_data = {"error": error_msg, "performance": perf_trace}
            if native_diagnostic:
                error_data["native_submission_diagnostic"] = native_diagnostic
            if unsubmitted:
                error_data.update(code=error_code, submission_pending=False, upstream_accepted=False)
            await self._log_request(
                token.id if token else None,
                request_operation if generation_type else "generate_unknown",
                request_payload if "request_payload" in locals() else {"model": model},
                error_data,
                500,
                duration,
                log_id=request_log_state.get("id"),
                status_text="failed",
                progress=request_log_state.get("progress", 0),
            )
            error_chunks = []
            if stream:
                error_chunks.append(self._create_stream_chunk(f"错误: {error_msg}\n"))
            error_chunks.append(self._create_error_response(
                error_msg, status_code=500, code=error_code,
                submission_pending=False if unsubmitted else None,
                upstream_accepted=False if unsubmitted else None,
                reason=(("unusual_activity" if 'UNUSUAL_ACTIVITY' in e.error_code else "upstream_rejected")
                        if rejected else (e.reason if isinstance(e, BrowserCaptchaError) else None)),
                native_submission_diagnostic=native_diagnostic,
            ))
            if (
                retry_state is not None and retry_state.get("allow")
                and generation_type == "video" and unsubmitted and routing_opened
            ):
                # Nothing reached upstream and this account is now cooling down for
                # an account/route reason, so another account may run the request.
                # The error is handed back instead of shown to the caller.
                retry_state.update(retry=True, token_id=token.id, tail=error_chunks)
                return
            for chunk in error_chunks:
                yield chunk
        finally:
            try:
                # Also cover clients closing the generator immediately after an
                # internal error event, before the outer loop can resume.
                if rotation_lease_acquired and not generation_result.get("success"):
                    await mark_rotation_error()
            finally:
                try:
                    if sent_callback_bound:
                        self.flow_client.clear_generation_sent_callback(sent_callback_context)
                        self.flow_client.clear_request_fingerprint()
                finally:
                    try:
                        if pending_token_state.get("active") and selected_token_id is not None and self.load_balancer:
                            await self.load_balancer.release_pending(
                                selected_token_id,
                                for_image_generation=(generation_type == "image"),
                                for_video_generation=(generation_type == "video"),
                            )
                            pending_token_state["active"] = False
                    finally:
                        try:
                            if rotation_lease_acquired:
                                await exit_rotation.release(selected_token_id, request_id)
                        finally:
                            try:
                                if concurrency_slot_acquired:
                                    release_slot = (
                                        concurrency_manager.release_image
                                        if generation_type == "image"
                                        else concurrency_manager.release_video
                                    )
                                    await release_slot(selected_token_id)
                            finally:
                                if account_generation_lease is not None:
                                    account_generation_lease.close()

    def _get_no_token_error_message(self, generation_type: str) -> str:
        """获取无可用Token时的详细错误信息"""
        if generation_type == "image":
            return "没有可用的Token进行图片生成。所有Token都处于禁用、冷却、锁定或已过期状态。"
        else:
            return "没有可用的Token进行视频生成。所有Token都处于禁用、冷却、配额耗尽或已过期状态。"

    def _record_routing_success(self, token, generation_type: str, model: str, *, started_at=None) -> None:
        record = getattr(getattr(self, "load_balancer", None), "record_generation_success", None)
        if not callable(record):
            return
        try:
            record(
                token.id, for_image_generation=generation_type == "image",
                for_video_generation=generation_type == "video", model=model, token=token, started_at=started_at,
            )
        except Exception as routing_error:
            debug_logger.log_warning(
                f"[GENERATION] 路由冷却清理失败: token_id={token.id}, "
                f"error_type={type(routing_error).__name__}"
            )

    def _should_count_token_error(self, error: Exception) -> bool:
        """判断失败是否应计入 token 连续错误。

        reCAPTCHA 获取失败、验证码供应商错误、打码资源不足等问题通常不是账号本身异常；
        若将其纳入连续错误，会在回归测试或代理波动时把 token 自动打成 inactive。
        """
        if isinstance(error, BrowserCaptchaError):
            return False
        error_text = str(error or "").strip().lower()
        if not error_text:
            return True

        non_token_fault_markers = (
            "failed to obtain recaptcha token",
            "recaptcha evaluation failed",
            "recaptcha 验证失败",
            "recaptcha 错误",
            "public_error_unusual_activity",
            "too much traffic",
            "error_no_slot_available",
            "打码服务资源不足",
            "打码服务资源阻塞",
            "yescaptcha",
            "capsolver",
            "captcharun",
            "capmonster",
            "ezcaptcha",
        )
        if any(marker in error_text for marker in non_token_fault_markers):
            return False

        if "没有可用的token进行" in error_text:
            return False

        return True

    async def _handle_image_generation(
        self,
        token,
        project_id: str,
        model_config: dict,
        prompt: str,
        images: Optional[List[bytes]],
        stream: bool,
        perf_trace: Optional[Dict[str, Any]] = None,
        generation_result: Optional[Dict[str, Any]] = None,
        response_state: Optional[Dict[str, Any]] = None,
        request_log_state: Optional[Dict[str, Any]] = None,
        pending_token_state: Optional[Dict[str, bool]] = None,
    ) -> AsyncGenerator:
        """处理图片生成 (同步返回)"""

        if response_state is None:
            response_state = self._create_response_state()

        image_trace: Optional[Dict[str, Any]] = None
        if isinstance(perf_trace, dict):
            image_trace = perf_trace.setdefault("image_generation", {})
            image_trace["input_image_count"] = len(images) if images else 0

        # 统一入口已取得账号硬并发槽位，此处直接执行图片生成链路。
        normalized_tier = normalize_user_paygate_tier(token.user_paygate_tier)

        if image_trace is not None:
            image_trace["slot_wait_ms"] = 0

        if images and len(images) > 0:
            await self._update_request_log_progress(
                request_log_state,
                token_id=token.id,
                status_text="uploading_images",
                progress=28,
            )
        else:
            await self._update_request_log_progress(
                request_log_state,
                token_id=token.id,
                status_text="submitting_image",
                progress=28,
            )

        try:
            # 上传图片 (如果有)
            upload_started_at = time.time()
            image_inputs = []
            if images and len(images) > 0:
                if stream:
                    yield self._create_stream_chunk(
                        f"上传 {len(images)} 张参考图片...\n"
                    )

                # 支持多图输入
                for idx, image_bytes in enumerate(images):
                    media_id = await self.flow_client.upload_image(
                        token.at,
                        image_bytes,
                        model_config["aspect_ratio"],
                        project_id=project_id,
                        token_id=token.id,
                        google_cookies=getattr(token, "google_cookies", None),
                    )
                    image_inputs.append(
                        {
                        "name": media_id,
                            "imageInputType": "IMAGE_INPUT_TYPE_REFERENCE",
                        }
                    )
                    if stream:
                        yield self._create_stream_chunk(
                            f"已上传第 {idx + 1}/{len(images)} 张图片\n"
                        )
            if image_trace is not None:
                image_trace["upload_images_ms"] = int(
                    (time.time() - upload_started_at) * 1000
                )

            # 调用生成API
            if stream:
                if images and len(images) > 0:
                    yield self._create_stream_chunk(
                        "参考图片上传完成，正在进行打码验证...\n"
                    )
                else:
                    yield self._create_stream_chunk(
                        "正在进行打码验证并提交图片生成请求...\n"
                    )

            async def _image_progress_callback(status_text: str, progress: int):
                await self._update_request_log_progress(
                    request_log_state,
                    token_id=token.id,
                    status_text=status_text,
                    progress=progress,
                )

            generate_started_at = time.time()
            (
                result,
                generation_session_id,
                upstream_trace,
            ) = await self.flow_client.generate_image(
                at=token.at,
                project_id=project_id,
                prompt=prompt,
                model_name=model_config["model_name"],
                aspect_ratio=model_config["aspect_ratio"],
                image_inputs=image_inputs,
                token_id=token.id,
                token_image_concurrency=token.image_concurrency,
                progress_callback=_image_progress_callback,
                google_cookies=getattr(token, "google_cookies", None),
            )
            if image_trace is not None:
                image_trace["generate_api_ms"] = int(
                    (time.time() - generate_started_at) * 1000
                )
                image_trace["upstream_trace"] = upstream_trace
                attempts = (
                    upstream_trace.get("generation_attempts")
                    if isinstance(upstream_trace, dict)
                    else None
                )
                if isinstance(attempts, list) and attempts:
                    first_attempt = attempts[0] if isinstance(attempts[0], dict) else {}
                    image_trace["launch_queue_wait_ms"] = int(
                        first_attempt.get("launch_queue_ms") or 0
                    )
                    image_trace["launch_stagger_wait_ms"] = int(
                        first_attempt.get("launch_stagger_ms") or 0
                    )
            await self._update_request_log_progress(
                request_log_state,
                token_id=token.id,
                status_text="image_generated",
                progress=72,
            )

            # 提取URL和mediaId
            media = result.get("media", [])
            if not media:
                self._mark_generation_failed(
                    generation_result, "\u751f\u6210\u7ed3\u679c\u4e3a\u7a7a"
                )
                yield self._create_error_response("生成结果为空", status_code=502)
                return

            image_url = media[0]["image"]["generatedImage"]["fifeUrl"]
            media_id = media[0].get("name")  # 用于 upsample
            response_state["generated_assets"] = {
                "type": "image",
                "origin_image_url": image_url,
            }

            # 检查是否需要 upsample
            upsample_resolution = model_config.get("upsample")
            if upsample_resolution and media_id:
                upsample_started_at = time.time()
                resolution_name = "4K" if "4K" in upsample_resolution else "2K"
                await self._update_request_log_progress(
                    request_log_state,
                    token_id=token.id,
                    status_text=f"upsampling_{resolution_name.lower()}",
                    progress=82,
                )
                if stream:
                    yield self._create_stream_chunk(
                        f"正在放大图片到 {resolution_name}...\n"
                    )

                # 4K/2K 图片重试逻辑 - 使用配置的最大重试次数
                max_retries = config.flow_max_retries
                for retry_attempt in range(max_retries):
                    try:
                        # 调用 upsample API
                        encoded_image = await self.flow_client.upsample_image(
                            at=token.at,
                            project_id=project_id,
                            media_id=media_id,
                            target_resolution=upsample_resolution,
                            user_paygate_tier=normalized_tier,
                            session_id=generation_session_id,
                            token_id=token.id,
                            google_cookies=getattr(token, "google_cookies", None),
                        )

                        if encoded_image:
                            debug_logger.log_info(
                                f"[UPSAMPLE] 图片已放大到 {resolution_name}"
                            )

                            if stream:
                                yield self._create_stream_chunk(
                                    f"✅ 图片已放大到 {resolution_name}\n"
                                )

                            # 2K/4K 图片统一落盘为真实文件，日志里只保留链接。
                            response_state["generated_assets"] = {
                                "type": "image",
                                "origin_image_url": image_url,
                                "upscaled_image": {"resolution": resolution_name},
                            }

                            if str(encoded_image).startswith("https://"):
                                response_state["url"] = encoded_image
                                response_state["generated_assets"]["upscaled_image"][
                                    "url"
                                ] = encoded_image
                                response_state["generated_assets"]["upscaled_image"][
                                    "delivery_mode"
                                ] = "frontend_url"
                                self._mark_generation_succeeded(generation_result)
                                if stream:
                                    yield self._create_stream_chunk(
                                        f"![Generated Image]({encoded_image})",
                                        finish_reason="stop",
                                    )
                                else:
                                    yield self._create_completion_response(
                                        encoded_image,
                                        media_type="image",
                                    )
                                if image_trace is not None:
                                    image_trace["upsample_ms"] = int(
                                        (time.time() - upsample_started_at) * 1000
                                    )
                                return

                            try:
                                await self._update_request_log_progress(
                                    request_log_state,
                                    token_id=token.id,
                                    status_text="caching_image",
                                    progress=90,
                                )
                                if stream:
                                    yield self._create_stream_chunk(
                                        f"缓存 {resolution_name} 图片中...\n"
                                    )
                                cached_filename = (
                                    await self.file_cache.cache_base64_image(
                                        encoded_image, resolution_name
                                    )
                                )
                                local_url = f"{self._get_base_url(response_state)}/tmp/{cached_filename}"
                                response_state["url"] = local_url
                                response_state["generated_assets"]["upscaled_image"][
                                    "local_url"
                                ] = local_url
                                response_state["generated_assets"]["upscaled_image"][
                                    "url"
                                ] = local_url
                                self._mark_generation_succeeded(generation_result)
                                if stream:
                                    yield self._create_stream_chunk(
                                        f"✅ {resolution_name} 图片缓存成功\n"
                                    )
                                    yield self._create_stream_chunk(
                                        f"![Generated Image]({local_url})",
                                        finish_reason="stop",
                                    )
                                else:
                                    yield self._create_completion_response(
                                        local_url, media_type="image"
                                    )
                                if image_trace is not None:
                                    image_trace["upsample_ms"] = int(
                                        (time.time() - upsample_started_at) * 1000
                                    )
                                return
                            except Exception as e:
                                debug_logger.log_error(
                                    f"Failed to cache {resolution_name} image: {str(e)}"
                                )
                                response_state["url"] = image_url
                                response_state["generated_assets"]["upscaled_image"][
                                    "local_url"
                                ] = None
                                response_state["generated_assets"]["upscaled_image"][
                                    "url"
                                ] = image_url
                                response_state["generated_assets"]["upscaled_image"][
                                    "delivery_mode"
                                ] = "inline_base64_fallback"
                                self._mark_generation_succeeded(generation_result)
                                base64_url = f"data:image/jpeg;base64,{encoded_image}"
                                if stream:
                                    cache_error = self._normalize_error_message(
                                        e, max_length=120
                                    )
                                    yield self._create_stream_chunk(
                                        f"⚠️ 缓存失败: {cache_error}，返回内联图片...\n"
                                    )
                                    yield self._create_stream_chunk(
                                        f"![Generated Image]({base64_url})",
                                        finish_reason="stop",
                                    )
                                else:
                                    yield self._create_completion_response(
                                        base64_url, media_type="image"
                                    )
                                if image_trace is not None:
                                    image_trace["upsample_ms"] = int(
                                        (time.time() - upsample_started_at) * 1000
                                    )
                                return
                        else:
                            debug_logger.log_warning("[UPSAMPLE] 返回结果为空")
                            if stream:
                                yield self._create_stream_chunk(
                                    f"⚠️ 放大失败，返回原图...\n"
                                )
                            break  # 空结果不重试

                    except Exception as e:
                        error_str = str(e)
                        debug_logger.log_error(
                            f"[UPSAMPLE] 放大失败 (尝试 {retry_attempt + 1}/{max_retries}): {error_str}"
                        )
                        
                        # 检查是否是可重试错误（403、reCAPTCHA、超时等）
                        retry_reason = self.flow_client._get_retry_reason(error_str)
                        if retry_reason and retry_attempt < max_retries - 1:
                            if stream:
                                yield self._create_stream_chunk(
                                    f"⚠️ 放大遇到{retry_reason}，正在重试 ({retry_attempt + 2}/{max_retries})...\n"
                                )
                            # 等待一小段时间后重试
                            await asyncio.sleep(1)
                            continue
                        else:
                            if stream:
                                yield self._create_stream_chunk(
                                    f"⚠️ 放大失败: {error_str}，返回原图...\n"
                                )
                            break
                if image_trace is not None:
                    image_trace["upsample_ms"] = int(
                        (time.time() - upsample_started_at) * 1000
                    )
                # 放大失败回退原图时记录失败标记，便于调用方感知实际交付分辨率
                if upsample_resolution and media_id:
                    response_state.setdefault("generated_assets", {})[
                        "upscaled_image"
                    ] = {
                        "resolution": resolution_name,
                        "failed": True,
                        "delivery_mode": "origin_fallback",
                    }

            local_url = image_url
            cache_started_at = time.time()
            if config.cache_enabled:
                await self._update_request_log_progress(
                    request_log_state,
                    token_id=token.id,
                    status_text="caching_image",
                    progress=90,
                )
                if stream:
                    yield self._create_stream_chunk("正在缓存 1K 图片文件...\n")
                try:
                    cached_filename = await self.file_cache.download_and_cache(
                        image_url, "image"
                    )
                    local_url = (
                        f"{self._get_base_url(response_state)}/tmp/{cached_filename}"
                    )
                    if stream:
                        yield self._create_stream_chunk(
                            "✅ 1K 图片缓存成功,准备返回缓存地址...\n"
                        )
                except Exception as e:
                    debug_logger.log_error(f"Failed to cache 1K image: {str(e)}")
                    local_url = image_url
                    if stream:
                        cache_error = self._normalize_error_message(e, max_length=120)
                        yield self._create_stream_chunk(
                            f"⚠️ 缓存失败: {cache_error}\n正在返回源链接...\n"
                        )
            elif stream:
                yield self._create_stream_chunk("缓存已关闭,正在返回官方图片链接...\n")
            if image_trace is not None:
                image_trace["cache_image_ms"] = int(
                    (time.time() - cache_started_at) * 1000
                )

            # 返回结果
            # 存储URL用于日志记录
            response_state["url"] = local_url
            final_assets = {
                "type": "image",
                "origin_image_url": image_url,
                "final_image_url": local_url,
            }
            # 保留放大失败回退标记（如有），便于调用方感知实际交付分辨率
            upscaled_marker = (response_state.get("generated_assets") or {}).get(
                "upscaled_image"
            )
            if upscaled_marker:
                final_assets["upscaled_image"] = upscaled_marker
            response_state["generated_assets"] = final_assets
            self._mark_generation_succeeded(generation_result)

            if stream:
                yield self._create_stream_chunk(
                    f"![Generated Image]({local_url})", finish_reason="stop"
                )
            else:
                yield self._create_completion_response(
                    local_url,  # 直接传URL,让方法内部格式化
                    media_type="image",
                )

        finally:
            pass

    async def _handle_video_generation(
        self,
        token,
        project_id: str,
        model_config: dict,
        prompt: str,
        images: Optional[List[bytes]],
        stream: bool,
        perf_trace: Optional[Dict[str, Any]] = None,
        generation_result: Optional[Dict[str, Any]] = None,
        response_state: Optional[Dict[str, Any]] = None,
        request_log_state: Optional[Dict[str, Any]] = None,
        pending_token_state: Optional[Dict[str, bool]] = None,
        video_media_id: Optional[str] = None,
    ) -> AsyncGenerator:
        """处理视频生成 (异步轮询)"""

        if response_state is None:
            response_state = self._create_response_state()

        video_trace: Optional[Dict[str, Any]] = None
        if isinstance(perf_trace, dict):
            video_trace = perf_trace.setdefault("video_generation", {})
            video_trace["input_image_count"] = len(images) if images else 0

        # 统一入口已取得账号硬并发槽位，持有至视频轮询与结果处理结束。
        normalized_tier = normalize_user_paygate_tier(token.user_paygate_tier)

        if video_trace is not None:
            video_trace["slot_wait_ms"] = 0

        await self._update_request_log_progress(
            request_log_state,
            token_id=token.id,
            status_text="preparing_video",
            progress=24,
        )

        try:
            # 获取模型类型和配置
            video_type = model_config.get("video_type")
            supports_images = model_config.get("supports_images", False)
            min_images = model_config.get("min_images", 0)
            max_images = model_config.get("max_images", 0)
            use_v2_model_config = bool(model_config.get("use_v2_model_config", False))

            # 根据账号tier自动调整模型 key
            user_tier = normalized_tier

            original_model_key = model_config["model_key"]
            model_key, tier_message = self._resolve_video_model_key_for_tier(
                model_config, user_tier
            )
            if tier_message:
                if stream:
                    yield self._create_stream_chunk(f"{tier_message}\n")
                debug_logger.log_info(
                    f"[VIDEO] 账号层级模型调整: {original_model_key} -> {model_key}"
                )
            elif user_tier == "PAYGATE_TIER_TWO" and original_model_key == model_key:
                debug_logger.log_info(
                    f"[VIDEO] TIER_TWO 账号，未找到有效 ultra 变体，保持模型: {model_key}"
                )

            # 更新 model_config 中的 model_key
            model_config = dict(model_config)  # 创建副本避免修改原配置
            model_config["model_key"] = model_key

            # 图片数量
            image_count = len(images) if images else 0

            # ========== 验证和处理图片 ==========

            # T2V: 文生视频 - 不支持图片
            if video_type == "t2v":
                if image_count > 0:
                    if stream:
                        yield self._create_stream_chunk(
                            "⚠️ 文生视频模型不支持上传图片,将忽略图片仅使用文本提示词生成\n"
                        )
                    debug_logger.log_warning(
                        f"[T2V] 模型 {model_config['model_key']} 不支持图片,已忽略 {image_count} 张图片"
                    )
                images = None  # 清空图片
                image_count = 0

            # Omni: 无图走 T2V，有图走当前上游 Reference Images 直连链路
            elif video_type == "omni":
                if max_images is not None and image_count > max_images:
                    error_msg = f"Omni 模型最多支持 {max_images} 张参考图，当前提供了 {image_count} 张"
                    if stream:
                        yield self._create_stream_chunk(f"{error_msg}\n")
                    self._mark_generation_failed(generation_result, error_msg)
                    yield self._create_error_response(error_msg, status_code=400)
                    return

            # I2V: 首尾帧模型 - 需要1-2张图片
            elif video_type == "i2v":
                if image_count < min_images or image_count > max_images:
                    error_msg = f"首尾帧模型需要 {min_images}-{max_images} 张图片，当前提供了 {image_count} 张"
                    if stream:
                        yield self._create_stream_chunk(f"{error_msg}\n")
                    self._mark_generation_failed(generation_result, error_msg)
                    yield self._create_error_response(error_msg, status_code=400)
                    return

            # R2V: 多图生成 - 当前上游协议最多 3 张参考图
            elif video_type == "r2v":
                if max_images is not None and image_count > max_images:
                    error_msg = f"多图视频模型最多支持 {max_images} 张参考图，当前提供了 {image_count} 张"
                    if stream:
                        yield self._create_stream_chunk(f"{error_msg}\n")
                    self._mark_generation_failed(generation_result, error_msg)
                    yield self._create_error_response(error_msg, status_code=400)
                    return

            # ========== 上传图片 ==========
            start_media_id = None
            end_media_id = None
            reference_images = []

            native_frames = bool(model_config.get("native_frames"))
            if native_frames and config.captcha_method != "browser":
                raise BrowserCaptchaError("native_frame_prepare", "native_mode_required")

            # Native Frames uploads these bytes within the same owned page as
            # submission; it never sends them through the detached HTTP uploader.
            # I2V: 首尾帧处理
            if video_type == "i2v" and images and not native_frames:
                if image_count == 1:
                    # 只有1张图: 仅作为首帧
                    if stream:
                        yield self._create_stream_chunk("上传首帧图片...\n")
                    start_media_id = await self.flow_client.upload_image(
                        token.at,
                        images[0],
                        model_config["aspect_ratio"],
                        project_id=project_id,
                        token_id=token.id,
                        google_cookies=getattr(token, "google_cookies", None),
                    )
                    debug_logger.log_info(f"[I2V] 仅上传首帧: {start_media_id}")

                elif image_count == 2:
                    # 2张图: 首帧+尾帧
                    if stream:
                        yield self._create_stream_chunk("上传首帧和尾帧图片...\n")
                    start_media_id = await self.flow_client.upload_image(
                        token.at,
                        images[0],
                        model_config["aspect_ratio"],
                        project_id=project_id,
                        token_id=token.id,
                        google_cookies=getattr(token, "google_cookies", None),
                    )
                    end_media_id = await self.flow_client.upload_image(
                        token.at,
                        images[1],
                        model_config["aspect_ratio"],
                        project_id=project_id,
                        token_id=token.id,
                        google_cookies=getattr(token, "google_cookies", None),
                    )
                    debug_logger.log_info(
                        f"[I2V] 上传首尾帧: {start_media_id}, {end_media_id}"
                    )

            # R2V: 多图处理
            elif video_type == "r2v" and images:
                if stream:
                    yield self._create_stream_chunk(
                        f"上传 {image_count} 张参考图片...\n"
                    )

                for img in images:
                    media_id = await self.flow_client.upload_image(
                        token.at,
                        img,
                        model_config["aspect_ratio"],
                        project_id=project_id,
                        token_id=token.id,
                        google_cookies=getattr(token, "google_cookies", None),
                    )
                    reference_images.append(
                        {
                        "imageUsageType": "IMAGE_USAGE_TYPE_ASSET",
                            "mediaId": media_id,
                        }
                    )
                debug_logger.log_info(
                    f"[R2V] 上传了 {len(reference_images)} 张参考图片"
                )

            # Omni R2V: 参考图上传到 project，随后走当前参考图视频 RPC
            elif video_type == "omni" and images:
                if stream:
                    yield self._create_stream_chunk(
                        f"上传 {image_count} 张 Omni 参考图片...\n"
                    )

                for img in images:
                    media_id = await self.flow_client.upload_image(
                        token.at,
                        img,
                        model_config["aspect_ratio"],
                        project_id=project_id,
                        token_id=token.id,
                        google_cookies=getattr(token, "google_cookies", None),
                    )
                    reference_images.append(
                        {
                        "imageUsageType": "IMAGE_USAGE_TYPE_ASSET",
                            "mediaId": media_id,
                        }
                    )
                debug_logger.log_info(
                    f"[VIDEO OMNI-R2V] 上传了 {len(reference_images)} 张参考图片"
                )

            # ========== 调用生成API ==========
            if stream:
                yield self._create_stream_chunk("提交视频生成任务...\n")
            submit_started_at = time.time()

            # I2V: 首尾帧生成
            if native_frames:
                result = await self.flow_client.generate_video_frames(
                    project_id=project_id, prompt=prompt,
                    model_key=model_config["model_key"], aspect_ratio=model_config["aspect_ratio"],
                    frame_images=images, resolution=model_config.get("resolution"),
                    token_id=token.id, token_video_concurrency=token.video_concurrency,
                    google_cookies=getattr(token, "google_cookies", None),
                )
            elif video_type == "i2v" and start_media_id:
                if end_media_id:
                    # 有首尾帧
                    result = await self.flow_client.generate_video_start_end(
                        at=token.at,
                        project_id=project_id,
                        prompt=prompt,
                        model_key=model_config["model_key"],
                        aspect_ratio=model_config["aspect_ratio"],
                        start_media_id=start_media_id,
                        end_media_id=end_media_id,
                        use_v2_model_config=use_v2_model_config,
                        user_paygate_tier=normalized_tier,
                        token_id=token.id,
                        token_video_concurrency=token.video_concurrency,
                        google_cookies=getattr(token, "google_cookies", None),
                    )
                else:
                    # 只有首帧 - 需要去掉 model_key 中的 _fl
                    # 情况1: _fl_ 在中间 (如 veo_3_1_i2v_s_fast_fl_ultra_relaxed -> veo_3_1_i2v_s_fast_ultra_relaxed)
                    # 情况2: _fl 在结尾 (如 veo_3_1_i2v_s_fast_ultra_fl -> veo_3_1_i2v_s_fast_ultra)
                    actual_model_key = model_config["model_key"].replace("_fl_", "_")
                    if actual_model_key.endswith("_fl"):
                        actual_model_key = actual_model_key[:-3]
                    debug_logger.log_info(
                        f"[I2V] 单帧模式，model_key: {model_config['model_key']} -> {actual_model_key}"
                    )
                    result = await self.flow_client.generate_video_start_image(
                        at=token.at,
                        project_id=project_id,
                        prompt=prompt,
                        model_key=actual_model_key,
                        aspect_ratio=model_config["aspect_ratio"],
                        start_media_id=start_media_id,
                        use_v2_model_config=use_v2_model_config,
                        user_paygate_tier=normalized_tier,
                        token_id=token.id,
                        token_video_concurrency=token.video_concurrency,
                        google_cookies=getattr(token, "google_cookies", None),
                    )

            # R2V: 多图生成
            elif video_type == "r2v" and reference_images:
                result = await self.flow_client.generate_video_reference_images(
                    at=token.at,
                    project_id=project_id,
                    prompt=prompt,
                    model_key=model_config["model_key"],
                    aspect_ratio=model_config["aspect_ratio"],
                    reference_images=reference_images,
                    user_paygate_tier=normalized_tier,
                    token_id=token.id,
                    token_video_concurrency=token.video_concurrency,
                    google_cookies=getattr(token, "google_cookies", None),
                )

            # Omni: 有图走 Reference Images 直连链路，无图走纯文本链路
            elif video_type == "omni" and reference_images:
                if stream:
                    yield self._create_stream_chunk("提交 Omni 参考图视频任务...\n")
                result = await self.flow_client.generate_video_reference_images(
                    at=token.at,
                    project_id=project_id,
                    prompt=prompt,
                    model_key=model_config.get("reference_model_key", "abra_r2v_8s"),
                    aspect_ratio=model_config["aspect_ratio"],
                    reference_images=reference_images,
                    user_paygate_tier=normalized_tier,
                    token_id=token.id,
                    token_video_concurrency=token.video_concurrency,
                    google_cookies=getattr(token, "google_cookies", None),
                )

            # Extend: 视频续写
            elif video_type == "extend":
                if not video_media_id:
                    error_msg = "视频续写需要提供源视频的 mediaGenerationId，请在 image_url 中传入 extend://VIDEO_MEDIA_ID"
                    if stream:
                        yield self._create_stream_chunk(f"{error_msg}\n")
                    self._mark_generation_failed(generation_result, error_msg)
                    yield self._create_error_response(error_msg, status_code=400)
                    return

                debug_logger.log_info(f"[EXTEND] 续写视频: {video_media_id}")
                if stream:
                    yield self._create_stream_chunk(
                        f"视频续写任务提交中，源视频: {video_media_id[:8]}...\n"
                    )
                result = await self.flow_client.generate_video_extend(
                    at=token.at,
                    project_id=project_id,
                    prompt=prompt,
                    video_media_id=video_media_id,
                    model_key=model_config["model_key"],
                    aspect_ratio=model_config["aspect_ratio"],
                    user_paygate_tier=normalized_tier,
                    token_id=token.id,
                    token_video_concurrency=token.video_concurrency,
                )

            # T2V 或 R2V无图: 纯文本生成
            else:
                result = await self.flow_client.generate_video_text(
                    at=token.at,
                    project_id=project_id,
                    prompt=prompt,
                    model_key=model_config["model_key"],
                    aspect_ratio=model_config["aspect_ratio"],
                    use_v2_model_config=use_v2_model_config,
                    user_paygate_tier=normalized_tier,
                    token_id=token.id,
                    token_video_concurrency=token.video_concurrency,
                    google_cookies=getattr(token, "google_cookies", None),
                    **({"resolution": model_config["resolution"]} if model_config.get("resolution") else {}),
                )
            if video_trace is not None:
                video_trace["submit_generation_ms"] = int(
                    (time.time() - submit_started_at) * 1000
                )

            direct_video_url = str(result.get("video_url") or "").strip()
            if result.get("direct_media") and direct_video_url:
                await self.token_manager.record_usage(token.id, is_video=True)
                await self.token_manager.record_success(token.id)
                if isinstance(generation_result, dict):
                    generation_result["usage_recorded"] = True
                routing_model = perf_trace.get("model", model_key) if isinstance(perf_trace, dict) else model_key
                self._record_routing_success(
                    token, "video", routing_model,
                    started_at=(generation_result or {}).get("routing_started_at"),
                )
                if self.proxy_manager and hasattr(
                    self.proxy_manager,
                    "record_attempt_success",
                ):
                    fingerprint = self.flow_client.get_request_fingerprint() or {}
                    await self.proxy_manager.record_attempt_success(
                        token.id,
                        str(fingerprint.get("proxy_url") or "").strip(),
                    )

                duration = time.time() - submit_started_at
                response_state["url"] = direct_video_url
                response_state["generated_assets"] = {
                    "type": "video",
                    "final_video_url": direct_video_url,
                    "delivery_mode": "frontend_direct_media",
                }
                await self._update_request_log_progress(
                    request_log_state,
                    token_id=token.id,
                    status_text="completed",
                    progress=100,
                )
                prompt_for_log = (
                    prompt if len(prompt) <= 2000 else f"{prompt[:2000]}...(truncated)"
                )
                await self._log_request(
                    token.id,
                    "generate_video",
                    {
                        "model": model_key,
                        "prompt": prompt_for_log,
                        "delivery_mode": "frontend_direct_media",
                    },
                    {
                        "status": "success",
                        "model": model_key,
                        "prompt": prompt_for_log,
                        "url": direct_video_url,
                        "performance": {
                            "status": "success",
                            "total_ms": int(duration * 1000),
                        },
                    },
                    200,
                    duration,
                    log_id=request_log_state.get("id"),
                    status_text="completed",
                    progress=100,
                )
                self._mark_generation_succeeded(generation_result)
                if stream:
                    yield self._create_stream_chunk(
                        f"<video src='{direct_video_url}' controls style='max-width:100%'></video>",
                        finish_reason="stop",
                    )
                else:
                    yield self._create_completion_response(
                        direct_video_url,
                        media_type="video",
                    )
                return

            # 获取task_id和operations
            operations = result.get("operations", [])
            if not operations:
                self._mark_generation_failed(
                    generation_result,
                    "\u751f\u6210\u4efb\u52a1\u521b\u5efa\u5931\u8d25",
                )
                yield self._create_error_response("生成任务创建失败", status_code=502)
                return

            operation = operations[0]
            task_id = operation["operation"]["name"]
            scene_id = operation.get("sceneId")
            if isinstance(generation_result, dict):
                # Keep acceptance evidence before the first database await, so
                # cancellation during create_task()/accepted() can recover it.
                generation_result["submitted_video"] = {
                    "operations": deepcopy(operations), "project_id": project_id,
                    "model": model_config["model_key"], "prompt": prompt, "scene_id": scene_id,
                }

            # 保存Task到数据库
            task = Task(
                task_id=task_id,
                token_id=token.id,
                model=model_config["model_key"],
                prompt=prompt,
                status="processing",
                scene_id=scene_id,
            )
            await self.db.create_task(task)
            client_submission_id = (request_log_state or {}).get('client_submission_id')
            if client_submission_id:
                ledger = SubmissionLedger(self.db)
                await ledger.accepted(client_submission_id, token.id, project_id, operations)
                if stream:
                    yield 'data: ' + json.dumps({'submission': ledger.public(client_submission_id, await ledger.get(client_submission_id))}, ensure_ascii=False) + '\n\n'
            await self._update_request_log_progress(
                request_log_state,
                token_id=token.id,
                status_text="video_submitted",
                progress=45,
                response_extra={"task_id": task_id, "scene_id": scene_id},
            )

            # 轮询结果
            if stream:
                yield self._create_stream_chunk(f"视频生成中...\n")

            # 检查是否需要放大
            upsample_config = model_config.get("upsample")

            # 如果是 extend，传入源视频 media_id 用于后续拼接
            extend_source_id = video_media_id if video_type == "extend" else None
            async with aclosing(self._poll_video_result(
                token,
                project_id,
                operations,
                stream,
                upsample_config,
                generation_result,
                response_state,
                request_log_state,
                extend_source_media_id=extend_source_id,
            )) as chunks:
                async for chunk in chunks:
                    yield chunk

        except (asyncio.CancelledError, GeneratorExit) as interruption:
            await self._preserve_interrupted_video(
                token, generation_result, request_log_state,
                reason="client_disconnected" if isinstance(interruption, asyncio.CancelledError) else "generator_closed")
            raise

    async def _poll_video_result(
        self, token, project_id: str, operations: List[Dict], stream: bool,
        upsample_config: Optional[Dict] = None, generation_result: Optional[Dict[str, Any]] = None,
        response_state: Optional[Dict[str, Any]] = None, request_log_state: Optional[Dict[str, Any]] = None,
        extend_source_media_id: Optional[str] = None,
    ) -> AsyncGenerator:
        if generation_result is None:
            generation_result = self._create_generation_result()
        generation_result.setdefault("submitted_video", {
            "operations": deepcopy(operations), "project_id": project_id,
        })
        try:
            async with aclosing(self._poll_video_result_inner(
                token, project_id, operations, stream, upsample_config, generation_result,
                response_state, request_log_state, extend_source_media_id,
            )) as chunks:
                async for chunk in chunks:
                    yield chunk
        except (asyncio.CancelledError, GeneratorExit) as interruption:
            await self._preserve_interrupted_video(
                token, generation_result, request_log_state,
                reason="client_disconnected" if isinstance(interruption, asyncio.CancelledError) else "generator_closed")
            raise

    async def _poll_video_result_inner(
        self,
        token,
        project_id: str,
        operations: List[Dict],
        stream: bool,
        upsample_config: Optional[Dict] = None,
        generation_result: Optional[Dict[str, Any]] = None,
        response_state: Optional[Dict[str, Any]] = None,
        request_log_state: Optional[Dict[str, Any]] = None,
        extend_source_media_id: Optional[str] = None,
    ) -> AsyncGenerator:
        """轮询视频生成结果
        
        Args:
            upsample_config: 放大配置 {"resolution": "VIDEO_RESOLUTION_4K", "model_key": "veo_3_1_upsampler_4k"}
        """

        if response_state is None:
            response_state = self._create_response_state()

        normalized_tier = normalize_user_paygate_tier(token.user_paygate_tier)
        max_attempts = config.max_poll_attempts
        poll_interval = config.poll_interval
        
        # 如果需要放大，轮询次数加倍（放大可能需要 30 分钟）
        if upsample_config:
            max_attempts = max_attempts * 3  # 放大需要更长时间

        consecutive_poll_errors = 0
        last_poll_error: Optional[Exception] = None
        max_consecutive_poll_errors = 3

        for attempt in range(max_attempts):
            await asyncio.sleep(poll_interval)

            try:
                result = await self.flow_client.check_video_status(
                    token.at,
                    operations,
                    token_id=token.id,
                    google_cookies=getattr(token, "google_cookies", None),
                )
                checked_operations = result.get("operations", [])
                consecutive_poll_errors = 0
                last_poll_error = None

                if not checked_operations:
                    continue

                operation = checked_operations[0]
                status = operation.get("status")

                # 状态更新 - 每20秒报告一次 (poll_interval=3秒, 20秒约7次轮询)
                progress_update_interval = 7  # 每7次轮询 = 21秒
                if stream and attempt % progress_update_interval == 0:  # 每20秒报告一次
                    progress = min(int((attempt / max_attempts) * 100), 95)
                    await self._update_request_log_progress(
                        request_log_state,
                        token_id=token.id,
                        status_text="video_polling",
                        progress=max(45, progress),
                        response_extra={"upstream_status": status},
                    )
                    yield self._create_stream_chunk(f"生成进度: {progress}%\n")

                # 检查状态
                if status == "MEDIA_GENERATION_STATUS_SUCCESSFUL":
                    try:
                        resolved_video = await self._resolve_video_asset(
                            token, operation
                        )
                    except Exception as redirect_error:
                        media_name = (
                            operation.get("mediaName")
                            or operation.get("name")
                            or operation["operation"].get("name")
                        )
                        error_msg = f"视频生成成功但获取媒体地址失败: {self._normalize_error_message(redirect_error)}"
                        debug_logger.log_warning(
                            f"[VIDEO POLL] 获取视频URL失败: media={media_name}, error={redirect_error}"
                        )
                        await self._fail_video_task(checked_operations, error_msg)
                        self._mark_generation_failed(generation_result, error_msg)
                        yield self._create_error_response(error_msg, status_code=502)
                        return

                    video_url = resolved_video["video_url"]
                    video_media_id = resolved_video["video_media_id"]
                    aspect_ratio = resolved_video["aspect_ratio"]
                    media_name = resolved_video["media_name"]
                    metadata = resolved_video["metadata"]
                    video_info = resolved_video["video_info"]

                    if not video_url:
                        media_name_for_fetch = operation.get("mediaName") or operation[
                            "operation"
                        ].get("name", "")
                        if media_name_for_fetch:
                            if stream:
                                yield self._create_stream_chunk(
                                    "视频生成完成，正在下载视频文件...\n"
                                )
                            try:
                                media_result = await self.flow_client.get_media(
                                    token.at,
                                    media_name_for_fetch,
                                    token_id=token.id,
                                    google_cookies=getattr(
                                        token, "google_cookies", None
                                    ),
                                    project_id=project_id,
                                )
                                encoded_video = media_result.get("video", {}).get(
                                    "encodedVideo", ""
                                )
                                if encoded_video:
                                    cached_filename = (
                                        await self.file_cache.cache_base64_video(
                                        encoded_video
                                    )
                                    )
                                    video_url = f"{self._get_base_url(response_state)}/tmp/{cached_filename}"
                                    video_info["fifeUrl"] = video_url
                                    debug_logger.log_info(
                                        f"[VIDEO] Video fetched via get_media and cached: {cached_filename}"
                                    )
                                else:
                                    debug_logger.log_error(
                                        "[VIDEO] get_media returned empty encodedVideo"
                                    )
                            except Exception as fetch_err:
                                debug_logger.log_error(
                                    f"[VIDEO] Failed to fetch video via get_media: {fetch_err}"
                                )

                    if not video_url:
                        error_msg = "视频生成成功但未获取到媒体地址"
                        await self._fail_video_task(checked_operations, error_msg)
                        self._mark_generation_failed(generation_result, error_msg)
                        yield self._create_error_response(error_msg, status_code=502)
                        return

                    video_info["url"] = video_url
                    video_info["mediaName"] = media_name
                    video_info["mediaGenerationId"] = video_media_id
                    metadata.setdefault("video", video_info)
                    operation["operation"]["metadata"] = metadata

                    # ========== 视频放大处理 ==========
                    if upsample_config and video_media_id:
                        if stream:
                            resolution_name = (
                                "4K"
                                if "4K" in upsample_config["resolution"]
                                else "1080P"
                            )
                            yield self._create_stream_chunk(
                                f"\n视频生成完成，开始 {resolution_name} 放大处理...（可能需要 30 分钟）\n"
                            )
                        
                        try:
                            # 提交放大任务
                            upsample_result = await self.flow_client.upsample_video(
                                at=token.at,
                                project_id=project_id,
                                video_media_id=video_media_id,
                                aspect_ratio=aspect_ratio,
                                resolution=upsample_config["resolution"],
                                model_key=upsample_config["model_key"],
                                user_paygate_tier=normalized_tier,
                                token_id=token.id,
                                token_video_concurrency=token.video_concurrency,
                                google_cookies=getattr(token, "google_cookies", None),
                            )
                            
                            upsample_operations = upsample_result.get("operations", [])
                            if upsample_operations:
                                if stream:
                                    yield self._create_stream_chunk(
                                        "放大任务已提交，继续轮询...\n"
                                    )
                                
                                # 递归轮询放大结果（不再放大）
                                async with aclosing(self._poll_video_result(
                                    token,
                                    project_id,
                                    upsample_operations,
                                    stream,
                                    None,
                                    generation_result,
                                    response_state,
                                    request_log_state,
                                )) as chunks:
                                    async for chunk in chunks:
                                        yield chunk
                                return
                            else:
                                if stream:
                                    yield self._create_stream_chunk(
                                        "⚠️ 放大任务创建失败，返回原始视频\n"
                                    )
                        except Exception as e:
                            debug_logger.log_error(f"Video upsample failed: {str(e)}")
                            if stream:
                                yield self._create_stream_chunk(
                                    f"⚠️ 放大失败: {str(e)}，返回原始视频\n"
                            )
                            
                    # Current Flow returns the generated extend media as its own
                    # asset. There is no current frontend RPC that concatenates
                    # two media IDs, so never label this single segment as a
                    # completed 16-second composite.
                    if extend_source_media_id and video_media_id and stream:
                        yield self._create_stream_chunk(
                            "续写片段已生成；当前 Flow 前端未提供媒体拼接 RPC，返回续写片段。\n"
                        )

                    # 缓存视频 (如果启用)
                    local_url = video_url
                    if config.cache_enabled:
                        await self._update_request_log_progress(
                            request_log_state,
                            token_id=token.id,
                            status_text="caching_video",
                            progress=92,
                        )
                        try:
                            if stream:
                                yield self._create_stream_chunk("正在缓存视频文件...\n")
                            cached_filename = await self.file_cache.download_and_cache(
                                video_url, "video"
                            )
                            local_url = f"{self._get_base_url(response_state)}/tmp/{cached_filename}"
                            if stream:
                                yield self._create_stream_chunk(
                                    "✅ 视频缓存成功,准备返回缓存地址...\n"
                                )
                        except Exception as e:
                            debug_logger.log_error(f"Failed to cache video: {str(e)}")
                            # 缓存失败不影响结果返回,使用原始URL
                            local_url = video_url
                            if stream:
                                cache_error = self._normalize_error_message(
                                    e, max_length=120
                                )
                                yield self._create_stream_chunk(
                                    f"⚠️ 缓存失败: {cache_error}\n正在返回源链接...\n"
                                )
                    else:
                        if stream:
                            yield self._create_stream_chunk(
                                "缓存已关闭,正在返回源链接...\n"
                            )

                    # 更新数据库
                    task_id = operation["operation"]["name"]
                    await self.db.update_task(
                        task_id,
                        status="completed",
                        progress=100,
                        result_urls=[local_url],
                        completed_at=time.time(),
                    )

                    # 存储URL用于日志记录
                    response_state["url"] = local_url
                    response_state["generated_assets"] = {
                        "type": "video",
                        "final_video_url": local_url,
                        "mediaGenerationId": video_media_id,
                        "mediaName": media_name,
                        "aspectRatio": aspect_ratio,
                        "model": resolved_video.get("model"),
                        "duration": resolved_video.get("duration"),
                    }

                    # 返回结果
                    self._mark_generation_succeeded(generation_result)

                    if stream:
                        yield self._create_stream_chunk(
                            f"<video src='{local_url}' data-media-id='{video_media_id}' controls style='max-width:100%'></video>",
                            finish_reason="stop",
                        )

                    else:
                        yield self._create_completion_response(
                            local_url,  # 直接传URL,让方法内部格式化
                            media_type="video",
                        )
                    return

                elif status == "MEDIA_GENERATION_STATUS_FAILED":
                    # 生成失败 - 提取错误信息
                    error_info = operation.get("operation", {}).get("error", {})
                    error_code = error_info.get("code", "unknown")
                    error_message = error_info.get("message", "未知错误")
                    
                    # 更新数据库任务状态
                    await self._fail_video_task(
                        checked_operations, f"{error_message} (code: {error_code})"
                    )
                    
                    # 返回友好的错误消息，提示用户重试
                    friendly_error = f"视频生成失败: {error_message}，请重试"
                    self._mark_generation_failed(generation_result, friendly_error)
                    if stream:
                        yield self._create_stream_chunk(f"错误: {friendly_error}\n")
                    yield self._create_error_response(friendly_error, status_code=502, code='video_generation_failed', submission_pending=False, upstream_accepted=True)
                    return

                elif status.startswith("MEDIA_GENERATION_STATUS_ERROR"):
                    # ??????
                    error_msg = f"视频生成失败: {status}"
                    await self._fail_video_task(checked_operations, error_msg)
                    self._mark_generation_failed(generation_result, error_msg)
                    yield self._create_error_response(error_msg, status_code=502, code='video_generation_failed', submission_pending=False, upstream_accepted=True)
                    return
                    
                elif status == "MEDIA_GENERATION_STATUS_ACTIVE" and attempt > 80:
                    # A local polling deadline does not cancel the upstream job.
                    yield await self._video_status_unknown(
                        token, operations, generation_result, request_log_state,
                        reason="poll_deadline",
                    )
                    return

            except Exception as e:
                last_poll_error = e
                consecutive_poll_errors += 1
                debug_logger.log_error(f"Poll error: {str(e)}")
                if consecutive_poll_errors >= max_consecutive_poll_errors:
                    yield await self._video_status_unknown(
                        token, operations, generation_result, request_log_state,
                        reason="poll_auth_failed" if re.search(r"401|UNAUTHENTICATED", str(e), re.I) else "poll_failed",
                    )
                    return
                continue

        yield await self._video_status_unknown(
            token, operations, generation_result, request_log_state,
            reason="poll_failed" if last_poll_error is not None else "poll_deadline",
        )

    # ========== 响应格式化 ==========

    def _create_stream_chunk(
        self, content: str, role: str = None, finish_reason: str = None
    ) -> str:
        """创建流式响应chunk"""
        import json
        import time

        chunk = {
            "id": f"chatcmpl-{int(time.time())}",
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": "flow2api",
            "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
        }

        if role:
            chunk["choices"][0]["delta"]["role"] = role

        if finish_reason:
            chunk["choices"][0]["delta"]["content"] = content
        else:
            chunk["choices"][0]["delta"]["reasoning_content"] = content

        return f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"

    def _create_completion_response(
        self,
        content: str,
        media_type: str = "image",
        is_availability_check: bool = False,
    ) -> str:
        """创建非流式响应

        Args:
            content: 媒体URL或纯文本消息
            media_type: 媒体类型 ("image" 或 "video")
            is_availability_check: 是否为可用性检查响应 (纯文本消息)

        Returns:
            JSON格式的响应
        """
        import json
        import time

        # 可用性检查: 返回纯文本消息
        if is_availability_check:
            formatted_content = content
        else:
            # 媒体生成: 根据媒体类型格式化内容为Markdown
            if media_type == "video":
                formatted_content = (
                    f"```html\n<video src='{content}' controls></video>\n```"
                )
            else:  # image
                formatted_content = f"![Generated Image]({content})"

        response = {
            "id": f"chatcmpl-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "flow2api",
            "choices": [
                {
                "index": 0,
                    "message": {"role": "assistant", "content": formatted_content},
                    "finish_reason": "stop",
                }
            ],
        }

        return json.dumps(response, ensure_ascii=False)

    @staticmethod
    def _safe_native_submission_diagnostic(value):
        if not isinstance(value, dict):
            return None
        result = {}
        for key in ("stage", "reason", "failure_kind"):
            item = value.get(key)
            if isinstance(item, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item):
                result[key] = item
        error_kind = value.get("error_kind")
        if isinstance(error_kind, str) and error_kind in {"TimeoutError", "Error", "TargetClosedError", "BrowserCaptchaError", "RuntimeError", "TypeError", "ValueError", "CancelledError", "other", "timeout", "browser_operation_failed"}:
            result["error_kind"] = error_kind
        for key in ("armed", "request_admitted", "forwarding_started", "request_forwarded", "page_closed"):
            if type(value.get(key)) is bool:
                result[key] = value[key]
        for key in ("submit_attempts", "elapsed_ms"):
            if type(value.get(key)) is int and 0 <= value[key] <= 3600000:
                result[key] = value[key]
        return result or None

    def _create_error_response(
        self,
        error_message: str,
        status_code: int = 500,
        code: str = "generation_failed",
        submission_pending: Optional[bool] = None,
        upstream_accepted: Optional[bool] = None,
        reason: Optional[str] = None,
        native_submission_diagnostic: Optional[Dict[str, Any]] = None,
    ) -> str:
        """创建错误响应

        submission_pending=False 明确表示请求在提交到上游之前就被拒绝（例如没有可用账号），
        客户端可据此放心清除"待确认"标记；None 表示不作声明。
        """
        import json

        error = {
            "error": {
                "message": error_message,
                "type": "server_error"
                if status_code >= 500
                else "invalid_request_error",
                "code": code,
                "status_code": status_code,
            }
        }
        if submission_pending is not None:
            error["error"]["submission_pending"] = submission_pending
        if upstream_accepted is not None:
            error['error']['upstream_accepted'] = upstream_accepted
        if reason is not None:
            error['error']['reason'] = reason
        diagnostic = self._safe_native_submission_diagnostic(native_submission_diagnostic)
        if diagnostic:
            error['error']['native_submission_diagnostic'] = diagnostic

        return json.dumps(error, ensure_ascii=False)

    def _get_base_url(self, response_state: Optional[Dict[str, Any]] = None) -> str:
        """获取基础URL用于缓存文件访问"""
        # 已配置缓存访问域名时，始终优先使用它，避免被请求 Host/IP 覆盖。
        if config.cache_base_url:
            return config.cache_base_url.rstrip("/")

        request_base_url = ""
        if isinstance(response_state, dict):
            request_base_url = (
                (response_state.get("base_url") or "").strip().rstrip("/")
            )
        if request_base_url:
            return request_base_url

        # 回退到服务地址，避免把监听地址 0.0.0.0 / :: 直接返回给客户端
        server_host = (config.server_host or "").strip()
        if server_host in {"", "0.0.0.0", "::", "[::]"}:
            server_host = "127.0.0.1"

        return f"http://{server_host}:{config.server_port}"

    async def _update_request_log_progress(
        self,
        request_log_state: Optional[Dict[str, Any]],
        *,
        token_id: Optional[int] = None,
        status_text: str,
        progress: int,
        response_extra: Optional[Dict[str, Any]] = None,
    ):
        """?????????????"""
        if not isinstance(request_log_state, dict):
            return
        log_id = request_log_state.get("id")
        if not log_id:
            return

        safe_progress = max(0, min(100, int(progress)))
        now = time.time()
        last_status_text = str(request_log_state.get("last_status_text") or "").strip()
        last_progress = int(request_log_state.get("last_progress") or 0)
        last_updated_at = float(request_log_state.get("last_progress_update_at") or 0)

        request_log_state["progress"] = safe_progress
        request_log_state["last_status_text"] = status_text
        request_log_state["last_progress"] = safe_progress
        payload = {
            "status": "processing",
            "status_text": status_text,
            "progress": safe_progress,
        }
        if isinstance(response_extra, dict):
            payload.update(response_extra)

        should_write = (
            safe_progress in (0, 100)
            or status_text != last_status_text
            or safe_progress >= last_progress + 5
            or (now - last_updated_at) >= 1.0
        )
        if not should_write:
            return

        request_log_state["last_progress_update_at"] = now

        try:
            await self.db.update_request_log(
                log_id,
                token_id=token_id,
                response_body=json.dumps(payload, ensure_ascii=False),
                status_code=102,
                duration=0,
                status_text=status_text,
                progress=safe_progress,
            )
        except Exception as e:
            debug_logger.log_error(f"Failed to update request log progress: {e}")

    async def _log_request(
        self,
        token_id: Optional[int],
        operation: str,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
        status_code: int,
        duration: float,
        log_id: Optional[int] = None,
        status_text: Optional[str] = None,
        progress: Optional[int] = None,
    ):
        """???????????? log_id ????????"""
        try:
            effective_status_text = status_text or (
                "completed"
                if status_code == 200
                else "failed"
                if status_code >= 400
                else "processing"
            )
            effective_progress = progress
            if effective_progress is None:
                effective_progress = (
                    100 if status_code == 200 else 0 if status_code >= 400 else 0
                )
            effective_progress = max(0, min(100, int(effective_progress)))

            request_body = json.dumps(request_data, ensure_ascii=False)
            response_body = json.dumps(response_data, ensure_ascii=False)

            if log_id:
                await self.db.update_request_log(
                    log_id,
                    token_id=token_id,
                    operation=operation,
                    request_body=request_body,
                    response_body=response_body,
                    status_code=status_code,
                    duration=duration,
                    status_text=effective_status_text,
                    progress=effective_progress,
                )
                return log_id

            log = RequestLog(
                token_id=token_id,
                operation=operation,
                request_body=request_body,
                response_body=response_body,
                status_code=status_code,
                duration=duration,
                status_text=effective_status_text,
                progress=effective_progress,
            )
            return await self.db.add_request_log(log)
        except Exception as e:
            debug_logger.log_error(f"Failed to log request: {e}")
            return None
