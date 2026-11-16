"""Load balancing module for Flow2API"""

import asyncio
import math
import random
import re
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Optional, Dict
from ..core.models import Token
from ..core.config import config
from ..core.account_tiers import (
    get_paygate_tier_label,
    get_required_paygate_tier_for_model,
    normalize_user_paygate_tier,
    supports_model_for_tier,
)
from .concurrency_manager import ConcurrencyManager
from ..core.logger import debug_logger
from ..core.account_audit import audit_account_operation
from .captcha_errors import BrowserCaptchaError
from .flow_frontend import FlowRPCRejected
from .token_manager import TokenManager


@dataclass
class _GenerationCooldown:
    identity: str
    reason: str
    failures: int
    retry_after: float
    last_failure: float
    account: str = ""
    credit_balance: Optional[int] = None


class LoadBalancer:
    """Token load balancer with load-aware selection"""

    def __init__(
        self, token_manager, concurrency_manager: Optional[ConcurrencyManager] = None
    ):
        self.token_manager = token_manager
        self.concurrency_manager = concurrency_manager
        self._image_pending: Dict[int, int] = {}
        self._video_pending: Dict[int, int] = {}
        self._pending_lock = asyncio.Lock()
        self._pending_selection_lock = asyncio.Lock()
        self._round_robin_state: Dict[str, Optional[int]] = {
            "image": None,
            "video": None,
            "default": None,
        }
        self._rr_lock = asyncio.Lock()
        self._selection_health = ContextVar("selection_health", default=None)
        self._generation_cooldowns: dict[tuple[int, str, Optional[str], str], _GenerationCooldown] = {}

    @staticmethod
    def _generation_scope(for_image_generation: bool, for_video_generation: bool) -> str:
        return "image" if for_image_generation else ("video" if for_video_generation else "default")

    @staticmethod
    def _below_video_credit_floor(token: Token) -> bool:
        """An account that cannot pay for another video only burns an attempt."""
        floor = getattr(config, "flow_min_video_credits", 10)
        credits = getattr(token, "credits", None)
        return bool(floor) and credits is not None and credits < floor

    def _validation_cooldown_reason(self, token: Token) -> Optional[str]:
        """Check the account's current identity before any route preparation."""
        getter = getattr(self.token_manager, "get_validation_cooldown_reason", None)
        reason = getter(token) if callable(getter) else None
        return reason if isinstance(reason, str) and reason.strip() else None

    @staticmethod
    def _generation_failure_category(error, scope: str, model: Optional[str]):
        """Only fixed, typed runtime failures affect temporary routing health."""
        # Routing away from an explicit traffic rejection does not establish
        # submission acceptance/rejection. Image RPCs have a separate evidence
        # contract, so do not use or change submission_rejected here.
        if isinstance(error, FlowRPCRejected) and error.error_code in {
            "PUBLIC_ERROR_UNUSUAL_ACTIVITY", "PUBLIC_ERROR_UNUSUAL_ACTIVITY_TOO_MUCH_TRAFFIC",
        }:
            return "all", None, f"上游流量限制 [{error.error_code}]", 300, 1800
        if not isinstance(error, BrowserCaptchaError) or error.submission_pending is not False:
            return None
        stage, reason = error.stage, error.reason
        if stage == "native_submit_prepare" and reason == "insufficient_credits":
            # A model can cost more than another capability. Keep this circuit
            # scoped to the selection that displayed the explicit UI warning.
            return scope, model, "当前模型积分不足 [insufficient_credits]", 900, 3600
        setup_reasons = {f"{phase}_failed" for phase in (
            "open", "summary_find", "summary_click", "panel_wait", "mode", "model",
            "duration", "submode", "resolution", "ratio", "count", "save",
            "verify_mode", "verify_model", "verify_duration", "verify_ratio", "verify_count",
        )}
        if stage == "native_generation_setup" and reason in setup_reasons:
            model_scope = model if reason in {"model_failed", "verify_model_failed", "resolution_failed"} else None
        elif stage == "native_frame_upload" and re.fullmatch(r"(?:frame_[12]_(?:open|chooser|binding|bound)_failed|frame_slots_failed|initial_slots_not_empty|other_slot_changed|uploaded_asset_mismatch|frame_binding_changed)", reason):
            model_scope = None
        elif stage in {"native_page_creation", "native_route_registration"} and reason == "browser_closed":
            model_scope = None
        elif stage in {
            "navigation", "page_loaded", "editor_readiness", "editor_wait", "editor_input", "submit_button",
            "page_warmup", "recaptcha_readiness", "native_page_prepare", "native_page_prepare_retry",
            "native_editor_input", "native_submit_prepare", "native_submit",
        } and reason in {
            "browser_operation_failed", "navigation_failed", "timeout", "flow_editor_unavailable",
            "flow_page_unavailable", "prompt_input_mismatch", "prompt_changed_during_upload",
            "submit_unavailable", "proxy_connection_failed", "editor_missing", "project_not_found",
            "network_empty_response", "network_connection_failed", "navigation_interrupted",
            "submit_control_missing", "submit_control_not_ready",
            "browser_closed", "element_detached", "click_intercepted", "submit_disabled",
        }:
            model_scope = None
        else:
            return None
        return scope, model_scope, f"浏览器生成准备不可用 [{stage}/{reason}]", 60, 600

    async def record_generation_failure(
        self, token_id: int, error, *, for_image_generation: bool = False,
        for_video_generation: bool = False, model: Optional[str] = None,
        token: Optional[Token] = None,
    ) -> bool:
        """Temporarily route new work away from a failed account/capability.

        This changes neither account activation nor accepted operation state.
        Each expired circuit permits normal selection again; repeat failures
        back off within a bounded window instead of permanently banning it.
        """
        scope = self._generation_scope(for_image_generation, for_video_generation)
        category = self._generation_failure_category(error, scope, model)
        if category is None:
            return False
        if token is None:
            token = await self.token_manager.get_token(token_id)
        if token is None:
            return False
        scope, model_scope, reason, base_seconds, max_seconds = category
        identity = TokenManager.health_identity(token)
        account = TokenManager.account_identity(token)
        # Keep concurrent old/new credential snapshots separate. A late failure
        # from an old request must not overwrite the current route's circuit.
        key = (int(token_id), scope, model_scope, identity)
        now = time.monotonic()
        self._prune_generation_cooldowns(now)
        previous_key, previous = key, self._generation_cooldowns.get(key)
        if previous is None:
            # Exit rotation moves an account to a new route, and so a new identity,
            # after each failed generation. The same credentials on another route
            # continue the streak; otherwise every repeat would restart at the
            # first step and a persistently failing account is retried too soon.
            streak = [
                (other, item) for other, item in self._generation_cooldowns.items()
                if other[:3] == key[:3] and item.account == account
            ]
            if streak:
                previous_key, previous = max(streak, key=lambda row: row[1].last_failure)
        failures = 1
        if previous and now - previous.last_failure <= 3600:
            failures = min(previous.failures + 1, 6)
        cooldown_seconds = min(max_seconds, base_seconds * (2 ** (failures - 1)))
        self._generation_cooldowns.pop(previous_key, None)
        self._generation_cooldowns[key] = _GenerationCooldown(
            identity, reason, failures, now + cooldown_seconds, now, account,
            credit_balance=(getattr(token, "credits", None)
                            if isinstance(error, BrowserCaptchaError) and error.reason == "insufficient_credits"
                            else None),
        )
        # Only fixed categories are logged, never upstream bodies/credentials.
        debug_logger.logger.warning(
            "[GENERATION_HEALTH] scope=%s reason=%s decision=cooldown seconds=%s",
            scope, reason, cooldown_seconds,
        )
        await audit_account_operation(
            getattr(self.token_manager, "db", None), token_id,
            operation="generation", status="cooldown",
            reason="traffic_restriction" if isinstance(error, FlowRPCRejected) else getattr(error, "reason", "validation_failed"),
            stage=getattr(error, "stage", "routing"), source="generation", token=token,
            details={"cooldown_seconds": cooldown_seconds, "attempt": failures},
        )
        return True

    def record_generation_success(
        self, token_id: int, *, for_image_generation: bool = False,
        for_video_generation: bool = False, model: Optional[str] = None,
        token: Optional[Token] = None, started_at: Optional[float] = None,
    ) -> None:
        scope = self._generation_scope(for_image_generation, for_video_generation)
        account = TokenManager.account_identity(token) if token is not None else None
        scopes = {(int(token_id), "all", None), (int(token_id), scope, None), (int(token_id), scope, model)}
        for key, cooldown in tuple(self._generation_cooldowns.items()):
            # Credentials decide whose failure this clears. The route may have
            # moved on since the request started, which does not undo a success.
            if key[:3] not in scopes or (account is not None and cooldown.account != account):
                continue
            # A previously accepted operation finishing now does not prove a
            # route recovered from a rejection that happened after it started.
            if started_at is not None and cooldown.last_failure > started_at:
                continue
            self._generation_cooldowns.pop(key, None)

    def _prune_generation_cooldowns(self, now: float) -> None:
        for key, cooldown in tuple(self._generation_cooldowns.items()):
            if now - cooldown.last_failure > 3600:
                self._generation_cooldowns.pop(key, None)

    def get_generation_cooldown_reason(
        self, token: Token, *, for_image_generation: bool = False,
        for_video_generation: bool = False, model: Optional[str] = None,
    ) -> Optional[str]:
        scope = self._generation_scope(for_image_generation, for_video_generation)
        identity = TokenManager.health_identity(token)
        now = time.monotonic()
        self._prune_generation_cooldowns(now)
        reasons = []
        for key in dict.fromkeys(((int(token.id), "all", None, identity), (int(token.id), scope, None, identity), (int(token.id), scope, model, identity))):
            cooldown = self._generation_cooldowns.get(key)
            if cooldown is None:
                continue
            credits = getattr(token, "credits", None)
            if (cooldown.credit_balance is not None and credits is not None
                    and credits > cooldown.credit_balance):
                # A refreshed/top-up balance permits a new UI check immediately;
                # the warning remains authoritative if it still cannot pay.
                self._generation_cooldowns.pop(key, None)
                continue
            if cooldown.retry_after > now:
                remaining = math.ceil(cooldown.retry_after - now)
                reasons.append(f"{cooldown.reason}（临时冷却，{remaining} 秒后可重试）")
        return "; ".join(reasons) if reasons else None

    @staticmethod
    def _selection_unavailable_message(health_failures, cooldown_failures, credit_failures=()) -> str:
        if not cooldown_failures and not credit_failures:
            return LoadBalancer._health_unavailable_message(health_failures)
        return "当前符合条件的账号暂时无法生成：" + "; ".join(dict.fromkeys(
            list(credit_failures) + cooldown_failures + health_failures
        ))

    @staticmethod
    def _health_unavailable_message(reasons) -> str:
        return (
            "当前符合条件的账号均未通过上游校验，暂时无法生成："
            + "; ".join(dict.fromkeys(reason.strip() for reason in reasons))
        )

    async def _get_pending_count(
        self, token_id: int, for_image_generation: bool, for_video_generation: bool
    ) -> int:
        async with self._pending_lock:
            if for_image_generation:
                return max(0, int(self._image_pending.get(token_id, 0)))
            if for_video_generation:
                return max(0, int(self._video_pending.get(token_id, 0)))
            return 0

    async def _add_pending(
        self, token_id: int, for_image_generation: bool, for_video_generation: bool
    ):
        async with self._pending_lock:
            if for_image_generation:
                self._image_pending[token_id] = (
                    max(0, int(self._image_pending.get(token_id, 0))) + 1
                )
            elif for_video_generation:
                self._video_pending[token_id] = (
                    max(0, int(self._video_pending.get(token_id, 0))) + 1
                )

    async def release_pending(
        self,
        token_id: int,
        for_image_generation: bool = False,
        for_video_generation: bool = False,
    ):
        async with self._pending_lock:
            if for_image_generation:
                current = max(0, int(self._image_pending.get(token_id, 0)))
                if current <= 1:
                    self._image_pending.pop(token_id, None)
                else:
                    self._image_pending[token_id] = current - 1
            elif for_video_generation:
                current = max(0, int(self._video_pending.get(token_id, 0)))
                if current <= 1:
                    self._video_pending.pop(token_id, None)
                else:
                    self._video_pending[token_id] = current - 1

    async def _get_token_load(
        self, token_id: int, for_image_generation: bool, for_video_generation: bool
    ) -> tuple[int, Optional[int]]:
        """获取 token 当前负载。

        Returns:
            (inflight, remaining)
            remaining 为 None 表示无限制
        """
        if not self.concurrency_manager:
            return await self._get_pending_count(
                token_id, for_image_generation, for_video_generation
            ), None

        if for_image_generation:
            inflight = await self.concurrency_manager.get_image_inflight(token_id)
            remaining = await self.concurrency_manager.get_image_remaining(token_id)
            pending = await self._get_pending_count(token_id, True, False)
            effective_inflight = inflight + pending
            if remaining is not None:
                remaining = max(0, remaining - pending)
            return effective_inflight, remaining

        if for_video_generation:
            inflight = await self.concurrency_manager.get_video_inflight(token_id)
            remaining = await self.concurrency_manager.get_video_remaining(token_id)
            pending = await self._get_pending_count(token_id, False, True)
            effective_inflight = inflight + pending
            if remaining is not None:
                remaining = max(0, remaining - pending)
            return effective_inflight, remaining

        return 0, None

    async def _reserve_slot(
        self, token_id: int, for_image_generation: bool, for_video_generation: bool
    ) -> bool:
        """尝试为当前 token 预占一个生成槽位。"""
        if not self.concurrency_manager:
            return True

        if for_image_generation:
            return await self.concurrency_manager.acquire_image(token_id)

        if for_video_generation:
            return await self.concurrency_manager.acquire_video(token_id)

        return True

    async def _claim_pending_candidate(
        self, candidates: list[dict], for_image_generation: bool,
        for_video_generation: bool, enforce_concurrency_filter: bool,
    ) -> Optional[dict]:
        """Distribute a burst before slow account validation starts.

        Refreshing load and recording a queue reservation share one short lock;
        network health checks run after it is released.
        """
        async with self._pending_selection_lock:
            available = []
            for item in candidates:
                inflight, remaining = await self._get_token_load(
                    item["token"].id, for_image_generation, for_video_generation
                )
                if enforce_concurrency_filter and remaining == 0:
                    continue
                available.append({**item, "inflight": inflight, "remaining": remaining})
            if not available:
                return None
            if config.call_logic_mode == "polling":
                scenario = "image" if for_image_generation else (
                    "video" if for_video_generation else "default"
                )
                lowest_load = min(item["inflight"] for item in available)
                least_loaded = [item for item in available if item["inflight"] == lowest_load]
                ready = [item for item in least_loaded if not item["needs_refresh"]]
                selected = await self._select_round_robin(ready or least_loaded, scenario)
            else:
                selected = min(available, key=lambda item: (
                    item["inflight"],
                    1 if item["needs_refresh"] else 0,
                    0 if item["remaining"] is None else 1,
                    -(item["remaining"] or 0),
                    item["random"],
                ))
            await self._add_pending(
                selected["token"].id, for_image_generation, for_video_generation
            )
            return selected

    async def _select_round_robin(
        self, tokens: list[dict], scenario: str
    ) -> Optional[dict]:
        """Select candidate in round-robin order for the given scenario."""
        if not tokens:
            return None

        tokens_sorted = sorted(tokens, key=lambda item: item["token"].id or 0)
        async with self._rr_lock:
            last_id = self._round_robin_state.get(scenario)
            start_idx = 0
            if last_id is not None:
                for idx, item in enumerate(tokens_sorted):
                    if item["token"].id == last_id:
                        start_idx = (idx + 1) % len(tokens_sorted)
                        break
            selected = tokens_sorted[start_idx]
            self._round_robin_state[scenario] = selected["token"].id
        return selected

    async def _check_extension_route(self, token: Token) -> tuple[bool, str]:
        """Ensure extension captcha requests are routed to the selected account."""
        if config.captcha_method != "extension":
            return True, ""

        try:
            from .browser_captcha_extension import ExtensionCaptchaService

            service = await ExtensionCaptchaService.get_instance(
                getattr(self.token_manager, "db", None)
            )
            has_connection, route_key = await service.has_connection_for_token(token.id)
            if has_connection:
                return True, ""

            available = service.describe_routes() or "none"
            if route_key:
                return False, f"扩展路由 {route_key} 未连接（可用路由: {available}）"
            return False, f"扩展路由未配置或匿名插件未连接（可用路由: {available}）"
        except Exception as exc:
            return False, f"扩展路由检查失败: {exc}"

    async def _audit_selection_failure(self, token_count: int):
        await audit_account_operation(
            getattr(self.token_manager, "db", None),
            operation="account_selection", status="failed", reason="account_selection_failed",
            stage="selection", source="generation", details={"token_count": token_count},
        )

    async def select_token(
        self,
        for_image_generation: bool = False,
        for_video_generation: bool = False,
        model: Optional[str] = None,
        reserve: bool = False,
        enforce_concurrency_filter: bool = True,
        track_pending: bool = False,
        exclude_token_ids=None,
    ) -> Optional[Token]:
        """
        Select a token using load-aware balancing

        Args:
            for_image_generation: If True, only select tokens with image_enabled=True
            for_video_generation: If True, only select tokens with video_enabled=True
            model: Model name (used to filter tokens for specific models)
            reserve: Whether to atomically reserve one concurrency slot for the selected token
            enforce_concurrency_filter:
                Whether to pre-filter tokens by current inflight/remaining capacity.
                For reserve=False generation paths, this should usually be False so
                requests can enter the downstream wait queue instead of failing fast.
            track_pending:
                Whether to count the selected token as a queued request immediately.
                This smooths burst distribution before the hard concurrency slot is acquired.
            exclude_token_ids:
                Accounts this request has already failed on and must not run on again.

        Returns:
            Selected token or None if no available tokens
        """
        selection_key = (for_image_generation, for_video_generation, model)
        # Store only this task's result. A new selection, including one with no
        # candidates, supersedes it; child tasks cannot consume an inherited one.
        selection_owner = asyncio.current_task()
        self._selection_health.set((selection_owner, selection_key, None))
        debug_logger.log_info(
            f"[LOAD_BALANCER] 开始选择Token (图片生成={for_image_generation}, "
            f"视频生成={for_video_generation}, 模型={model}, 预占槽位={reserve})"
        )

        active_tokens = await self.token_manager.get_active_tokens()
        debug_logger.log_info(
            f"[LOAD_BALANCER] 获取到 {len(active_tokens)} 个活跃Token"
        )

        if not active_tokens:
            debug_logger.log_info(f"[LOAD_BALANCER] ❌ 没有活跃的Token")
            await self._audit_selection_failure(0)
            return None

        available_tokens = []
        filtered_reasons = {}
        required_tier = get_required_paygate_tier_for_model(model)
        health_candidate_count = 0
        health_failures = []
        cooldown_failures = []
        credit_failures = []
        excluded = set(exclude_token_ids or ())

        for token in active_tokens:
            admission = getattr(self.token_manager, "account_admission", None)
            if admission is not None and admission.maintenance_active(token.id):
                filtered_reasons[token.id] = "账号正在维护登录凭证"
                continue
            if token.id in excluded:
                filtered_reasons[token.id] = "本次请求已在该账号失败，改用其他账号"
                continue
            normalized_tier = normalize_user_paygate_tier(token.user_paygate_tier)
            if model and not supports_model_for_tier(model, normalized_tier):
                filtered_reasons[token.id] = (
                    "账号等级不足，需要 " + get_paygate_tier_label(required_tier)
                )
                continue
            if (not for_image_generation or token.image_enabled) and (
                not for_video_generation or token.video_enabled
            ):
                health_candidate_count += 1
            if for_image_generation:
                if not token.image_enabled:
                    filtered_reasons[token.id] = "图片生成已禁用"
                    continue

                route_ok, route_reason = await self._check_extension_route(token)
                if not route_ok:
                    filtered_reasons[token.id] = route_reason
                    continue

                if (
                    enforce_concurrency_filter
                    and self.concurrency_manager
                    and not await self.concurrency_manager.can_use_image(token.id)
                ):
                    filtered_reasons[token.id] = "图片并发已满"
                    continue

            if for_video_generation:
                if not token.video_enabled:
                    filtered_reasons[token.id] = "视频生成已禁用"
                    continue

                route_ok, route_reason = await self._check_extension_route(token)
                if not route_ok:
                    filtered_reasons[token.id] = route_reason
                    continue

                if (
                    enforce_concurrency_filter
                    and self.concurrency_manager
                    and not await self.concurrency_manager.can_use_video(token.id)
                ):
                    filtered_reasons[token.id] = "视频并发已满"
                    continue

            validation_reason = self._validation_cooldown_reason(token)
            if validation_reason:
                filtered_reasons[token.id] = validation_reason
                health_failures.append(validation_reason)
                continue

            cooldown_reason = self.get_generation_cooldown_reason(
                token, for_image_generation=for_image_generation,
                for_video_generation=for_video_generation, model=model,
            )
            if cooldown_reason:
                filtered_reasons[token.id] = cooldown_reason
                cooldown_failures.append(cooldown_reason)
                continue

            inflight, remaining = await self._get_token_load(
                token.id,
                for_image_generation=for_image_generation,
                for_video_generation=for_video_generation,
            )
            available_tokens.append(
                {
                "token": token,
                "inflight": inflight,
                "remaining": remaining,
                "needs_refresh": self.token_manager.needs_at_refresh(token),
                    "random": random.random(),
                }
            )

        # Cached credits only describe a candidate. Validate it before enforcing
        # the floor so a newly refreshed balance can restore video selection.

        if filtered_reasons:
            debug_logger.log_info(f"[LOAD_BALANCER] 已过滤Token:")
            for token_id, reason in filtered_reasons.items():
                debug_logger.log_info(f"[LOAD_BALANCER]   - Token {token_id}: {reason}")

        if not available_tokens:
            if health_candidate_count and len(health_failures) + len(cooldown_failures) == health_candidate_count:
                self._selection_health.set((
                    selection_owner, selection_key,
                    self._selection_unavailable_message(health_failures, cooldown_failures),
                ))
            debug_logger.log_info(
                f"[LOAD_BALANCER] ❌ 没有可用的Token (图片生成={for_image_generation}, 视频生成={for_video_generation})"
            )
            await self._audit_selection_failure(len(active_tokens))
            return None

        # 最低 in-flight 优先；有并发上限时，剩余槽位更多的 token 优先；最后随机打散
        call_mode = config.call_logic_mode
        if call_mode == "polling" and not track_pending:
            scenario = "default"
            if for_image_generation:
                scenario = "image"
            elif for_video_generation:
                scenario = "video"

            ordered_candidates = []
            first_candidate = await self._select_round_robin(available_tokens, scenario)
            if first_candidate is not None:
                ordered_candidates.append(first_candidate)
                ordered_candidates.extend(
                    item
                    for item in sorted(
                        available_tokens, key=lambda item: item["token"].id or 0
                    )
                    if item["token"].id != first_candidate["token"].id
                )
            available_tokens = ordered_candidates
        else:
            available_tokens.sort(
                key=lambda item: (
                    1 if item["needs_refresh"] else 0,
                    item["inflight"],
                    0 if item["remaining"] is None else 1,
                    -(item["remaining"] or 0),
                    item["random"],
                )
            )

        ready_candidates = [
            item for item in available_tokens if not item["needs_refresh"]
        ]
        refresh_candidates = [
            item for item in available_tokens if item["needs_refresh"]
        ]
        if ready_candidates and refresh_candidates:
            available_tokens = ready_candidates + refresh_candidates

        debug_logger.log_info("[LOAD_BALANCER] 候选Token负载:")
        for item in available_tokens:
            token = item["token"]
            remaining = "unlimited" if item["remaining"] is None else item["remaining"]
            debug_logger.log_info(
                f"[LOAD_BALANCER]   - Token {token.id} ({token.email}) "
                f"inflight={item['inflight']}, remaining={remaining}, "
                f"needs_refresh={item['needs_refresh']}, credits={token.credits}"
            )

        # 只为候选列表中真正尝试到的 token 做 AT 校验，避免每次请求把所有 token 全扫一遍
        get_health_error = getattr(self.token_manager, "get_last_validation_error", None)
        exit_rotation = getattr(self, "exit_rotation", None)
        while available_tokens:
            if track_pending:
                item = await self._claim_pending_candidate(
                    available_tokens, for_image_generation,
                    for_video_generation, enforce_concurrency_filter,
                )
                if item is None:
                    break
                available_tokens = [
                    candidate for candidate in available_tokens
                    if candidate["token"].id != item["token"].id
                ]
            else:
                item = available_tokens.pop(0)
            token = item["token"]
            token_id = token.id
            selected = False
            try:
                # Another validation may fail after candidate collection or
                # while a pending reservation is awaited. Do not rotate away
                # from that identity and inadvertently clear its backoff.
                validation_reason = self._validation_cooldown_reason(token)
                if validation_reason:
                    health_failures.append(validation_reason)
                    continue
                if exit_rotation is not None:
                    try:
                        token = await exit_rotation.prepare_token(token)
                    except Exception as exc:
                        health_failures.append("EXIT_ROTATION: no verified exit available")
                        debug_logger.log_warning(
                            f"[EXIT_ROTATION] Token {token_id}: preparation failed ({type(exc).__name__})"
                        )
                        continue
                # A concurrent request can open a circuit after the candidate
                # list was built or while this account's exit was prepared.
                cooldown_reason = self.get_generation_cooldown_reason(
                    token, for_image_generation=for_image_generation,
                    for_video_generation=for_video_generation, model=model,
                )
                if cooldown_reason:
                    cooldown_failures.append(cooldown_reason)
                    continue

                validation_reason = self._validation_cooldown_reason(token)
                if validation_reason:
                    health_failures.append(validation_reason)
                    continue

                consume_outcome = getattr(self.token_manager, "consume_validation_outcome", None)
                if callable(consume_outcome):
                    # This caller's earlier validation must not authorize a
                    # route change if this attempt exits for busy/cooldown.
                    consume_outcome(token_id)
                token = await self.token_manager.ensure_valid_token(token)
                outcome = consume_outcome(token_id) if callable(consume_outcome) else None
                if not token:
                    has_failure_evidence = (
                        getattr(outcome, "token_id", None) == token_id
                        and getattr(outcome, "success", None) is False
                        and isinstance(getattr(outcome, "reason", None), str)
                        and isinstance(getattr(outcome, "identity", None), str)
                        and bool(outcome.identity)
                    )
                    reason = (outcome.reason if has_failure_evidence
                              else get_health_error(token_id) if callable(get_health_error) else None)
                    if exit_rotation is not None and (has_failure_evidence or not callable(consume_outcome)):
                        try:
                            mark_health_error = exit_rotation.mark_health_error
                            if (has_failure_evidence
                                    and getattr(exit_rotation, "accepts_health_error_identity", False)):
                                await mark_health_error(
                                    token_id, error=reason, failed_identity=outcome.identity,
                                )
                            elif getattr(exit_rotation, "accepts_health_error_reason", False):
                                # TokenManager exposes a fixed, credential-free
                                # category. The rotation service decides whether
                                # that category is a real route failure.
                                await mark_health_error(token_id, error=reason)
                            else:
                                await mark_health_error(token_id)
                        except Exception as exc:
                            debug_logger.log_warning(
                                f"[EXIT_ROTATION] Token {token_id}: health state write failed ({type(exc).__name__})"
                            )
                    if isinstance(reason, str) and reason.strip():
                        health_failures.append(reason)
                    debug_logger.log_info(
                        f"[LOAD_BALANCER] 跳过 Token {token_id}: AT无效或已过期"
                    )
                    continue

                cooldown_reason = self.get_generation_cooldown_reason(
                    token, for_image_generation=for_image_generation,
                    for_video_generation=for_video_generation, model=model,
                )
                if cooldown_reason:
                    cooldown_failures.append(cooldown_reason)
                    continue

                if for_video_generation and self._below_video_credit_floor(token):
                    credit_failures.append(
                        f"视频生成积分不足（剩余 {token.credits}，最低要求 {getattr(config, 'flow_min_video_credits', 10)}）"
                    )
                    continue

                if reserve and not await self._reserve_slot(
                    token.id, for_image_generation, for_video_generation
                ):
                    debug_logger.log_info(
                        f"[LOAD_BALANCER] 跳过 Token {token.id}: 预占槽位失败"
                    )
                    continue

                debug_logger.log_info(
                    f"[LOAD_BALANCER] ✅ 已选择Token {token.id} ({token.email}) - "
                    f"余额: {token.credits}, inflight={item['inflight']}"
                )
                selected = True
                await audit_account_operation(
                    getattr(self.token_manager, "db", None), token.id,
                    operation="account_selection", status="success", reason="account_selected",
                    stage="selection", source="generation", token=token,
                    details={"credits": token.credits},
                )
                return token
            finally:
                if track_pending and not selected:
                    await self.release_pending(
                        token_id, for_image_generation, for_video_generation
                    )

        if health_candidate_count and len(health_failures) + len(cooldown_failures) + len(credit_failures) == health_candidate_count:
            self._selection_health.set((
                selection_owner, selection_key,
                self._selection_unavailable_message(health_failures, cooldown_failures, credit_failures),
            ))
        debug_logger.log_info(
            f"[LOAD_BALANCER] ❌ 候选Token均不可用 (图片生成={for_image_generation}, 视频生成={for_video_generation})"
        )
        await self._audit_selection_failure(len(active_tokens))
        return None

    async def get_unavailable_reason(
        self,
        *,
        for_image_generation: bool = False,
        for_video_generation: bool = False,
        model: Optional[str] = None,
    ) -> Optional[str]:
        """Explain tier/capability filtering or a failure shared by all candidates."""
        selection = self._selection_health.get()
        self._selection_health.set(None)
        selection_known = bool(
            selection and selection[0] is asyncio.current_task()
            and selection[1] == (for_image_generation, for_video_generation, model)
        )
        if selection_known and selection[2]:
            return selection[2]
        active_tokens = await self.token_manager.get_active_tokens()
        if not active_tokens:
            return None

        required_tier = get_required_paygate_tier_for_model(model)
        supported_tokens = []
        for token in active_tokens:
            normalized_tier = normalize_user_paygate_tier(token.user_paygate_tier)
            if model and not supports_model_for_tier(model, normalized_tier):
                continue
            supported_tokens.append(token)

        if model and not supported_tokens:
            tier_label = get_paygate_tier_label(required_tier)
            return f"当前模型需要 {tier_label} 账号，但没有可用的 {tier_label} 账号: {model}"

        capability_tokens = []
        for token in supported_tokens:
            if for_image_generation and not token.image_enabled:
                continue
            if for_video_generation and not token.video_enabled:
                continue
            capability_tokens.append(token)

        if supported_tokens and not capability_tokens:
            if for_image_generation:
                return "当前有符合档位的账号，但图片生成功能已全部禁用。"
            if for_video_generation:
                return "当前有符合档位的账号，但视频生成功能已全部禁用。"

        # Historical manager errors cannot describe this request's quota or
        # capabilities. Health reasons come only from its selection above.
        return None
