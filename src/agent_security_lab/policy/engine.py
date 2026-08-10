"""Policy engine: orchestrates Rule of Two, pins, sigma, approvals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_security_lab.config import LabConfig
from agent_security_lab.models.intent import ToolCallIntent
from agent_security_lab.models.policy import PolicyDecision, Verdict
from agent_security_lab.models.session import SessionState, TrifectaFlags
from agent_security_lab.observability.sigma import SigmaEngine
from agent_security_lab.policy.approvals import ApprovalStore, get_approval_store
from agent_security_lab.policy.capabilities import project_call_flags, role_allows
from agent_security_lab.policy.description_guard import check_description
from agent_security_lab.policy.rule_of_two import evaluate_rule_of_two
from agent_security_lab.policy.schema_pin import SchemaPinStore


class PolicyDenied(RuntimeError):
    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__("; ".join(decision.reasons) or decision.verdict.value)


@dataclass
class ToolMeta:
    server_id: str
    name: str  # bare or namespaced
    description: str
    input_schema: dict[str, Any]


class PolicyEngine:
    def __init__(
        self,
        cfg: LabConfig,
        *,
        pins: SchemaPinStore | None = None,
        approvals: ApprovalStore | None = None,
        sigma: SigmaEngine | None = None,
    ) -> None:
        self.cfg = cfg
        self.pins = pins or SchemaPinStore(cfg.pins_dir)
        self.approvals = approvals or get_approval_store(cfg)
        self.sigma = sigma or SigmaEngine.from_yaml(cfg.sigma_rules_path)

    def evaluate(
        self,
        intent: ToolCallIntent,
        session: SessionState,
        *,
        tool_meta: ToolMeta | None = None,
        execution_token: str | None = None,
        actor: str = "agent",
    ) -> PolicyDecision:
        reasons: list[str] = []
        alerts: list[str] = []
        sigma_hits: list[str] = []
        extra: dict[str, Any] = {}

        description = tool_meta.description if tool_meta else ""
        input_schema = tool_meta.input_schema if tool_meta else {}

        # --- Schema pin ---
        if tool_meta is not None:
            pin_ok, pin_reason, pin_rec = self.pins.verify(
                intent.server_id,
                intent.tool_name,
                description=description,
                input_schema=input_schema,
            )
            extra["pin_reason"] = pin_reason
            if not pin_ok and self.cfg.policy.schema_pin_enforce:
                return PolicyDecision(
                    verdict=Verdict.DENY,
                    reasons=[f"schema_pin:{pin_reason}"],
                    alerts=[pin_reason],
                    extra=extra,
                )
            if not pin_ok:
                alerts.append(f"schema_pin:{pin_reason}")

            prev_desc = None
            if pin_rec is not None and pin_reason != "pin_created":
                prev_desc = pin_rec.description
            # For mismatch cases pin_rec is the old pin — good for diff
            if pin_reason in {"description_hash_mismatch", "schema_hash_mismatch"}:
                prev_desc = pin_rec.description if pin_rec else None

            desc_check = check_description(
                intent.tool_name,
                description,
                previous=prev_desc if pin_reason != "pin_created" else None,
                enforce_diff=self.cfg.policy.description_diff_enforce
                and pin_reason != "pin_created",
            )
            alerts.extend(desc_check.alerts)
            if desc_check.poison_markers:
                extra["poison_markers"] = desc_check.poison_markers
            if desc_check.diff:
                extra["description_diff"] = desc_check.diff
            if (
                not desc_check.ok
                and self.cfg.policy.description_diff_enforce
                and pin_reason != "pin_created"
            ):
                # Description change already covered by pin; keep deny if enforce
                if pin_reason != "pin_match" and self.cfg.policy.schema_pin_enforce:
                    pass  # already denied above when pin fails
                elif desc_check.changed and self.cfg.policy.schema_pin_enforce:
                    return PolicyDecision(
                        verdict=Verdict.DENY,
                        reasons=["description_guard:description_changed"],
                        alerts=alerts,
                        extra=extra,
                    )

        # --- Capability projection ---
        call_flags = project_call_flags(intent, self.cfg, tool_description=description)
        # Session already untrusted (e.g. poisoned prompt scenario)
        combined = session.flags.merge(call_flags)

        # --- Role matrix ---
        ok_role, role_reason = role_allows(intent.role, call_flags)
        if not ok_role and role_reason:
            # analyst + state_change: require_approval rather than hard deny when hardened
            if (
                intent.role == "analyst"
                and call_flags.state_change
                and self.cfg.policy.require_approval_for_state_change
            ):
                reasons.append(role_reason)
            elif intent.role == "observer":
                return PolicyDecision(
                    verdict=Verdict.DENY,
                    reasons=[role_reason or "role_denied"],
                    call_flags=call_flags,
                    session_flags_after=combined,
                    alerts=alerts,
                    extra=extra,
                )
            else:
                reasons.append(role_reason)

        # --- Sigma ---
        if self.sigma is not None:
            s_result = self.sigma.evaluate(
                intent,
                description=description,
                session=session,
            )
            sigma_hits = list(s_result.hits)
            alerts.extend(s_result.alerts)
            if s_result.raise_sensitive:
                call_flags.sensitive_data = True
                combined = session.flags.merge(call_flags)
            if s_result.deny and self.cfg.policy.sigma_enforce:
                return PolicyDecision(
                    verdict=Verdict.DENY,
                    reasons=[f"sigma:{h}" for h in s_result.hits],
                    call_flags=call_flags,
                    session_flags_after=combined,
                    alerts=alerts,
                    sigma_hits=sigma_hits,
                    extra=extra,
                )
            if s_result.require_approval:
                reasons.append("sigma:require_approval")

        # --- State change always needs approval in hardened ---
        needs_approval = False
        if (
            call_flags.state_change
            and self.cfg.policy.require_approval_for_state_change
        ):
            needs_approval = True
            reasons.append("state_change_requires_approval")

        # --- Rule of Two ---
        rot_verdict, rot_reasons = evaluate_rule_of_two(combined, self.cfg)
        reasons.extend(rot_reasons)
        if rot_verdict is Verdict.DENY:
            return PolicyDecision(
                verdict=Verdict.DENY,
                reasons=reasons,
                call_flags=call_flags,
                session_flags_after=combined,
                alerts=alerts,
                sigma_hits=sigma_hits,
                extra=extra,
            )
        if rot_verdict is Verdict.REQUIRE_APPROVAL:
            needs_approval = True

        # Sensitive + untrusted without state still needs approval under RoT
        if needs_approval:
            if execution_token:
                try:
                    self.approvals.consume(execution_token, intent.intent_hash)
                    extra["token_consumed"] = True
                    # Commit session flags after successful authorization
                    session.flags = combined
                    return PolicyDecision(
                        verdict=Verdict.ALLOW,
                        reasons=reasons + ["approval_token_consumed"],
                        call_flags=call_flags,
                        session_flags_after=combined,
                        requires_token=False,
                        alerts=alerts,
                        sigma_hits=sigma_hits,
                        extra=extra,
                    )
                except ValueError as exc:
                    return PolicyDecision(
                        verdict=Verdict.DENY,
                        reasons=reasons + [f"approval_token_error:{exc}"],
                        call_flags=call_flags,
                        session_flags_after=combined,
                        requires_token=True,
                        alerts=alerts,
                        sigma_hits=sigma_hits,
                        extra=extra,
                    )

            # Create pending approval (do not mutate session flags until allowed)
            item = self.approvals.create(
                intent,
                proposed_by=actor,
                reasons=reasons,
                force_human=self.cfg.policy.always_require_human,
            )
            return PolicyDecision(
                verdict=Verdict.REQUIRE_APPROVAL,
                reasons=reasons,
                call_flags=call_flags,
                session_flags_after=session.flags,  # not yet committed
                requires_token=True,
                approval_id=item.approval_id,
                alerts=alerts,
                sigma_hits=sigma_hits,
                extra=extra,
            )

        # Allow — commit flags
        session.flags = combined
        return PolicyDecision(
            verdict=Verdict.ALLOW,
            reasons=reasons or ["ok"],
            call_flags=call_flags,
            session_flags_after=combined,
            alerts=alerts,
            sigma_hits=sigma_hits,
            extra=extra,
        )
