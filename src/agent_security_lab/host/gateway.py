"""Host gateway: sole tools/call exit path through the policy engine."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from agent_security_lab.config import LabConfig
from agent_security_lab.host.client import MCPClientManager
from agent_security_lab.host.tool_router import route_tool
from agent_security_lab.models.intent import ToolCallIntent
from agent_security_lab.models.policy import PolicyDecision, Verdict
from agent_security_lab.models.session import SessionState
from agent_security_lab.observability.audit import set_audit_path, write_tool_audit
from agent_security_lab.observability.dataflow import DataFlowTracker
from agent_security_lab.policy.approvals import ApprovalStore, get_approval_store
from agent_security_lab.policy.engine import PolicyEngine, ToolMeta
from agent_security_lab.policy.locks import SessionLockError, get_session_lock
from agent_security_lab.policy.schema_pin import SchemaPinStore


@dataclass
class GatewayResult:
    ok: bool
    content: str | None
    decision: PolicyDecision
    call_id: str
    tool_namespaced: str | None = None


@dataclass
class HostGateway:
    cfg: LabConfig
    client: MCPClientManager
    session: SessionState
    engine: PolicyEngine
    dataflow: DataFlowTracker = field(default_factory=DataFlowTracker)
    actor: str = "scripted_agent"

    @classmethod
    def create(
        cls,
        cfg: LabConfig,
        client: MCPClientManager,
        *,
        session_id: str | None = None,
        role: str | None = None,
        mark_untrusted: bool | None = None,
        pins: SchemaPinStore | None = None,
        approvals: ApprovalStore | None = None,
    ) -> HostGateway:
        set_audit_path(cfg.audit_path)
        sid = session_id or f"sess-{uuid.uuid4().hex[:12]}"
        session = SessionState(
            session_id=sid,
            role=role or cfg.default_role,
            profile=cfg.profile,
        )
        if mark_untrusted if mark_untrusted is not None else cfg.mark_prompt_untrusted:
            session.mark_untrusted()
        pins = pins or SchemaPinStore(cfg.pins_dir)
        approvals = approvals or get_approval_store(cfg)
        engine = PolicyEngine(cfg, pins=pins, approvals=approvals)
        return cls(cfg=cfg, client=client, session=session, engine=engine)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        execution_token: str | None = None,
        role: str | None = None,
    ) -> GatewayResult:
        arguments = dict(arguments or {})
        call_id = f"call-{uuid.uuid4().hex[:12]}"
        lock = get_session_lock()

        try:
            with lock.hold(f"session:{self.session.session_id}"):
                return await self._call_locked(
                    name,
                    arguments,
                    call_id=call_id,
                    execution_token=execution_token,
                    role=role,
                )
        except SessionLockError as exc:
            decision = PolicyDecision(
                verdict=Verdict.DENY,
                reasons=[f"lock_timeout:{exc}"],
            )
            write_tool_audit(
                event="tool_call_denied",
                source="host",
                session_id=self.session.session_id,
                actor=self.actor,
                role=self.session.role,
                policy=decision.to_dict(),
                path=self.cfg.audit_path,
            )
            return GatewayResult(
                ok=False, content=None, decision=decision, call_id=call_id
            )

    async def _call_locked(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        call_id: str,
        execution_token: str | None,
        role: str | None,
    ) -> GatewayResult:
        route = route_tool(
            self.client,
            name,
            conflict_mode=self.cfg.policy.name_conflict_mode,
        )
        if route.error or route.tool is None:
            decision = PolicyDecision(
                verdict=Verdict.DENY,
                reasons=[route.error or "route_failed"],
                alerts=list(route.alerts or []),
            )
            write_tool_audit(
                event="tool_call_denied",
                source="host",
                session_id=self.session.session_id,
                actor=self.actor,
                role=self.session.role,
                tool_name=name,
                policy=decision.to_dict(),
                path=self.cfg.audit_path,
            )
            return GatewayResult(
                ok=False,
                content=None,
                decision=decision,
                call_id=call_id,
                tool_namespaced=name,
            )

        tool = route.tool
        intent = ToolCallIntent(
            session_id=self.session.session_id,
            server_id=tool.server_id,
            tool_name=tool.namespaced,
            arguments=arguments,
            role=role or self.session.role,
            untrusted_input_ts=self.session.untrusted_input_ts,
            data_cutoff_ts=self.session.data_cutoff_ts,
            parent_call_id=self.session.last_sensitive_call_id,
        )
        meta = ToolMeta(
            server_id=tool.server_id,
            name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
        )
        decision = self.engine.evaluate(
            intent,
            self.session,
            tool_meta=meta,
            execution_token=execution_token,
            actor=self.actor,
        )

        if decision.verdict is Verdict.DENY:
            write_tool_audit(
                event="tool_call_denied",
                source="host",
                session_id=self.session.session_id,
                actor=self.actor,
                role=intent.role,
                intent=intent.to_dict(),
                policy=decision.to_dict(),
                server_id=tool.server_id,
                tool_name=tool.namespaced,
                path=self.cfg.audit_path,
            )
            return GatewayResult(
                ok=False,
                content=None,
                decision=decision,
                call_id=call_id,
                tool_namespaced=tool.namespaced,
            )

        if decision.verdict is Verdict.REQUIRE_APPROVAL:
            write_tool_audit(
                event="tool_call_require_approval",
                source="host",
                session_id=self.session.session_id,
                actor=self.actor,
                role=intent.role,
                intent=intent.to_dict(),
                policy=decision.to_dict(),
                server_id=tool.server_id,
                tool_name=tool.namespaced,
                path=self.cfg.audit_path,
            )
            return GatewayResult(
                ok=False,
                content=None,
                decision=decision,
                call_id=call_id,
                tool_namespaced=tool.namespaced,
            )

        # ALLOW — execute
        try:
            content = await self.client.call_raw(tool.server_id, tool.name, arguments)
        except Exception as exc:  # noqa: BLE001 — fail closed on server errors
            decision = PolicyDecision(
                verdict=Verdict.DENY,
                reasons=[f"tool_execution_error:{type(exc).__name__}"],
                alerts=[f"tool_execution_error:{exc}"],
            )
            write_tool_audit(
                event="tool_call_error",
                source="host",
                session_id=self.session.session_id,
                actor=self.actor,
                role=intent.role,
                intent=intent.to_dict(),
                policy=decision.to_dict(),
                server_id=tool.server_id,
                tool_name=tool.namespaced,
                path=self.cfg.audit_path,
            )
            return GatewayResult(
                ok=False,
                content=None,
                decision=decision,
                call_id=call_id,
                tool_namespaced=tool.namespaced,
            )
        edges: list[dict[str, Any]] = []

        # Dataflow: sensitive reads
        if decision.call_flags.sensitive_data:
            h = self.dataflow.record_output(
                self.session.session_id,
                call_id,
                tool.server_id,
                content,
                sensitive=True,
            )
            self.session.last_sensitive_call_id = call_id
            self.session.last_sensitive_content_hashes.add(h)

        # Dataflow: outbound email
        bare = tool.name
        if bare == "send_email":
            body = str(arguments.get("body", ""))
            found = self.dataflow.check_outbound(
                self.session.session_id, call_id, tool.server_id, body
            )
            edges = [e.to_dict() for e in found]

        write_tool_audit(
            event="tool_call_allowed",
            source="host",
            session_id=self.session.session_id,
            actor=self.actor,
            role=intent.role,
            intent=intent.to_dict(),
            policy=decision.to_dict(),
            server_id=tool.server_id,
            tool_name=tool.namespaced,
            dataflow_edges=edges,
            extra={"call_id": call_id, "content_preview": content[:200]},
            path=self.cfg.audit_path,
        )
        return GatewayResult(
            ok=True,
            content=content,
            decision=decision,
            call_id=call_id,
            tool_namespaced=tool.namespaced,
        )
