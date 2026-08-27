"""Dispatch: bounded parallel tool execution with approval gating."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from .config import Config
from .errors import BudgetExhaustedError
from .guardrails.redactor import Redactor
from .llm.client import ToolCall
from .scope import Engagement, ScopeGate
from .safety import SafetyController

BUDGET_KIND_BY_TOOL: dict[str, str] = {
    "http": "max_requests",
    "http_replay": "max_requests",
    "auth_session": "max_requests",
    "multipart_upload": "max_requests",
    "websocket": "max_requests",
    "tcp_probe": "max_requests",
    "scan": "max_scan_targets",
    "mdns_browse": "max_requests",
    "packet_capture": "max_requests",
}
_DEFAULT_BUDGET_KIND = "max_actions"

AUTO_APPROVE = frozenset({
    "read_file", "read_source_code", "glob", "grep",
    "pane_spawn", "pane_list", "pane_read",
    "pane_note",
    "memory_remember", "memory_recall", "memory_pin", "memory_unpin",
    "json_extract", "base64_decode", "jwt_inspect", "binary_inspect",
    "read_callback_endpoint",
})

@dataclass
class ApprovalResult:
    approved: bool
    summarize: bool = False
    edited_command: str | None = None
    # Set only when the operator explicitly enabled a short-lived, exact
    # target approval from the TUI.  It is deliberately data, rather than a
    # global dispatch setting, so every automatic decision is auditable.
    auto_approved: bool = False
    auto_approve_target: str | None = None


ApprovalCallback = Callable[
    [ToolCall, Engagement],
    Awaitable[ApprovalResult],
]


async def dispatch_parallel(
    calls: list[ToolCall],
    executor: Any,
    gate: ScopeGate,
    audit: Any,
    config: Config,
    approver: ApprovalCallback,
    redactor: Redactor,
    safety: SafetyController | None = None,
    budgets: Any | None = None,
) -> list[dict]:
    """Dispatch all tool calls with bounded concurrency and approval gating.
    Results are returned in the same order as `calls`.
    A failure in one call does NOT abort the others.
    """
    max_concurrent = 4
    active_packages = gate.active_packages()
    if active_packages:
        # Dispatch is shared by all active engagements. Enforce the strictest
        # active package instead of accidentally privileging the first one.
        max_concurrent = min(
            package.guardrails.max_concurrent_tools
            for package in active_packages)
    sem = asyncio.Semaphore(max_concurrent)

    async def run_one(tc: ToolCall, idx: int) -> dict:
        async with sem:
            if safety:
                safety.raise_if_stopped()
            engagement_id = tc.arguments.get("engagement_id", "")
            if not engagement_id:
                active = gate.active_engagements()
                if len(active) == 1:
                    engagement_id = active[0].id
                    tc.arguments["engagement_id"] = engagement_id
            try:
                allowed, reason, engagement = gate.authorize(
                    tc.name, tc.arguments, engagement_id)
            except Exception as e:
                # Tool arguments are model-controlled input.  An unexpected
                # validation error must reject this call, not abort sibling
                # calls in the parallel batch.
                reason = f"tool authorization failed: {e}"
                audit.guard_decision(tc.name, False, reason)
                return {"error": reason}
            if not allowed:
                audit.guard_decision(tc.name, False, reason)
                return {"error": reason}

            # Make the route-derived address visible in the *existing*
            # mandatory approval prompt before an external listener is
            # provisioned. It is recomputed by the handler after approval and
            # is never accepted as model-controlled configuration.
            if (tc.name == "request_callback_endpoint"
                    and tc.arguments.get("bind", "127.0.0.1") == "0.0.0.0"):
                from .tools.callback_endpoint import infer_callback_advertised_host
                configured_host = config.callback.advertised_host
                tc.arguments["_callback_approved_advertised_host"] = (
                    configured_host or infer_callback_advertised_host(engagement))
                tc.arguments["_callback_advertised_host_source"] = (
                    "configured" if configured_host else "route-inferred")

            # Budget check
            reservation = None
            if budgets is not None and engagement is not None:
                budget_kind = BUDGET_KIND_BY_TOOL.get(
                    tc.name, _DEFAULT_BUDGET_KIND)
                budget_event = getattr(audit, "budget_decision", None)
                try:
                    reservation = budgets.try_reserve(
                        engagement.id, budget_kind, 1)
                    if budget_event:
                        budget_event(engagement.id, True,
                                     f"reserved 1 {budget_kind}")
                except BudgetExhaustedError as e:
                    if budget_event:
                        budget_event(engagement.id, False, str(e), budget_kind)
                    audit.guard_decision(tc.name, False, str(e))
                    return {"error": str(e)}
                except (ValueError, Exception) as e:
                    if budget_event:
                        budget_event(engagement.id, False,
                                      f"budget error: {e}", budget_kind)
                    audit.guard_decision(tc.name, False, f"budget error: {e}")
                    return {"error": f"budget error: {e}"}

            # Approval gate
            if tc.name not in AUTO_APPROVE:
                info = await approver(tc, engagement)
                # Test and integration adapters predating the approval-event
                # API may not implement it; the production audit logger does.
                approval_event = getattr(audit, "approval", None)
                if approval_event:
                    approval_event(tc.name, info.approved, info.summarize,
                                   engagement.id)
                if not info.approved:
                    audit.guard_decision(tc.name, False, "denied by operator")
                    if reservation is not None:
                        budgets.release(reservation)
                    return {"error": "denied by operator"}
                if info.edited_command and tc.name == "shell":
                    tc.arguments["command"] = info.edited_command
                    # The edited command is executable input, not merely
                    # display text.  It must pass the same scope checks as
                    # the command originally proposed by the model.
                    allowed, reason, engagement = gate.authorize(
                        tc.name, tc.arguments, engagement_id)
                    if not allowed:
                        audit.guard_decision(tc.name, False,
                                             f"edited command denied: {reason}")
                        if reservation is not None:
                            budgets.release(reservation)
                        return {"error": f"edited command denied: {reason}"}
                if info.auto_approved:
                    audit.guard_decision(
                        tc.name, True,
                        "session auto-approval for engagement target "
                        f"{info.auto_approve_target or engagement.target}",
                        engagement.id)

            # Dry-run mode
            if engagement.safety_overrides.get("dry_run", config.safety.dry_run):
                plan = _build_dry_run_plan(tc, engagement)
                audit.guard_decision(tc.name, True, f"dry-run: {plan}")
                if reservation is not None:
                    budgets.release(reservation)
                return {"dry_run": True, "plan": plan}

            # Execute
            audit.tool_call(tc.name, tc.arguments, engagement.id)
            t0 = time.monotonic()
            try:
                # ToolRegistry exposes this narrower entry point so its public
                # ``call`` API cannot sidestep dispatch approval, budgeting,
                # and auditing. Lightweight test/integration executors retain
                # the original two-argument ``call`` contract.
                execute = getattr(executor, "call_authorized", executor.call)
                result = await execute(tc.name, tc.arguments)
            except Exception as e:
                result = {"error": f"tool execution failed: {e}"}
            elapsed = (time.monotonic() - t0) * 1000

            # Redact and audit
            raw_result = result
            try:
                result = await redactor.redact_object(
                    result, f"tool_result:{tc.name}", engagement.id)
            except Exception:
                pass
            audit.tool_result(
                tc.name, result, elapsed,
                truncated=result.get("truncated", False) if isinstance(result, dict) else False,
                raw=raw_result, engagement_id=engagement.id)

            # Settle budget
            if reservation is not None:
                try:
                    budgets.settle(reservation)
                except Exception:
                    pass

            return result

    return list(await asyncio.gather(
        *(run_one(tc, i) for i, tc in enumerate(calls)),
        return_exceptions=False,
    ))


def _build_dry_run_plan(tc: ToolCall, engagement: Engagement) -> str:
    if tc.name == "shell":
        return (f"CMD: {tc.arguments.get('command')} | "
                f"engagement: {engagement.label} | "
                f"target: {engagement.target}")
    if tc.name == "http":
        return (f"METHOD: {tc.arguments.get('method', 'GET')} {tc.arguments.get('url')} | "
                f"engagement: {engagement.label} | target: {engagement.target}")
    if tc.name == "request_callback_endpoint":
        return (f"LISTENER: {tc.arguments.get('protocol')} "
                f"bind={tc.arguments.get('bind', '127.0.0.1')} "
                f"port={tc.arguments.get('port', 'auto')} "
                f"max={tc.arguments.get('max_requests', 1)} "
                f"expires={tc.arguments.get('expires_seconds', 300)}s | "
                f"reason: {str(tc.arguments.get('reason', ''))[:200]} | "
                f"engagement: {engagement.label}")
    if tc.name == "mdns_browse":
        return (f"mDNS browse: {tc.arguments.get('service_type', '_services._dns-sd._udp.local.')} | "
                f"duration: {tc.arguments.get('duration_seconds', 3)}s | "
                f"engagement: {engagement.label}")
    if tc.name == "packet_capture":
        return (f"PACKET CAPTURE: interface={tc.arguments.get('interface')} "
                f"filter={tc.arguments.get('protocol', 'mdns')} "
                f"duration: {tc.arguments.get('duration_seconds', 10)}s | "
                f"engagement: {engagement.label}")
    if tc.name == "jwt_sign":
        claims = tc.arguments.get("claims")
        keys = sorted(str(k) for k in claims) if isinstance(claims, dict) else []
        return (f"MINT: {tc.arguments.get('algorithm', 'HS256')} "
                f"credential={tc.arguments.get('credential_ref') or '(none)'} "
                f"claims={','.join(keys) or '(none)'} "
                f"ttl={tc.arguments.get('ttl_seconds')}s | "
                f"reason: {str(tc.arguments.get('reason', ''))[:200]} | "
                f"engagement: {engagement.label}")
    if tc.name == "scan":
        ts = tc.arguments.get("targets", [])
        return (f"SCAN: {','.join(ts) if isinstance(ts, list) else ts} | "
                f"ports: {tc.arguments.get('ports', 'default')} | "
                f"engagement: {engagement.label}")
    if tc.name == "pane_spawn":
        return (f"SPAWN: {tc.arguments.get('command')} | "
                f"name: {tc.arguments.get('name')} | engagement: {engagement.label}")
    return f"TOOL: {tc.name} args: {str(tc.arguments)[:200]}"
