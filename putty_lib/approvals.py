"""Operator approvals: a tool call (or host key, or passphrase prompt) waits
until the human decides in the dashboard, or the request times out."""

from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

# Approval kinds
TOOL = "tool"  # a tool call that policy flagged
HOSTKEY = "hostkey"  # an unknown SSH host key
SECRET = "secret"  # the operator types a passphrase (never seen by the AI)


@dataclass
class Approval:
    approval_id: str
    kind: str
    title: str
    details: dict[str, Any]
    options: list[dict[str, str]]  # "always allow" choices: {"id", "label"}
    timeout: float
    created_at: float = field(default_factory=time.time)
    approved: bool | None = None
    reason: str = ""
    remember: list[str] = field(default_factory=list)
    secret: str | None = field(default=None, repr=False)
    _done: threading.Event = field(default_factory=threading.Event, repr=False)

    def public(self) -> dict[str, Any]:
        """What the dashboard may see (never the secret)."""
        return {
            "approval_id": self.approval_id,
            "kind": self.kind,
            "title": self.title,
            "details": self.details,
            "options": self.options,
            "created_at": self.created_at,
            "expires_in": max(0, round(self.created_at + self.timeout - time.time())),
        }


class ApprovalQueue:
    def __init__(self, emit: Callable[..., Any]) -> None:
        self._emit = emit
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._pending: dict[str, Approval] = {}
        self.on_request: Callable[[Approval], None] | None = None

    def request(
        self,
        kind: str,
        title: str,
        details: dict[str, Any],
        timeout: float,
        options: list[dict[str, str]] | None = None,
    ) -> Approval:
        """Block until the operator decides or timeout expires."""
        with self._lock:
            approval = Approval(f"a{next(self._ids)}", kind, title, details, options or [], timeout)
            self._pending[approval.approval_id] = approval
        self._emit("approval", approval_id=approval.approval_id, approval_kind=kind,
                   title=title, status="waiting")
        if self.on_request:
            self.on_request(approval)

        if not approval._done.wait(timeout):
            with self._lock:
                timed_out = self._pending.pop(approval.approval_id, None) is not None
            if timed_out:
                approval.approved = False
                approval.reason = f"no decision within {int(timeout)}s"
                approval._done.set()
            else:
                # decide()/deny_all() took it at the last moment; let it finish
                approval._done.wait()
        status = "approved" if approval.approved else "denied"
        self._emit("approval", approval_id=approval.approval_id, approval_kind=kind,
                   title=title, status=status, reason=approval.reason, remember=approval.remember)
        return approval

    def decide(
        self,
        approval_id: str,
        approved: bool,
        remember: list[str] | None = None,
        secret: str | None = None,
        reason: str = "",
    ) -> bool:
        with self._lock:
            approval = self._pending.pop(approval_id, None)
        if approval is None:
            return False
        if approved and approval.kind == SECRET and not secret:
            # Put it back: a secret prompt can't be approved without a value
            with self._lock:
                self._pending[approval_id] = approval
            return False
        valid = {o["id"] for o in approval.options}
        approval.remember = [r for r in (remember or []) if r in valid] if approved else []
        approval.secret = secret if approved else None
        approval.approved = approved
        approval.reason = reason or ("approved by operator" if approved else "denied by operator")
        approval._done.set()
        return True

    def deny_all(self, reason: str) -> int:
        with self._lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for approval in pending:
            approval.approved = False
            approval.reason = reason
            approval._done.set()
        return len(pending)

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return [a.public() for a in self._pending.values()]
