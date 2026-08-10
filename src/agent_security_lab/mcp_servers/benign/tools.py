"""Benign tool implementations: sandboxed read, mock email, safe calculate."""

from __future__ import annotations

import ast
import json
import operator
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Project root
_ROOT = Path(__file__).resolve().parents[4]
_LAB_FS = _ROOT / "lab_fs"
_PUBLIC = _LAB_FS / "public"
_OUTBOX = _ROOT / "outbox"

_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


class SandboxError(ValueError):
    pass


def _resolve_public(path: str) -> Path:
    raw = Path(path)
    if raw.is_absolute():
        candidate = raw.resolve()
    else:
        # Allow lab_fs/public/... or public/... or bare filename
        text = path.replace("\\", "/")
        if text.startswith("lab_fs/"):
            candidate = (_ROOT / text).resolve()
        elif text.startswith("public/"):
            candidate = (_LAB_FS / text).resolve()
        else:
            candidate = (_PUBLIC / text).resolve()
    public_root = _PUBLIC.resolve()
    try:
        candidate.relative_to(public_root)
    except ValueError as exc:
        raise SandboxError(
            f"path_outside_public_sandbox: {path} (resolved={candidate})"
        ) from exc
    if not candidate.exists() or not candidate.is_file():
        raise SandboxError(f"file_not_found: {path}")
    return candidate


def read_file(path: str) -> str:
    """Read a file under lab_fs/public only (sandbox)."""
    target = _resolve_public(path)
    return target.read_text(encoding="utf-8")


def send_email(to: str, subject: str, body: str) -> str:
    """Mock email: write JSON to outbox/ (no network)."""
    _OUTBOX.mkdir(parents=True, exist_ok=True)
    msg_id = f"mail-{uuid.uuid4().hex[:12]}"
    payload: dict[str, Any] = {
        "id": msg_id,
        "to": to,
        "subject": subject,
        "body": body,
        "ts": datetime.now(timezone.utc).isoformat(),
        "transport": "mock_outbox",
        "server": "benign",
    }
    out = _OUTBOX / f"{msg_id}.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return json.dumps({"status": "queued", "id": msg_id, "path": str(out)})


def _eval_ast(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _eval_ast(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return float(_OPS[type(node.op)](_eval_ast(node.operand)))
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        left = _eval_ast(node.left)
        right = _eval_ast(node.right)
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and right == 0:
            raise SandboxError("division_by_zero")
        return float(_OPS[type(node.op)](left, right))
    raise SandboxError(f"unsupported_expression_node:{type(node).__name__}")


def calculate(expression: str) -> str:
    """Safe arithmetic calculator (AST whitelist)."""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise SandboxError(f"syntax_error:{exc}") from exc
    value = _eval_ast(tree)
    return json.dumps({"expression": expression, "result": value})
