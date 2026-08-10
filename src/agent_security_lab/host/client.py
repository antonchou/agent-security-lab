"""Multi-MCP stdio client manager."""

from __future__ import annotations

import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_security_lab.config import ROOT


@dataclass
class RemoteTool:
    server_id: str
    name: str  # bare name from server
    namespaced: str
    description: str
    input_schema: dict[str, Any]

    def to_meta_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "name": self.name,
            "namespaced": self.namespaced,
            "description": self.description,
            "input_schema": self.input_schema,
        }


@dataclass
class MCPClientManager:
    """Connects to benign + malicious MCP servers over stdio."""

    python_executable: str = field(default_factory=lambda: sys.executable)
    _stack: AsyncExitStack | None = None
    _sessions: dict[str, ClientSession] = field(default_factory=dict)
    tools: dict[str, RemoteTool] = field(default_factory=dict)
    bare_index: dict[str, list[str]] = field(default_factory=dict)

    def _server_params(self, module: str, env: dict[str, str] | None = None) -> StdioServerParameters:
        import os

        full_env = os.environ.copy()
        # Ensure src is importable
        pp = full_env.get("PYTHONPATH", "")
        src = str(ROOT / "src")
        full_env["PYTHONPATH"] = src if not pp else f"{src}:{pp}"
        if env:
            full_env.update(env)
        return StdioServerParameters(
            command=self.python_executable,
            args=["-m", module],
            env=full_env,
            cwd=str(ROOT),
        )

    async def start(
        self,
        *,
        connect_benign: bool = True,
        connect_malicious: bool = True,
        malicious_env: dict[str, str] | None = None,
    ) -> None:
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()
        if connect_benign:
            await self._connect("benign", "agent_security_lab.mcp_servers.benign.server")
        if connect_malicious:
            await self._connect(
                "malicious",
                "agent_security_lab.mcp_servers.malicious.server",
                env=malicious_env,
            )
        await self.refresh_tools()

    async def _connect(
        self,
        server_id: str,
        module: str,
        env: dict[str, str] | None = None,
    ) -> None:
        assert self._stack is not None
        params = self._server_params(module, env=env)
        read, write = await self._stack.enter_async_context(stdio_client(params))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        self._sessions[server_id] = session

    async def refresh_tools(self) -> dict[str, RemoteTool]:
        self.tools.clear()
        self.bare_index.clear()
        for server_id, session in self._sessions.items():
            listed = await session.list_tools()
            for t in listed.tools:
                bare = t.name
                namespaced = f"{server_id}.{bare}"
                schema = t.inputSchema if isinstance(t.inputSchema, dict) else {}
                rt = RemoteTool(
                    server_id=server_id,
                    name=bare,
                    namespaced=namespaced,
                    description=t.description or "",
                    input_schema=schema,
                )
                self.tools[namespaced] = rt
                self.bare_index.setdefault(bare, []).append(namespaced)
        return self.tools

    def resolve(self, name: str, conflict_mode: str = "deny") -> RemoteTool:
        """Resolve namespaced or bare tool name."""
        if name in self.tools:
            return self.tools[name]
        # bare name
        cands = self.bare_index.get(name, [])
        if not cands:
            # try with any server prefix match
            for ns, rt in self.tools.items():
                if ns.endswith(f".{name}"):
                    cands.append(ns)
        if not cands:
            raise KeyError(f"unknown_tool:{name}")
        if len(cands) == 1:
            return self.tools[cands[0]]
        if conflict_mode == "last_wins":
            return self.tools[cands[-1]]
        raise LookupError(f"name_conflict:{name}->{cands}")

    def collisions(self) -> dict[str, list[str]]:
        return {b: ns for b, ns in self.bare_index.items() if len(ns) > 1}

    async def call_raw(self, server_id: str, bare_name: str, arguments: dict[str, Any]) -> str:
        session = self._sessions[server_id]
        result = await session.call_tool(bare_name, arguments)
        # Concatenate text content blocks
        parts: list[str] = []
        for block in result.content:
            text = getattr(block, "text", None)
            if text is not None:
                parts.append(text)
            else:
                parts.append(str(block))
        return "\n".join(parts)

    async def aclose(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
        self._sessions.clear()
        self.tools.clear()
