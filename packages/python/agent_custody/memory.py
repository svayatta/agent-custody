"""The memory tools from Python, over MCP, against the shared memory server (`agent-custody-memory serve --http`).

Writes made this way are claimed: they did not come through the receipts gateway, so the ledger quarantines them
until a gateway confirms them. That is the honest position of an SDK-only agent, and the point of a shared ledger:
the fleet sees what a gateway-attested agent wrote, and what this agent wrote waits for confirmation.

    async with MemoryClient("http://127.0.0.1:8790/mcp", token="...") as memory:
        fact = await memory.write("acct:42", "plan", "pro", space="team:support", actor="py-agent")
        facts = await memory.read(subject="acct:42", include_claimed=True)
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

__all__ = ["MemoryClient", "MemoryError"]


class MemoryError(RuntimeError):
    """The memory server refused the call. Nothing was written."""


def _refusal(e: BaseException) -> str:
    """The reason inside whatever the transport raised: an HTTP status if there is one, else the innermost message."""
    seen = [e]
    while seen:
        x = seen.pop()
        status = getattr(getattr(x, "response", None), "status_code", None)
        if status is not None:
            return f"HTTP {status}"
        seen.extend(getattr(x, "exceptions", []) or [])
    inner = e
    while getattr(inner, "exceptions", None):
        inner = inner.exceptions[0]  # type: ignore[attr-defined]
    return str(inner) or type(inner).__name__


class MemoryClient:
    def __init__(self, url: str, token: Optional[str] = None):
        self.url = url
        self.token = token
        self._cm = None
        self._session: Optional[ClientSession] = None

    async def __aenter__(self) -> "MemoryClient":
        headers = {"authorization": f"Bearer {self.token}"} if self.token else None
        # A refused token surfaces inside the transport's task group as a cancellation, not as the status. Ask first.
        try:
            async with create_mcp_http_client(headers=headers) as http:
                probe = await http.post(self.url, json={"jsonrpc": "2.0", "id": 0, "method": "ping"}, headers={"accept": "application/json, text/event-stream"})
        except Exception as e:  # noqa: BLE001 - mcp 1.x brings httpx and mcp 2.x httpx2; either one's transport error means the same
            raise MemoryError(f"memory server at {self.url} could not be reached: {_refusal(e)}") from None
        if probe.status_code in (401, 403):
            raise MemoryError(f"memory server at {self.url} refused the connection: HTTP {probe.status_code}")
        self._cm = streamable_http_client(self.url, http_client=create_mcp_http_client(headers=headers))
        try:
            # mcp 2.x yields (read, write); mcp 1.x yields (read, write, get_session_id). Both are supported.
            read, write, *_ = await self._cm.__aenter__()
            self._session = ClientSession(read, write)
            await self._session.__aenter__()
            await self._session.initialize()
        except BaseException as e:  # noqa: BLE001 - the transport raises exception groups; the caller gets one plain error
            detail = _refusal(e)
            # the transport often reports only "Session terminated"; the probe's status says why
            if probe.status_code >= 400 and not detail.startswith("HTTP "):
                detail = f"HTTP {probe.status_code} ({detail})"
            try:
                await self.__aexit__(None, None, None)
            except BaseException:  # noqa: BLE001
                pass
            self._session = None
            self._cm = None
            raise MemoryError(f"memory server at {self.url} refused the connection: {detail}") from None
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._session is not None:
            await self._session.__aexit__(*exc)
        if self._cm is not None:
            await self._cm.__aexit__(*exc)

    async def _call(self, tool: str, args: Dict[str, Any]) -> Any:
        assert self._session is not None, "use `async with MemoryClient(...) as memory:`"
        result = await self._session.call_tool(tool, {k: v for k, v in args.items() if v is not None})
        text = next((c.text for c in result.content if getattr(c, "type", None) == "text"), "")
        if getattr(result, "is_error", None) or getattr(result, "isError", None):
            raise MemoryError(text)
        return json.loads(text) if text else None

    async def write(self, subject: str, predicate: str, value: Any, *, space: str, actor: Optional[str] = None, supersedes: Optional[str] = None, valid_from: Optional[str] = None) -> Dict[str, Any]:
        """Records a belief. Returns {fact, eventId, txTime, supersedes}; the fact's provenance is claimed."""
        return await self._call("memory.write", {"subject": subject, "predicate": predicate, "value": value, "space": space, "actor": actor, "supersedes": supersedes, "validFrom": valid_from})

    async def read(self, *, subject: Optional[str] = None, predicate: Optional[str] = None, space: Optional[str] = None, valid_at: Optional[str] = None, tx_at: Optional[str] = None, include_claimed: bool = False, require_verified: bool = False) -> List[Dict[str, Any]]:
        """The facts believed at a moment. Quarantined facts, including this client's own unconfirmed writes, are left out unless include_claimed."""
        out = await self._call("memory.read", {"subject": subject, "predicate": predicate, "space": space, "validAt": valid_at, "txAt": tx_at, "includeClaimed": include_claimed or None, "requireVerified": require_verified or None})
        return out["facts"]

    async def retract(self, fact_id: str, reason: str, *, actor: Optional[str] = None) -> Dict[str, Any]:
        return await self._call("memory.retract", {"factId": fact_id, "reason": reason, "actor": actor})

    async def history(self, fact_id: str) -> List[Dict[str, Any]]:
        return (await self._call("memory.history", {"factId": fact_id}))["events"]
