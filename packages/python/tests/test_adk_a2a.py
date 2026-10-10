# An ADK agent delegating to an ADK agent over A2A, through the gateway. The remote agent is served by ADK's own
# to_a2a; the caller is ADK's own RemoteA2aAgent, pointed at the gateway's card instead of the remote agent's. The
# gateway is `agent-custody gateway --a2a` in its own process. One delegation is allowed and answered by the remote
# agent, one is refused by the policy and never reaches it; both receipts pass the TypeScript verifier.
import asyncio
import json
import re
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from google.adk.a2a.utils.agent_to_a2a import to_a2a
from google.adk.agents import LlmAgent
from google.adk.agents.remote_a2a_agent import AGENT_CARD_WELL_KNOWN_PATH, RemoteA2aAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from conftest import RECEIPTS

POLICY = """permit(principal, action == Action::"docs.card", resource);
permit(principal, action == Action::"docs.send", resource)
when { context.facts.card.name == "document_agent" && !(context.args.text like "*privileged*") };
"""


class Scripted(BaseLlm):
    model: str = "scripted"

    async def generate_content_async(self, llm_request, stream=False):
        texts = [p.text for c in llm_request.contents for p in (c.parts or []) if p.text]
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=f"document agent says: {texts[-1]}")]))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def remote_agent():
    """The document agent, served by ADK over A2A on a free port."""
    port = free_port()
    agent = LlmAgent(name="document_agent", model=Scripted(), description="Reads and summarises engagement documents.", instruction="Summarise.")
    app = to_a2a(agent, host="127.0.0.1", port=port)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True


@pytest.fixture(scope="module")
def proxy(sidecar, remote_agent):
    """The gateway as an A2A agent in front of the document agent, under the engagement lead's grant."""
    node = sidecar["node"]
    d = Path(tempfile.mkdtemp(prefix="agent-custody-a2a-"))
    cli = str(RECEIPTS / "src/cli.ts")
    for name in ("gateway", "principal"):
        subprocess.run([node, cli, "keygen", "--dir", str(d / "keys"), "--name", name], check=True, capture_output=True)
    subprocess.run([node, cli, "grant", "--key", str(d / "keys/principal.key"), "--principal", "engagement_lead_12", "--agent", "engagement-agent", "--scopes", "docs.send,docs.card", "--out", str(d / "grant.json")], check=True, capture_output=True)
    (d / "policy.cedar").write_text(POLICY)
    (d / "gateway.json").write_text(json.dumps({
        "identity": {"keyFile": "keys/gateway.key"},
        "upstream": {"a2a": {"url": remote_agent, "prefix": "docs"}},
        "grantFile": "grant.json",
        "trustedPrincipalKeys": ["keys/principal.pub"],
        "policyFile": "policy.cedar",
        "facts": [{"name": "card", "tool": "docs.card", "args": {}, "forTools": ["docs.send"]}],
        "precommit": ["docs.send"],
        "receiptsDir": "receipts",
        "logFile": "log.jsonl",
    }))
    p = subprocess.Popen([node, cli, "gateway", "--config", str(d / "gateway.json"), "--a2a", "--port", "0"], stderr=subprocess.PIPE, text=True)
    line = p.stderr.readline()
    m = re.search(r"(http://[^ ]+)", line)
    assert m, f"gateway did not start: {line}"
    yield {"url": m.group(1), "dir": d, "node": node, "cli": cli}
    p.terminate()
    p.wait(timeout=10)


def run(agent, *texts):
    """One loop for every run: the remote agent's HTTP client is bound to the loop it first saw."""

    async def go():
        runner = InMemoryRunner(agent=agent, app_name="t")
        outs = []
        for text in texts:
            session = await runner.session_service.create_session(app_name="t", user_id="u")
            out = []
            async for ev in runner.run_async(user_id="u", session_id=session.id, new_message=types.Content(role="user", parts=[types.Part(text=text)])):
                out.append(ev)
            outs.append(out)
        return outs

    return asyncio.run(go())


def texts(events):
    return [p.text for ev in events for p in (ev.content.parts if ev.content else []) if p.text]


def verify(proxy, receipt: Path) -> dict:
    out = subprocess.run([proxy["node"], proxy["cli"], "verify", str(receipt), "--issuer-key", str(proxy["dir"] / "keys/gateway.pub"), "--principal-key", str(proxy["dir"] / "keys/principal.pub"), "--log", str(proxy["dir"] / "log.jsonl"), "--json"], capture_output=True, text=True)
    return json.loads(out.stdout)


def test_adk_delegation_through_the_gateway(proxy):
    card = json.loads(__import__("urllib.request").request.urlopen(proxy["url"] + AGENT_CARD_WELL_KNOWN_PATH).read())
    assert card["name"] == "document_agent" and card["supportedInterfaces"][0]["url"] == proxy["url"]

    caller = RemoteA2aAgent(name="document_agent", description="The document agent, through the gateway", agent_card=proxy["url"] + AGENT_CARD_WELL_KNOWN_PATH)
    first, second = run(caller, "summarise the evidence for matter M-1042", "summarise the privileged memo for matter M-1042")
    allowed, refused = texts(first), texts(second)
    assert any("document agent says: summarise the evidence for matter M-1042" in t for t in allowed), allowed
    assert any("agent-custody: no permit policy matched (receipt " in t for t in refused), refused

    # the allowed delegation was consequential, so its authorization sits beside its receipt as <id>.authorization.json
    receipts = sorted((p for p in (proxy["dir"] / "receipts").glob("*.json") if not p.name.endswith(".authorization.json")), key=lambda p: p.stat().st_mtime)
    assert len(receipts) == 2
    reports = [verify(proxy, r) for r in receipts]
    assert all(r["ok"] for r in reports), reports
    predicates = [r["statement"]["predicate"] for r in reports]
    assert [p["execution"]["status"] for p in predicates] == ["executed", "denied"]
    assert all(p["tool"]["name"] == "docs.send" for p in predicates)
    assert predicates[0]["facts"]["card"]["value"]["name"] == "document_agent"
    assert predicates[0]["request"]["args"]["method"] == "SendStreamingMessage"
    assert "authorization" in predicates[0]
    assert "TASK_STATE_COMPLETED" in json.dumps(predicates[0]["execution"]["result"])
