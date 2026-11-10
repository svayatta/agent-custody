# A deny reason goes into the model's context. When the denial receipt cannot be written, the reason says why by
# failure class only: a sidecar URL can carry credentials and an upstream answer can carry anything, and neither may
# reach the model. The operator still gets the full error, from the agent_custody logger.
import asyncio
import io
import json
import logging
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest
from agents import RunConfig, function_tool
from agents.tool_context import ToolContext
from crewai.tools import tool

from agent_custody import Client
from agent_custody import crewai as crewai_adapter
from agent_custody import openai_agents as openai_adapter
from agent_custody.adk import adk_callbacks
from agent_custody.claude_agent_sdk import handle_hook_event
from agent_custody.hermes import hermes_hooks
from conftest import closed_port

SECRETS = ("admin", "s3cr3t", "t0k3n", "127.0.0.1", "log.example", "upstream said")
DENY = {"decision": "deny", "reasons": [], "errors": [], "policyDigest": "sha256:0"}


@function_tool(name_override="stripe.refund")
def oa_refund(amount: int) -> dict:
    """Refund an amount."""
    return {"amount": amount}


@tool("stripe.refund")
def crew_refund(amount: int) -> dict:
    """Refund an amount, in minor units."""
    return {"amount": amount}


def _openai(client):
    ctx = ToolContext(context=None, tool_name="stripe.refund", tool_call_id="call-1", tool_arguments='{"amount": 1}', run_config=RunConfig())
    return asyncio.run(openai_adapter.wrap_tools(client, [oa_refund])[0].on_invoke_tool(ctx, '{"amount": 1}'))


ADAPTERS = {
    "adk": lambda c: adk_callbacks(c)["before_tool_callback"](SimpleNamespace(name="stripe.refund"), {"amount": 1}, SimpleNamespace())["error"],
    "hermes": lambda c: hermes_hooks(c)["pre_tool_call"]("stripe.refund", {"amount": 1}, "task-1")["message"],
    "openai_agents": _openai,
    "crewai": lambda c: crewai_adapter.wrap_tools(c, [crew_refund])[0].run(amount=1),
    "claude_agent_sdk": lambda c: handle_hook_event(c, {"hook_event_name": "PreToolUse", "tool_name": "stripe.refund", "tool_input": {"amount": 1}})["hookSpecificOutput"]["permissionDecisionReason"],
}


class _Answer(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _unreachable(req, timeout):
    raise urllib.error.URLError(ConnectionRefusedError(61, "Connection refused"))


def _upstream_error(req, timeout):
    body = {"error": "log https://admin:s3cr3t@log.example/?token=t0k3n refused the append: 500 upstream said t0k3n"}
    raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway", {}, io.BytesIO(json.dumps(body).encode()))


def _not_json(req, timeout):
    return _Answer(b"<html>upstream said s3cr3t</html>")


FAILURES = {
    "credentials in the url": (_unreachable, "the sidecar could not be reached", "s3cr3t"),
    "an upstream body": (_upstream_error, "the sidecar answered HTTP 502", "upstream said"),
    "an answer that is not json": (_not_json, "the sidecar's answer was malformed", "not JSON"),
}


@pytest.mark.parametrize("adapter", ADAPTERS)
@pytest.mark.parametrize("failure", FAILURES)
def test_the_deny_reason_names_the_failure_and_keeps_secrets_out(adapter, failure, monkeypatch, caplog):
    urlopen, why, logged = FAILURES[failure]
    client = Client(f"http://admin:s3cr3t@127.0.0.1:{closed_port()}/?token=t0k3n")
    monkeypatch.setattr(client, "decide", lambda *a, **k: DENY)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    with caplog.at_level(logging.WARNING, logger="agent_custody"):
        reason = str(ADAPTERS[adapter](client))
    assert reason.endswith(f"no permit policy matched (no receipt: {why})"), reason
    assert [s for s in SECRETS if s in reason] == []
    assert logged in caplog.text  # the operator can still see what went wrong


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_a_real_unreachable_sidecar_with_a_token_in_the_url(adapter, monkeypatch):
    client = Client(f"http://127.0.0.1:{closed_port()}/?token=t0k3n")
    monkeypatch.setattr(client, "decide", lambda *a, **k: DENY)
    reason = str(ADAPTERS[adapter](client))
    assert reason.endswith("(no receipt: the sidecar could not be reached)") and "t0k3n" not in reason, reason


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_an_unexpected_error_gives_its_type_not_its_text(adapter, monkeypatch):
    client = Client()
    monkeypatch.setattr(client, "decide", lambda *a, **k: DENY)

    def boom(*a, **k):
        raise RuntimeError("http://admin:s3cr3t@127.0.0.1/")

    monkeypatch.setattr(client, "record", boom)
    reason = str(ADAPTERS[adapter](client))
    assert reason.endswith("(no receipt: an unexpected RuntimeError)") and "s3cr3t" not in reason, reason


@pytest.mark.parametrize("failure", FAILURES)
def test_the_claude_hook_keeps_secrets_out_when_the_policy_cannot_be_evaluated(failure, monkeypatch, caplog):
    urlopen, why, logged = FAILURES[failure]
    client = Client(f"http://admin:s3cr3t@127.0.0.1:{closed_port()}/?token=t0k3n")
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    with caplog.at_level(logging.WARNING, logger="agent_custody"):
        reason = handle_hook_event(client, {"hook_event_name": "PreToolUse", "tool_name": "stripe.refund", "tool_input": {"amount": 1}})["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason == f"agent-custody: the policy could not be evaluated; no receipt: {why}"
    assert [s for s in SECRETS if s in reason] == []
    assert logged in caplog.text
