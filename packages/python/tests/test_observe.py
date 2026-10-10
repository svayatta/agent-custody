# Observe mode from Python: the sidecar's decision carries enforced=False, so wrap runs the function and records the
# deny instead of raising, and the hook adapters return no block. Against a second real sidecar started in observe mode.
import json
import re
import subprocess
from types import SimpleNamespace

import pytest
from agent_custody import Client, denies
from agent_custody.claude_agent_sdk import handle_hook_event
from agent_custody.adk import adk_callbacks
from agent_custody.hermes import hermes_hooks
from conftest import POLICY, RECEIPTS, receipt_count, verify


@pytest.fixture(scope="module")
def observe_sidecar(sidecar, tmp_path_factory):
    d = tmp_path_factory.mktemp("observe")
    subprocess.run([sidecar["node"], str(RECEIPTS / "src/cli.ts"), "keygen", "--dir", str(d / "keys"), "--name", "app"], check=True, capture_output=True)
    (d / "policy.cedar").write_text(POLICY)
    (d / "sdk.json").write_text(json.dumps({"agentId": "py-bot", "identity": {"keyFile": "keys/app.key"}, "policyFile": "policy.cedar", "mode": "observe", "receiptsDir": "receipts", "logFile": "log.jsonl", "framework": "python"}))
    p = subprocess.Popen([sidecar["node"], str(RECEIPTS / "src/cli.ts"), "serve", "--config", str(d / "sdk.json"), "--port", "0"], stderr=subprocess.PIPE, text=True)
    m = re.search(r"(http://[^ ]+)", p.stderr.readline())
    assert m
    yield {"url": m.group(1), "receipts": d / "receipts", "app_pub": d / "keys" / "app.pub", "log": d / "log.jsonl", "node": sidecar["node"]}
    p.terminate()
    p.wait(timeout=10)


def test_observe_mode_records_the_deny_and_never_blocks(observe_sidecar):
    client = Client(observe_sidecar["url"])
    policy = client.decide("stripe.refund", {"amount": 999999})
    assert policy["decision"] == "deny" and policy["enforced"] is False
    assert denies(policy) is False and denies({"decision": "deny", "reasons": [], "errors": [], "policyDigest": "x"}) is True
    ran = []
    out = client.wrap("stripe.refund", lambda a: ran.append(a) or "refunded")({"amount": 999999})
    assert out == "refunded" and ran == [{"amount": 999999}]
    assert handle_hook_event(client, {"hook_event_name": "PreToolUse", "tool_name": "stripe.refund", "tool_input": {"amount": 999999}}) == {}
    assert hermes_hooks(client)["pre_tool_call"]("stripe.refund", {"amount": 999999}, "t1") is None
    assert adk_callbacks(client)["before_tool_callback"](SimpleNamespace(name="stripe.refund"), {"amount": 999999}, SimpleNamespace(invocation_id="i1", function_call_id="c1")) is None
    # the receipt the wrap wrote says deny, not enforced, executed, and the reference verifier accepts it
    assert receipt_count(observe_sidecar) >= 1
    rid = sorted(observe_sidecar["receipts"].glob("*.json"))[0].stem
    st = verify(observe_sidecar, rid)
    assert st["ok"] is True
    assert st["statement"]["predicate"]["policy"]["decision"] == "deny" and st["statement"]["predicate"]["policy"]["enforced"] is False
    assert st["statement"]["predicate"]["execution"]["status"] == "executed"
