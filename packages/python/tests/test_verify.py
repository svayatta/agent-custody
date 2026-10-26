# The independent verifier against the conformance vectors. It agrees with the reference only when it reproduces
# every verdict and names exactly the checks that fail, so each case compares the failing set, not just ok.
import base64
import hashlib
import json
from pathlib import Path

import pytest

from agent_custody import verify as v

VECTORS = Path(__file__).resolve().parents[2] / "receipts" / "vectors"


def load(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


RECEIPTS = load("receipts.json")
KEYS = {name: v.load_public_key(k["publicKeyPem"]) for name, k in RECEIPTS["keys"].items()}


def keys(names):
    return [KEYS[n] for n in names or []]


@pytest.mark.parametrize("case", RECEIPTS["cases"], ids=lambda c: c["name"])
def test_receipt_vector(case):
    trust = v.Trust(
        issuer=keys(case["issuerKeys"]),
        principal=keys(case["principalKeys"]),
        approval=keys(case.get("approvalKeys")),
        upstream=keys(case.get("upstreamKeys")),
        log=keys(case["logKeys"]),
        provider_secrets=case.get("providerSecrets") or {},
    )
    report = v.verify_bundle(case["bundle"], trust, log=case["log"], log_id=case.get("logId"), require_strict=bool(case.get("requireStrict")))
    assert sorted(report.failing) == sorted(case["expected"]["failing"]), [(c.name, c.ok, c.detail) for c in report.checks]
    assert report.ok is case["expected"]["ok"]


def test_vector_keys_match_their_keyids():
    for name, k in RECEIPTS["keys"].items():
        assert KEYS[name].keyid == k["keyid"], name


@pytest.mark.parametrize("case", load("audit.json")["cases"], ids=lambda c: c["name"])
def test_audit_vector(case):
    report = v.audit_extends(case["older"], case["newer"], case["proof"], keys(case["keys"]))
    assert sorted(report.failing) == sorted(case["expected"]["failing"])
    assert report.ok is case["expected"]["ok"]


CANONICAL = load("canonical.json")


@pytest.mark.parametrize("item", CANONICAL["values"], ids=lambda i: i["canonical"][:20])
def test_canonical_json_and_digest(item):
    assert v.canonical_json(item["value"]) == item["canonical"]
    assert v.digest(item["value"]) == item["digest"]


def test_keyid_is_sha256_of_spki():
    assert v.load_public_key(CANONICAL["keyid"]["publicKeyPem"]).keyid == CANONICAL["keyid"]["keyid"]


def test_dsse_pae_and_signature():
    d = CANONICAL["dsse"]
    payload = base64.b64decode(d["envelope"]["payload"])
    assert payload.decode() == d["payloadJson"]
    message = v.pae(d["envelope"]["payloadType"], payload)
    assert message.hex() == d["paeHex"]
    assert hashlib.sha256(message).hexdigest() == d["paeSha256"]
    key = v.load_public_key(d["publicKeyPem"])
    assert (v.dsse_signers(d["envelope"], [key]) == [key.keyid]) is d["expected"]


def test_a_changed_payload_byte_breaks_the_dsse_signature():
    d = CANONICAL["dsse"]
    env = dict(d["envelope"], payload=base64.b64encode(b'{"hello":"World"}').decode())
    assert v.dsse_signers(env, [v.load_public_key(d["publicKeyPem"])]) == []


# Numbers print as ECMAScript prints them, or a digest over a float or a large integer differs between languages.
@pytest.mark.parametrize(
    "value,text",
    [(1e21, "1e+21"), (1e20, "100000000000000000000"), (1e-7, "1e-7"), (0.000001, "0.000001"), (25.01, "25.01"), (2.0, "2"), (-0.0, "0"), (1.5e300, "1.5e+300")],
)
def test_numbers_print_like_ecmascript(value, text):
    assert v.canonical_json(value) == text


def test_keys_sort_by_utf16_code_units():
    # U+FFFF sorts after U+1F600 in UTF-16 (0xFFFF > 0xD83D) but before it by code point.
    assert v.canonical_json({"\U0001F600": 1, "￿": 2}) == '{"\U0001F600":1,"￿":2}'


MERKLE = load("merkle.json")


def test_merkle_leaf_hashes_and_roots():
    leaves = [leaf.encode() if isinstance(leaf, str) else bytes.fromhex(leaf["hex"]) for leaf in MERKLE["leaves"]]
    hashes = [v.leaf_hash(leaf) for leaf in leaves]
    assert [h.hex() for h in hashes] == MERKLE["leafHashes"]
    for size, root in enumerate(MERKLE["roots"]):
        assert v.tree_root(hashes[:size]).hex() == root


@pytest.mark.parametrize("case", MERKLE["inclusion"], ids=lambda c: f"{c['leafIndex']}-of-{c['treeSize']}")
def test_merkle_inclusion(case):
    leaf = bytes.fromhex(MERKLE["leafHashes"][case["leafIndex"]])
    root = v.root_from_inclusion(case["leafIndex"], case["treeSize"], leaf, [bytes.fromhex(h) for h in case["hashes"]])
    assert (root is not None and root.hex() == case["root"]) is case["expected"]


@pytest.mark.parametrize("case", MERKLE["consistency"], ids=lambda c: f"{c['oldSize']}-to-{c['newSize']}")
def test_merkle_consistency(case):
    ok = v.verify_consistency(case["oldSize"], case["newSize"], bytes.fromhex(case["oldRoot"]), bytes.fromhex(case["newRoot"]), [bytes.fromhex(h) for h in case["hashes"]])
    assert ok is case["expected"]


def test_cli_verifies_a_bundle_and_exits_nonzero_on_a_forgery(tmp_path, capsys):
    case = next(c for c in RECEIPTS["cases"] if c["name"] == "gateway-executed")
    (tmp_path / "bundle.json").write_text(json.dumps(case["bundle"]))
    (tmp_path / "log.jsonl").write_text("".join(json.dumps(line) + "\n" for line in case["log"]))
    for name in ("gateway", "principal"):
        (tmp_path / f"{name}.pub").write_text(RECEIPTS["keys"][name]["publicKeyPem"])
    args = [str(tmp_path / "bundle.json"), "--issuer-key", str(tmp_path / "gateway.pub"), "--principal-key", str(tmp_path / "principal.pub"), "--log", str(tmp_path / "log.jsonl")]
    assert v.main(args + ["--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] and "log file root matches tree head" in [c["name"] for c in out["checks"]]
    assert ("tool", "observed", "stripe.refund") in [(f["field"], f["provenance"], f["value"]) for f in out["fields"]]
    assert v.main([str(tmp_path / "bundle.json"), "--issuer-key", str(tmp_path / "principal.pub")]) == 1
    assert "FAIL  receipt signature (issuer key)" in capsys.readouterr().out


def test_cli_reads_provider_secrets_from_the_environment(tmp_path, monkeypatch, capsys):
    case = next(c for c in RECEIPTS["cases"] if c["name"] == "gateway-executed-stripe-webhook")
    (tmp_path / "bundle.json").write_text(json.dumps(case["bundle"]))
    for name in ("gateway-2", "principal-2"):
        (tmp_path / f"{name}.pub").write_text(RECEIPTS["keys"][name]["publicKeyPem"])
    monkeypatch.setenv("STRIPE_SECRET_FOR_TEST", case["providerSecrets"]["stripe"])
    args = [str(tmp_path / "bundle.json"), "--issuer-key", str(tmp_path / "gateway-2.pub"), "--principal-key", str(tmp_path / "principal-2.pub")]
    assert v.main(args + ["--provider-secret-env", "stripe=STRIPE_SECRET_FOR_TEST"]) == 0
    assert "PASS  upstream signature (provider secret)" in capsys.readouterr().out


# Beyond the vectors: a receipt the sidecar issues now, and an edit of it, get the same verdict from both verifiers.
def test_a_fresh_sidecar_receipt_gets_the_reference_verdict(client, sidecar):
    from agent_custody import receipt_id_of
    from conftest import verify as reference

    policy = client.decide("stripe.refund", {"amount": 500})
    rid = receipt_id_of(client.record("stripe.refund", {"amount": 500}, {"status": "executed", "result": {"refund_id": "re_9"}}, policy))
    path = sidecar["receipts"] / f"{rid}.json"
    trust = v.Trust(issuer=[v.load_public_key(sidecar["app_pub"].read_text())])
    log = v.read_log(str(sidecar["log"]))
    report = v.verify_bundle(json.loads(path.read_text()), trust, log=log)
    ts = reference(sidecar, rid)
    assert report.ok and ts["ok"], report.failing
    assert {c["name"] for c in ts["checks"]} == {c.name for c in report.checks}

    edited = json.loads(path.read_text())
    edited["inclusion"]["leafIndex"] += 1
    assert v.verify_bundle(edited, trust, log=log).failing == ["log inclusion proof"]


# Inputs the published vectors do not cover, issued and verified by the TypeScript code in cross_language.mts. Each
# names what the TypeScript verifier must reject, so a change on either side that stops rejecting it fails here too.
CROSS_LANGUAGE = {
    "approval-only-in-precommit": ["authorization carries this approval", "authorization approval was valid"],
    "upstream-evidence-missing": ["upstream signature (upstream key)"],
    "upstream-unknown-provider": ["upstream signature (upstream key)"],
    "upstream-malformed-provider": ["upstream signature (upstream key)"],
    "provider-secret-for-other-provider": ["upstream signature (provider secret)"],
    "operation-confirmed-without-evidence": ["operation awaits provider reconciliation", "operation carries committed authorization"],
    "numeric-keys": [],
    "astral-key": [],
}


@pytest.fixture(scope="module")
def cross_language(tmp_path_factory):
    import shutil
    import subprocess

    node = shutil.which("node")
    assert node, "node is required: these bundles are issued by the TypeScript code"
    d = tmp_path_factory.mktemp("cross-language")
    out = subprocess.run([node, str(Path(__file__).with_name("cross_language.mts")), str(d)], check=True, capture_output=True, text=True)
    data = json.loads(out.stdout)
    data["keys"] = {name: v.load_public_key(pem) for name, pem in data["keys"].items()}
    data["cases"] = {c["name"]: c for c in data["cases"]}
    return data


@pytest.mark.parametrize("name", CROSS_LANGUAGE)
def test_cross_language_verdicts(cross_language, name):
    case, k = cross_language["cases"][name], cross_language["keys"]
    assert sorted(case["tsFailing"]) == sorted(CROSS_LANGUAGE[name]), "the TypeScript verifier changed its verdict"
    trust = v.Trust(issuer=[k["issuer"]], principal=[k["principal"]], approval=[k[n] for n in case["trust"]["approval"]], upstream=[k[n] for n in case["trust"]["upstream"]], provider_secrets=case["trust"].get("providerSecrets") or {})
    report = v.verify_bundle(case["bundle"], trust, log=v.read_log(cross_language["log"]))
    assert sorted(report.failing) == sorted(case["tsFailing"]), [(c.name, c.ok, c.detail) for c in report.checks]


def test_array_index_keys_come_first_in_numeric_order():
    # The producer sorts keys, then JSON.stringify emits array-index keys (canonical integers below 2^32 - 1) first.
    assert v.canonical_json({"a": 1, "10": "ten", "2": "two", "01": 0, "4294967295": 0, "4294967294": 0}) == '{"2":"two","10":"ten","4294967294":0,"01":0,"4294967295":0,"a":1}'


def test_integers_beyond_2_53_print_as_the_double_javascript_reads():
    assert v.canonical_json(12345678901234567890) == "12345678901234567000"
