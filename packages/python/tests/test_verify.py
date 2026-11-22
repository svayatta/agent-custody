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


def _hex32(value):
    """A hash as a tree head or proof carries it: 64 lowercase hex digits, read as the bundle verifier reads them."""
    return bytes.fromhex(value) if isinstance(value, str) and v.HEX64.fullmatch(value) else None


@pytest.mark.parametrize("case", MERKLE["inclusion"], ids=lambda c: f"{c['leafIndex']}-of-{c['treeSize']}")
def test_merkle_inclusion(case):
    leaf = bytes.fromhex(case["leafHash"] if "leafHash" in case else MERKLE["leafHashes"][case["leafIndex"]])
    hashes = v._hashes(case["hashes"])
    root = None if hashes is None else v.root_from_inclusion(case["leafIndex"], case["treeSize"], leaf, hashes)
    assert (root is not None and _hex32(case["root"]) == root) is case["expected"]


@pytest.mark.parametrize("case", MERKLE["consistency"], ids=lambda c: f"{c['oldSize']}-to-{c['newSize']}")
def test_merkle_consistency(case):
    old_root, new_root, hashes = _hex32(case["oldRoot"]), _hex32(case["newRoot"]), v._hashes(case["hashes"])
    ok = None not in (old_root, new_root, hashes) and v.verify_consistency(case["oldSize"], case["newSize"], old_root, new_root, hashes)
    assert ok is case["expected"]


def test_proof_checks_read_only_32_byte_hashes():
    # sha256(0x01 || n01 || n23) is the root of four leaves; split as 16 bytes || 48 bytes it "proves" a 16-byte leaf
    hashes = [v.leaf_hash(f"leaf-{i}".encode()) for i in range(4)]
    n01, n23 = v.tree_root(hashes[:2]), v.tree_root(hashes[2:])
    root4 = v.tree_root(hashes)
    assert v.node_hash(n01[:16], n01[16:] + n23) == root4
    assert v.root_from_inclusion(0, 2, n01[:16], [n01[16:] + n23]) is None
    assert v.root_from_inclusion(0, 2, n01, [n23]) == root4
    # the same widths in a consistency check, and roots that are not 32 bytes
    proof = [n23]
    assert v.verify_consistency(2, 4, n01, root4, proof) is True
    assert v.verify_consistency(2, 4, n01, root4, [n23 + b"\x00"]) is False
    assert v.verify_consistency(2, 4, n01[:31], root4, proof) is False
    assert v.verify_consistency(0, 0, b"", b"", []) is False


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


# Malformed inputs from cross_language.mts: the case, a check of the Python verifier, its verdict, and its detail. The
# detail is the fault the verifier names, so a rejection for another reason fails here.
STRUCTURE, HUMANS, GRANT, CHAIN = "structural parts in clear", "approval signatures (human keys)", "delegation signature (principal key)", "delegation chain to the principal"
PROVIDER, ORIGINAL = "upstream signature (provider secret)", "reconciliation original "
NO_STATE = "provider state missing maps to None; the gateway observed the read, no provider signature is implied"
CHECKS = [
    ("predicate-not-an-object", STRUCTURE, False, "statement has no predicate"),
    ("subject-empty", STRUCTURE, False, "statement has no single subject"),
    ("subject-without-digest", STRUCTURE, False, "subject has no name and sha256 digest"),
    ("wrong-predicate-type", "receipt payload type", False, "not an in-toto statement with the receipt predicate type"),
    ("capture-note-without-paths", STRUCTURE, False, "capture note has no path list"),
    ("receipt-id-not-a-string", STRUCTURE, False, "receiptId is not a string"),
    ("issuer-keyid-not-a-string", STRUCTURE, False, "issuer keyid is not a string"),
    ("issuer-strict-not-a-boolean", STRUCTURE, False, "issuer.strict is not a boolean"),
    ("principal-provenance-unknown", STRUCTURE, False, "principal has no provenance"),
    ("agent-id-not-a-string", STRUCTURE, False, "agent id is not a string"),
    ("tool-without-name", STRUCTURE, False, "tool name is not a string"),
    ("delegation-without-envelope", STRUCTURE, False, "delegation has no envelope"),
    ("request-without-args", STRUCTURE, False, "request has no args and argsDigest"),
    ("executed-without-result", STRUCTURE, False, "executed call has no result and resultDigest"),
    ("policy-decision-unknown", STRUCTURE, False, "policy decision is not allow or deny"),
    ("policy-enforced-not-a-boolean", STRUCTURE, False, "policy.enforced is not a boolean"),
    ("policy-errors-not-a-list", STRUCTURE, False, "policy errors is not a list"),
    ("reconciliation-empty", STRUCTURE, False, "reconciliation has no original and lookup"),
    ("bundle-without-tree-head", STRUCTURE, False, "bundle has no tree head and inclusion proof"),
    ("operation-not-an-object", STRUCTURE, False, "operation is not an object"),
    ("operation-id-not-a-uuid", STRUCTURE, False, "operation id is not a UUID"),
    ("operation-original-not-a-uuid", STRUCTURE, False, "operation originalReceiptId is not a UUID"),
    ("operation-key-not-a-sha256", STRUCTURE, False, "operation idempotencyKey or lookupDigest is not a sha256"),
    ("operation-status-unknown", STRUCTURE, False, "operation status or provenance is invalid"),
    ("operation-budget-currency-lowercase", STRUCTURE, False, "operation budget is invalid"),
    ("approval-not-a-record", STRUCTURE, False, "approval is not a record"),
    ("approval-three-approvers", STRUCTURE, False, "approval requiredApprovers is not 1 or 2"),
    ("approval-keyids-not-a-list", STRUCTURE, False, "approval approverKeyids is not a list of strings"),
    ("approval-consumed-at-not-a-time", STRUCTURE, False, "approval consumedAt is not a time with an offset"),
    ("approval-provenance-claimed", STRUCTURE, False, "approval provenance is not observed"),
    ("approval-fields-empty-name", STRUCTURE, False, "approval fields is not a map of names"),
    ("approval-payload-not-an-object", HUMANS, False, "approval payload is not an object"),
    ("approval-payload-version", HUMANS, False, "approval version is not 0.1"),
    ("approval-payload-id-not-a-uuid", HUMANS, False, "approvalId is not a UUID"),
    ("approval-payload-agent-not-a-string", HUMANS, False, "approval agent is not a string"),
    ("approval-payload-args-digest", HUMANS, False, "approval argsDigest is not a sha256"),
    ("approval-payload-currency-empty", HUMANS, False, "approval currency is not a nonempty string"),
    ("approval-payload-expires-at-issue", HUMANS, False, "approval expires before it is issued"),
    ("approval-payload-version", "authorization approval was valid", False, ""),
    ("grant-version", GRANT, False, "grant is not a version 0.1 delegation"),
    ("grant-without-agent", GRANT, False, "grant has no principal and agent"),
    ("grant-scopes-not-a-list", GRANT, False, "grant scopes is not a list of tool names"),
    ("grant-expiry-not-a-time", GRANT, False, "grant window is not two valid times with offsets"),
    ("grant-parent-not-an-envelope", CHAIN, False, "a link is not a delegation envelope"),
    ("chain-verifies", CHAIN, True, "support-agent <- lead"),
    ("chain-parent-without-key", CHAIN, False, "lead names no key to delegate with"),
    ("chain-parent-key-not-ed25519", CHAIN, False, "lead's key is not an Ed25519 public key"),
    ("chain-leaf-signed-by-another-key", CHAIN, False, "the grant to support-agent is not signed by lead's key"),
    ("chain-leaf-names-another-principal", CHAIN, False, "the grant to support-agent names another principal"),
    ("chain-of-4-links", CHAIN, False, "chain deeper than 3 delegations"),
    ("chain-of-5-links", CHAIN, False, "chain deeper than 3 delegations"),
    ("authorization-tree-head-untrusted", "authorization tree head signature", False, ""),
    ("github-delivery", PROVIDER, True, "attested (shared secret), bound issue.id"),
    ("github-delivery-wrong-hmac", PROVIDER, False, "HMAC does not verify"),
    ("github-delivery-body-not-json", PROVIDER, False, "raw body is not JSON"),
    ("github-delivery-bind-missing", PROVIDER, False, "issue.number is not a value in the delivery"),
    ("github-delivery-body-withheld-undeclared", PROVIDER, False, "delivery has no raw body, signature, and binding"),
    ("github-delivery-body-withheld", "upstream signature not checked", True, "the result or the delivery is withheld"),
    ("stripe-signature-without-timestamp", PROVIDER, False, "Stripe signature has no timestamp"),
    ("stripe-timestamp-an-hour-early", PROVIDER, False, "Stripe timestamp outside tolerance of the receipt's"),
    ("reconciliation-over-authorization", ORIGINAL + "authorization operation is submitted", True, ""),
    ("reconciliation-over-authorization", "reconciliation original evidence verifies", True, ""),
    ("reconciliation-over-authorization-private", ORIGINAL + "request args digest", True, ""),
    ("reconciliation-over-authorization-private", "reconciliation lookup args match request", True, "request arguments committed under the capture rule"),
    ("reconciliation-over-authorization-private", "reconciliation provider status", True, "provider result withheld; disclose it to recompute the observed status"),
    ("reconciliation-original-other-predicate-type", ORIGINAL + "authorization signature (issuer key)", False, ""),
    ("reconciliation-original-tool-without-name", ORIGINAL + STRUCTURE, False, "tool name is not a string"),
    ("reconciliation-original-without-delegation", ORIGINAL + GRANT, False, "no delegation"),
    ("reconciliation-original-operation-pending", ORIGINAL + "authorization operation is submitted", False, ""),
    ("reconciliation-original-without-tree-head", ORIGINAL + STRUCTURE, False, "the authorization has no tree head and inclusion proof"),
    ("reconciliation-result-without-text", "reconciliation provider status", False, NO_STATE),
    ("reconciliation-result-not-json", "reconciliation provider status", False, NO_STATE),
    ("operation-only-in-precommit", "authorization names this operation", False, ""),
    ("operation-precommit-pending", "authorization names this operation", False, ""),
]

# Where the TypeScript verifier does not fail the same checks as the Python verifier: the checks it fails instead, or
# None when it throws. An empty list is an input that TypeScript accepts and Python rejects.
TS_DIFFERS = {
    "subject-empty": ["request args digest"],
    "subject-without-digest": None,
    "issuer-keyid-not-a-string": ["issuer keyid matches signer"],
    "issuer-strict-not-a-boolean": [],
    "principal-provenance-unknown": ["delegation binds principal and agent"],
    "agent-id-not-a-string": ["delegation binds principal and agent"],
    "executed-without-result": None,
    "policy-enforced-not-a-boolean": [],
    "policy-errors-not-a-list": [],
    # TypeScript reads the principal's grant and three delegations below it; Python stops one link sooner
    "chain-of-4-links": [],
    "bundle-without-tree-head": ["tree head signature"],
    "reconciliation-original-without-tree-head": ["structural parts in clear"],
}


def cross_language_report(data, name):
    case, k = data["cases"][name], data["keys"]
    trust = v.Trust(issuer=[k["issuer"]], principal=[k["principal"]], approval=[k[n] for n in case["trust"]["approval"]], upstream=[k[n] for n in case["trust"]["upstream"]], provider_secrets=case["trust"].get("providerSecrets") or {})
    return v.verify_bundle(case["bundle"], trust, log=v.read_log(data["log"]))


@pytest.mark.parametrize("name,check,ok,detail", CHECKS, ids=lambda x: x if isinstance(x, str) else "")
def test_cross_language_check(cross_language, name, check, ok, detail):
    report = cross_language_report(cross_language, name)
    assert [(c.ok, c.detail) for c in report.checks if c.name == check] == [(ok, detail)], [(c.name, c.ok, c.detail) for c in report.checks]
    ts = cross_language["cases"][name]["tsFailing"]
    if name in TS_DIFFERS:
        assert (ts and sorted(ts)) == TS_DIFFERS[name], "the TypeScript verifier changed its verdict"
    else:
        assert sorted(report.failing) == sorted(ts), [(c.name, c.ok, c.detail) for c in report.checks]


@pytest.mark.xfail(strict=True, raises=KeyError, reason="verify.py reads predicate.facts before it checks that the receipt has one")
def test_a_receipt_without_facts_fails_the_structural_check(cross_language):
    assert cross_language["cases"]["facts-absent"]["tsFailing"] == [STRUCTURE]
    assert cross_language_report(cross_language, "facts-absent").failing == [STRUCTURE]


def test_a_log_line_that_is_not_a_leaf_fails_the_log_copy():
    case = next(c for c in RECEIPTS["cases"] if c["name"] == "gateway-executed")
    trust = v.Trust(issuer=keys(case["issuerKeys"]), principal=keys(case["principalKeys"]), log=keys(case["logKeys"]))
    assert v.verify_bundle(case["bundle"], trust, log=[7] + case["log"][1:]).failing == ["log file root matches tree head"]


@pytest.mark.parametrize("value,error", [(float("nan"), ValueError), (float("inf"), ValueError), ({"a": {1, 2}}, TypeError)])
def test_canonical_json_refuses_what_json_cannot_hold(value, error):
    with pytest.raises(error):
        v.canonical_json(value)


def test_parse_json_refuses_a_duplicate_key():
    assert v.parse_json('{"a":1,"b":{"a":2}}') == {"a": 1, "b": {"a": 2}}
    with pytest.raises(ValueError, match="duplicate key 'a'"):
        v.parse_json('{"a":1,"a":2}')


def b64(data):
    return base64.b64encode(data).decode()


@pytest.mark.parametrize(
    "change",
    [{"payload": "not base64!"}, {"payload": b64(b"not json")}, {"payload": 7}, {"signatures": "none"}, {"payloadType": None}],
    ids=lambda c: f"{next(iter(c))}-{next(iter(c.values()))}",
)
def test_a_malformed_envelope_has_no_signers_and_no_payload(change):
    d = CANONICAL["dsse"]
    key = v.load_public_key(d["publicKeyPem"])
    env = dict(d["envelope"], **change)
    assert v.dsse_payload(d["envelope"]) == json.loads(d["payloadJson"])
    assert v.dsse_payload(env) is None
    assert v.dsse_signers(env, [key]) == []


def test_a_signature_that_is_not_base64_is_no_signer():
    d = CANONICAL["dsse"]
    env = dict(d["envelope"], signatures=[dict(s, sig="not base64!") for s in d["envelope"]["signatures"]])
    assert v.dsse_signers(env, [v.load_public_key(d["publicKeyPem"])]) == []


@pytest.mark.parametrize(
    "text,seconds",
    [
        ("2026-01-01T00:00:00Z", 1767225600.0),
        ("2026-01-01T01:30:00.5+01:30", 1767225600.5),
        ("2025-12-31T23:00:00-01:00", 1767225600.0),
        ("2026-01-01T24:00:00Z", None),
        ("2026-01-01T00:60:00Z", None),
        ("2026-01-01T00:00:00+24:00", None),
        ("2026-01-01T00:00:00+00:60", None),
        ("2026-01-01T00:00:00", None),
        (1767225600, None),
    ],
)
def test_parse_instant(text, seconds):
    assert v.parse_instant(text) == seconds


ENCRYPTED = {"$custody": "encrypted", "alg": "A256GCM", "keyid": "a" * 64, "iv": b64(bytes(12)), "ciphertext": b64(b"x"), "tag": b64(bytes(16)), "sha256": "b" * 64}


@pytest.mark.parametrize(
    "value,expected",
    [
        (ENCRYPTED, True),
        ({"$custody": "withheld", "sha256": "b" * 64}, True),
        ({**ENCRYPTED, "extra": 1}, False),
        ({k: x for k, x in ENCRYPTED.items() if k != "tag"}, False),
        ({**ENCRYPTED, "iv": 7}, False),
        ({**ENCRYPTED, "iv": "not base64!"}, False),
        ({**ENCRYPTED, "iv": b64(bytes(11))}, False),
        ({**ENCRYPTED, "alg": "A128GCM"}, False),
        ({"$custody": "disclosed", "sha256": "b" * 64}, False),
        ({"$custody": "withheld", "sha256": "B" * 64}, False),
        ("withheld", False),
    ],
)
def test_is_commitment(value, expected):
    assert v.is_commitment(value) is expected


def test_a_proof_longer_than_the_tree_is_refused():
    a, b = v.leaf_hash(b"a"), v.leaf_hash(b"b")
    root = v.node_hash(a, b)
    assert v.root_from_inclusion(0, 2, a, [b]) == root
    assert v.root_from_inclusion(0, 2, a, [b, b]) is None
    assert v.verify_consistency(1, 2, a, root, [b]) is True
    assert v.verify_consistency(1, 2, a, root, [b, b]) is False


def test_cli_refuses_a_provider_secret_variable_that_is_not_set(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SECRET_THAT_IS_NOT_SET", raising=False)
    with pytest.raises(SystemExit) as exit:
        v.main([str(tmp_path / "bundle.json"), "--issuer-key", str(tmp_path / "gateway.pub"), "--provider-secret-env", "stripe=SECRET_THAT_IS_NOT_SET"])
    assert exit.value.code == 2
    assert "--provider-secret-env stripe=SECRET_THAT_IS_NOT_SET: set the variable and pass PROVIDER=VAR" in capsys.readouterr().err


def test_cli_reports_a_file_that_is_not_a_bundle(tmp_path, capsys):
    (tmp_path / "bundle.json").write_text("{}")
    (tmp_path / "gateway.pub").write_text(RECEIPTS["keys"]["gateway"]["publicKeyPem"])
    assert v.main([str(tmp_path / "bundle.json"), "--issuer-key", str(tmp_path / "gateway.pub"), "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out == {"ok": False, "checks": [{"name": "receipt signature (issuer key)", "ok": False, "detail": "no trusted issuer key signed this envelope"}], "fields": []}


def test_array_index_keys_come_first_in_numeric_order():
    # The producer sorts keys, then JSON.stringify emits array-index keys (canonical integers below 2^32 - 1) first.
    assert v.canonical_json({"a": 1, "10": "ten", "2": "two", "01": 0, "4294967295": 0, "4294967294": 0}) == '{"2":"two","10":"ten","4294967294":0,"01":0,"4294967295":0,"a":1}'


def test_integers_beyond_2_53_print_as_the_double_javascript_reads():
    assert v.canonical_json(12345678901234567890) == "12345678901234567000"


def test_egress_addresses_match_the_typescript_list():
    # the same cases as packages/receipts/test/egress.test.ts: a leading zero is not an address, NAT64 carries its IPv4
    for a in ("127.0.0.1", "169.254.169.254", "192.0.0.192", "::1", "fd00::1", "::ffff:127.0.0.1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "010.0.0.1", "not-an-address"):
        assert v._internal_address(a), a
    for a in ("1.1.1.1", "172.32.0.1", "2606:4700::1111", "::ffff:1.1.1.1", "64:ff9b::808:808"):
        assert not v._internal_address(a), a
    assert v._address("010.0.0.1") is None
    assert v._address("::1") == v._address("0:0:0:0:0:0:0:1")
