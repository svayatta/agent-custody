/-
Runs the Lean model against the conformance vectors that the TypeScript and Python verifiers also pass. A mismatch
means the model, or a verifier, disagrees with the format: the run prints it and exits 1.

  lake exe vectors [path to packages/receipts/vectors]
-/
import Lean.Data.Json
import AgentCustodySpec
open Lean AgentCustodySpec

abbrev Check := StateT (Nat × Nat) IO

def expect (what : String) (ok : Bool) : Check Unit := do
  let (pass, fail) ← get
  if ok then set (pass + 1, fail) else do
    IO.eprintln s!"FAIL {what}"
    set (pass, fail + 1)

def field {α} [FromJson α] (j : Json) (k : String) : IO α :=
  match j.getObjValAs? α k with
  | .ok v => pure v
  | .error e => throw (IO.userError s!"vector field {k}: {e}")

def hex (s : String) : IO ByteArray :=
  match Hex.decode s with
  | some b => pure b
  | none => throw (IO.userError s!"not lowercase hex: {s}")

def sha256Examples : Check Unit := do
  -- FIPS 180-4 examples: "abc", the empty message, and the two-block message.
  expect "sha256(\"abc\")" <|
    Hex.encode (Sha256.hash "abc".toUTF8) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  expect "sha256(\"\")" <|
    Hex.encode (Sha256.hash ByteArray.empty) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  expect "sha256(448-bit message)" <|
    Hex.encode (Sha256.hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8) ==
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

def merkleVectors (j : Json) : Check Unit := do
  let leaves : Array String ← field j "leaves"
  let leafHashes : Array String ← field j "leafHashes"
  let roots : Array String ← field j "roots"
  let hs := leaves.toList.map (fun l => Log.leafHash l.toUTF8)
  for (l, h, want) in leaves.toList.zip (hs.zip leafHashes.toList) do
    expect s!"leafHash({l})" (Hex.encode h == want)
  for n in [0:roots.size] do
    expect s!"root of size {n}" (Hex.encode (Log.root (hs.take n)) == roots[n]!)
  let cases : Array Json ← field j "inclusion"
  for c in cases do
    let i : Nat ← field c "leafIndex"
    let n : Nat ← field c "treeSize"
    let proof ← (← field c "hashes" : Array String).toList.mapM fun s => do return (← hex s)
    let root ← hex (← field c "root")
    let expected : Bool ← field c "expected"
    let leaf := hs.getD i ByteArray.empty
    expect s!"inclusion leafIndex {i} treeSize {n}" (Log.verifyInclusion leaf i n proof root == expected)
    if expected then
      expect s!"path({i}) of size {n} is the vector's proof" (Log.path i (hs.take n) == proof)

def consistencyVectors (j : Json) : Check Unit := do
  let leaves : Array String ← field j "leaves"
  let hs := leaves.toList.map (fun l => Log.leafHash l.toUTF8)
  let cases : Array Json ← field j "consistency"
  for c in cases do
    let m : Nat ← field c "oldSize"
    let n : Nat ← field c "newSize"
    let oldRoot ← hex (← field c "oldRoot")
    let newRoot ← hex (← field c "newRoot")
    let proof ← (← field c "hashes" : Array String).toList.mapM fun s => do return (← hex s)
    let expected : Bool ← field c "expected"
    expect s!"consistency {m} -> {n}" (Log.verifyConsistency m oldRoot n newRoot proof == expected)
    if expected then
      expect s!"consistencyProof {m} -> {n} is the vector's proof" (Log.consistencyProof hs m n == proof)

def main (args : List String) : IO UInt32 := do
  let dir := args.headD "../../packages/receipts/vectors"
  let merkle ← match Json.parse (← IO.FS.readFile s!"{dir}/merkle.json") with
    | .ok j => pure j
    | .error e => throw (IO.userError s!"merkle.json: {e}")
  let ((), (pass, fail)) ← (do sha256Examples; merkleVectors merkle; consistencyVectors merkle : Check Unit).run (0, 0)
  IO.println s!"{pass} passed, {fail} failed"
  return if fail == 0 then 0 else 1
