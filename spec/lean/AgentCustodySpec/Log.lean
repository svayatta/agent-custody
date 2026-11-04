/- The Merkle model of `Merkle.lean` with the log's real hashes: SHA-256 with the RFC 9162 domain separation. -/
import AgentCustodySpec.Sha256
import AgentCustodySpec.Merkle
namespace AgentCustodySpec.Log
open AgentCustodySpec

/-- `leafHash` of `log.ts`: sha256(0x00 || data). -/
def leafHash (data : ByteArray) : ByteArray := Sha256.hash (ByteArray.mk #[0x00] ++ data)
/-- `nodeHash` of `log.ts`: sha256(0x01 || left || right). -/
def nodeHash (l r : ByteArray) : ByteArray := Sha256.hash (ByteArray.mk #[0x01] ++ l ++ r)
/-- The root of the empty tree: sha256 of nothing. -/
def emptyRoot : ByteArray := Sha256.hash ByteArray.empty

def root (leafHashes : List ByteArray) : ByteArray := Merkle.mth nodeHash emptyRoot leafHashes
def path (m : Nat) (leafHashes : List ByteArray) : List ByteArray := Merkle.path nodeHash emptyRoot m leafHashes

instance : DecidableEq ByteArray := fun a b =>
  if h : a.data = b.data then isTrue (by cases a; cases b; simp_all) else isFalse (by intro e; cases e; exact h rfl)

def verifyInclusion (leaf : ByteArray) (i n : Nat) (proof : List ByteArray) (root : ByteArray) : Bool :=
  Merkle.verifyInclusion nodeHash leaf i n proof root

def consistencyProof (l : List ByteArray) (oldSize newSize : Nat) : List ByteArray :=
  Merkle.consistencyProof nodeHash emptyRoot l oldSize newSize

def verifyConsistency (oldSize : Nat) (oldRoot : ByteArray) (newSize : Nat) (newRoot : ByteArray)
    (proof : List ByteArray) : Bool :=
  Merkle.verifyConsistency nodeHash oldSize oldRoot newSize newRoot proof

end AgentCustodySpec.Log
