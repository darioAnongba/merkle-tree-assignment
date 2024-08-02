package merkle_test

import (
	"encoding/hex"
	"merkle-tree-assignment/internal/merkle"
	"testing"
)

func TestNewMerkleSumTree(t *testing.T) {
	tree := newMerkleSumTree()

	expectedRootHash := "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7"

	if hash := hex.EncodeToString(tree.RootHash()); hash != expectedRootHash {
		t.Errorf("Expected root hash %s, got %s", expectedRootHash, hash)
	}
}

func TestGenerateSumProof(t *testing.T) {
	tree := newMerkleSumTree()

	proof, sums, found := tree.GenerateProof([]byte("a"))
	if !found {
		t.Errorf("Expected to find proof for 'a'")
	}
	if len(proof) == 0 {
		t.Errorf("Expected non-empty proof")
	}
	if len(sums) == 0 {
		t.Errorf("Expected non-empty sums")
	}
}

func TestVerifySumProofLeftLeaf(t *testing.T) {
	tree := newMerkleSumTree()

	data := []byte("a")

	proof, sums, found := tree.GenerateProof(data)
	if !found {
		t.Fatalf("Expected to find proof for 'a'")
	}

	valid := merkle.VerifySumProof(data, 1, proof, sums, tree.RootHash(), tree.RootSum())
	if !valid {
		t.Errorf("Expected proof to be valid")
	}

	valid = merkle.VerifySumProof([]byte("unknown"), 1, proof, sums, tree.RootHash(), tree.RootSum())
	if valid {
		t.Errorf("Expected proof for unknown data to be invalid")
	}

	valid = merkle.VerifySumProof(data, 667, proof, sums, tree.RootHash(), tree.RootSum())
	if valid {
		t.Errorf("Expected proof for incorrect expected value to be invalid")
	}
}

func TestVerifySumProofRightLeaf(t *testing.T) {
	tree := newMerkleSumTree()

	data := []byte("d")

	proof, sums, found := tree.GenerateProof(data)
	if !found {
		t.Fatalf("Expected to find proof for 'c'")
	}

	valid := merkle.VerifySumProof(data, 4, proof, sums, tree.RootHash(), tree.RootSum())
	if !valid {
		t.Errorf("Expected proof to be valid")
	}
}

func TestUpdateSum(t *testing.T) {
	tree := newMerkleSumTree()

	updated := tree.Update([]byte("a"), []byte("e"), 10)
	if !updated {
		t.Errorf("Expected leaf update to succeed")
	}

	proof, sums, found := tree.GenerateProof([]byte("e"))
	if !found {
		t.Errorf("Expected to find proof for 'e'")
	}

	valid := merkle.VerifySumProof([]byte("e"), 10, proof, sums, tree.RootHash(), tree.RootSum())
	if !valid {
		t.Errorf("Expected proof for updated leaf to be valid")
	}
}

func newMerkleSumTree() *merkle.MerkleSumTree {
	data := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
	}
	values := []int{1, 2, 3, 4}

	return merkle.NewMerkleSumTree(data, values)
}
