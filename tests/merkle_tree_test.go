package merkle_test

import (
	"encoding/hex"
	"merkle-tree-assignment/internal/merkle"
	"testing"
)

func TestNewMerkleTree(t *testing.T) {
	tree := newMerkleTree()
	tree.Print()

	if tree.Root == nil {
		t.Errorf("Expected root to be non-nil")
	}
}

func TestMerkleTreeRootHash(t *testing.T) {
	tree := newMerkleTree()

	expectedRootHash := "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7"

	if hash := hex.EncodeToString(tree.Root.Hash); hash != expectedRootHash {
		t.Errorf("Expected root hash %s, got %s", expectedRootHash, hash)
	}
}

func TestGenerateProof(t *testing.T) {
	tree := newMerkleTree()
	proof, found := tree.GenerateProof([]byte("a"))

	if !found {
		t.Errorf("Expected to find proof for 'a'")
	}

	if len(proof) == 0 {
		t.Errorf("Expected non-empty proof")
	}
}

func TestVerifyProofLeft(t *testing.T) {
	tree := newMerkleTree()

	proof, found := tree.GenerateProof([]byte("a"))
	if !found {
		t.Fatalf("Expected to find proof for 'a'")
	}

	valid := merkle.VerifyProof([]byte("a"), proof, tree.Root.Hash)
	if !valid {
		t.Errorf("Expected proof to be valid")
	}

	valid = merkle.VerifyProof([]byte("unknown"), proof, tree.Root.Hash)
	if valid {
		t.Errorf("Expected proof for unknown data to be invalid")
	}
}

func TestVerifyProofRight(t *testing.T) {
	tree := newMerkleTree()

	data := []byte("d")
	proof, found := tree.GenerateProof(data)
	if !found {
		t.Fatalf("Expected to find proof for 'd'")
	}

	valid := merkle.VerifyProof(data, proof, tree.Root.Hash)
	if !valid {
		t.Errorf("Expected proof to be valid")
	}
}

func TestUpdate(t *testing.T) {
	tree := newMerkleTree()

	updated := tree.Update([]byte("a"), []byte("e"))
	if !updated {
		t.Errorf("Expected leaf update to succeed")
	}

	proof, found := tree.GenerateProof([]byte("e"))
	if !found {
		t.Errorf("Expected to find proof for 'e'")
	}

	valid := merkle.VerifyProof([]byte("e"), proof, tree.Root.Hash)
	if !valid {
		t.Errorf("Expected proof for updated leaf to be valid")
	}
}

func newMerkleTree() *merkle.MerkleTree {
	data := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
	}

	return merkle.NewMerkleTree(data)
}
