package merkle_test

import (
	"encoding/hex"
	"merkle-tree-assignment/internal/merkle"
	"testing"
)

func TestNewSparseMerkleTree(t *testing.T) {
	tree := newSpareMerkleTree()

	expectedRootHash := "1d37988a0cf11b56560712ab69563f22ab126f17fb12e58fa107fb89cc275bdf"

	if hash := hex.EncodeToString(tree.RootHash()); hash != expectedRootHash {
		t.Errorf("Expected root hash %s, got %s", expectedRootHash, hash)
	}
}

func TestSparseMerkleTreeUpdate(t *testing.T) {
	tree := newSpareMerkleTree()

	tree.Update(0, []byte("newValue"))

	expectedRootHash := "e5cd9a4a1691f621e675b265d5408fb7b597ae858a29665102a3b0c37c712e36"

	if hash := hex.EncodeToString(tree.RootHash()); hash != expectedRootHash {
		t.Errorf("Expected root hash %s, got %s", expectedRootHash, hash)
	}
}

func TestGenerateSparseProof(t *testing.T) {
	tree := newSpareMerkleTree()

	leafIndex := 1

	proof := tree.GenerateProof(leafIndex)

	if len(proof) != merkle.TREE_DEPTH {
		t.Errorf("Expected proof to be of length %d, got %d", 256, len(proof))
	}
}

func TestVerifySparseProofLeft(t *testing.T) {
	tree := newSpareMerkleTree()

	leafIndex := 2

	proof := tree.GenerateProof(leafIndex)
	valid := merkle.VerifySparseProof([]byte("c"), leafIndex, proof, tree.RootHash())
	if !valid {
		t.Errorf("Expected proof to be valid")
	}
}

func TestVerifySparseProofRight(t *testing.T) {
	tree := newSpareMerkleTree()

	leafIndex := 1

	proof := tree.GenerateProof(leafIndex)
	valid := merkle.VerifySparseProof([]byte("b"), leafIndex, proof, tree.RootHash())
	if !valid {
		t.Errorf("Expected proof to be valid")
	}
}

func TestVerifySparseProofNonExistence(t *testing.T) {
	tree := newSpareMerkleTree()

	leafIndex := 12312 // Not initialized in the tree

	proof := tree.GenerateProof(leafIndex)
	valid := merkle.VerifySparseProofNonExistence(leafIndex, proof, tree.RootHash())
	if !valid {
		t.Errorf("Expected non-existence proof to be valid")
	}
}

func newSpareMerkleTree() *merkle.SparseMerkleTree {
	tree := merkle.NewSparseMerkleTree()

	tree.Update(0, []byte("a"))
	tree.Update(1, []byte("b"))
	tree.Update(2, []byte("c"))
	tree.Update(3, []byte("d"))

	return tree
}
