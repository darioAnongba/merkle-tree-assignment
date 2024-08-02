package merkle

import (
	"bytes"
	"crypto/sha256"
)

type SparseNode struct {
	hash  []byte
	left  *SparseNode
	right *SparseNode
}

type SparseMerkleTree struct {
	root *SparseNode
}

var defaultHash = sha256.Sum256([]byte(""))
var TREE_DEPTH = 256

func newSparseNode(hash []byte) *SparseNode {
	return &SparseNode{hash: hash}
}

func (n *SparseNode) updateNode(leafIndex int, dataHash []byte, depth int) *SparseNode {
	if depth == 0 {
		return newSparseNode(dataHash[:])
	}

	bit := (leafIndex >> (depth - 1)) & 1
	if bit == 0 {
		if n.left == nil {
			n.left = newSparseNode(defaultHash[:])
		}
		n.left = n.left.updateNode(leafIndex, dataHash, depth-1)
	} else {
		if n.right == nil {
			n.right = newSparseNode(defaultHash[:])
		}
		n.right = n.right.updateNode(leafIndex, dataHash, depth-1)
	}

	leftHash := defaultHash[:]
	if n.left != nil {
		leftHash = n.left.hash
	}
	rightHash := defaultHash[:]
	if n.right != nil {
		rightHash = n.right.hash
	}

	combinedHash := append(leftHash, rightHash...)
	hash := sha256.Sum256(combinedHash)
	n.hash = hash[:]

	return n
}

func (n *SparseNode) generateProof(leafIndex int, depth int) [][]byte {
	if depth == 0 {
		return [][]byte{}
	}

	bit := (leafIndex >> (depth - 1)) & 1
	var siblingHash []byte
	var proof [][]byte

	if bit == 0 {
		if n.right != nil {
			siblingHash = n.right.hash
		}
		if n.left != nil {
			proof = n.left.generateProof(leafIndex, depth-1)
		}
	} else {
		if n.left != nil {
			siblingHash = n.left.hash
		}
		if n.right != nil {
			proof = n.right.generateProof(leafIndex, depth-1)
		}
	}

	return append(proof, siblingHash)
}

func NewSparseMerkleTree() *SparseMerkleTree {
	return &SparseMerkleTree{
		root: newSparseNode(defaultHash[:]),
	}
}

func (smt *SparseMerkleTree) RootHash() []byte {
	return smt.root.hash
}

func (smt *SparseMerkleTree) Update(leafIndex int, data []byte) {
	hash := sha256.Sum256(data)
	smt.root = smt.root.updateNode(leafIndex, hash[:], TREE_DEPTH)
}

func (smt *SparseMerkleTree) GenerateProof(leafIndex int) [][]byte {
	return smt.root.generateProof(leafIndex, TREE_DEPTH)
}

func VerifySparseProof(data []byte, leafIndex int, proof [][]byte, rootHash []byte) bool {
	hash := sha256.Sum256(data)
	computedHash := hash[:]

	for depth := 0; depth < TREE_DEPTH; depth++ {
		bit := (leafIndex >> depth) & 1
		siblingHash := proof[depth]

		if siblingHash == nil {
			siblingHash = defaultHash[:]
		}

		if bit == 0 {
			computedHash = computeParentHash(computedHash, siblingHash)
		} else {
			computedHash = computeParentHash(siblingHash, computedHash)
		}
	}

	return bytes.Equal(computedHash, rootHash)
}

func VerifySparseProofNonExistence(leafIndex int, proof [][]byte, rootHash []byte) bool {
	computedHash := defaultHash[:]
	startDepth := TREE_DEPTH - len(proof)

	for i, siblingHash := range proof {
		bit := (leafIndex >> (startDepth + i)) & 1

		if siblingHash == nil {
			siblingHash = defaultHash[:]
		}

		if bit == 0 {
			computedHash = computeParentHash(computedHash, siblingHash)
		} else {
			computedHash = computeParentHash(siblingHash, computedHash)
		}
	}

	return bytes.Equal(computedHash, rootHash)
}

func computeParentHash(left, right []byte) []byte {
	combinedHash := append(left, right...)
	hash := sha256.Sum256(combinedHash)
	return hash[:]
}
