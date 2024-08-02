package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Node struct {
	left  *Node
	right *Node
	hash  []byte
}

func newNode(left, right *Node, data []byte) *Node {
	node := &Node{left: left, right: right}

	// If the node is a leaf, hash the data, otherwise hash the concatenation of the left and right children's hashes
	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.hash = hash[:]
	} else {
		prevHashes := append(left.hash, right.hash...)
		hash := sha256.Sum256(prevHashes)
		node.hash = hash[:]
	}

	return node
}

// generateProof generates a proof for the given data in the Merkle tree.
// It recursively traverses the tree to find the data and constructs the proof path.
// The proof path is stored in the provided path slice, where each element represents a node in the path.
// The proof path is constructed by appending the hash of the sibling node and a flag indicating whether the sibling is on the left or right.
// Returns true if the data is found in the tree and the proof is generated, false otherwise.
func (n *Node) generateProof(data []byte, path *[][]byte) bool {
	if n.left == nil && n.right == nil {
		hash := sha256.Sum256(data)
		return bytes.Equal(n.hash, hash[:])
	}
	if n.left.generateProof(data, path) {
		*path = append(*path, append([]byte{0x00}, n.right.hash...))
		return true
	}
	if n.right.generateProof(data, path) {
		*path = append(*path, append([]byte{0x01}, n.left.hash...))
		return true
	}

	return false
}

// updateLeaf updates the hash of a leaf node if the old data matches the current hash.
// It traverses the tree to find the leaf node with the matching old data, updates its hash with the new data,
// and then updates the hashes of all its ancestors.
// Returns true if the leaf node is found and updated, false otherwise.
func (n *Node) updateLeaf(oldHash, newHash []byte) bool {
	if n.left == nil && n.right == nil {
		if bytes.Equal(n.hash, oldHash[:]) {
			n.hash = newHash[:]
			return true
		}
		return false
	}

	if n.left.updateLeaf(oldHash, newHash) || n.right.updateLeaf(oldHash, newHash) {
		leftHash := n.left.hash
		rightHash := n.right.hash
		hash := sha256.Sum256(append(leftHash, rightHash...))
		n.hash = hash[:]
		return true
	}

	return false
}

func (n *Node) print(level int) {
	indent := ""
	for i := 0; i < level; i++ {
		indent += "    "
	}

	fmt.Printf("%sHash: %s\n", indent, hex.EncodeToString(n.hash))

	if n.left != nil || n.right != nil {
		fmt.Printf("%sL:\n", indent)
		n.left.print(level + 1)

		fmt.Printf("%sR:\n", indent)
		n.right.print(level + 1)
	}
}

type MerkleTree struct {
	root *Node
}

func NewMerkleTree(data [][]byte) *MerkleTree {
	var nodes []*Node

	for _, datum := range data {
		nodes = append(nodes, newNode(nil, nil, datum))
	}

	for len(nodes) > 1 {
		var newLevel []*Node
		for i := 0; i < len(nodes); i += 2 {
			if i+1 == len(nodes) {
				newLevel = append(newLevel, nodes[i])
			} else {
				newLevel = append(newLevel, newNode(nodes[i], nodes[i+1], nil))
			}
		}
		nodes = newLevel
	}

	return &MerkleTree{root: nodes[0]}
}

func (mt *MerkleTree) RootHash() []byte {
	return mt.root.hash
}

func (mt *MerkleTree) GenerateProof(data []byte) ([][]byte, bool) {
	var path [][]byte
	found := mt.root.generateProof(data, &path)

	return path, found
}

func VerifyProof(data []byte, proof [][]byte, rootHash []byte) bool {
	hash := sha256.Sum256(data)
	computedHash := hash[:]

	for _, p := range proof {
		if p[0] == 0x00 {
			computedHash = append(computedHash, p[1:]...)
		} else {
			computedHash = append(p[1:], computedHash...)
		}
		hash := sha256.Sum256(computedHash)
		computedHash = hash[:]
	}

	return bytes.Equal(computedHash, rootHash)
}

func (mt *MerkleTree) Update(oldData, newData []byte) bool {
	oldHash := sha256.Sum256(oldData)
	newHash := sha256.Sum256(newData)
	return mt.root.updateLeaf(oldHash[:], newHash[:])
}

func (mt *MerkleTree) Print() {
	mt.root.print(0)
}
