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

func (n *Node) updateLeaf(oldData, newData []byte) bool {
	if n.left == nil && n.right == nil {
		oldHash := sha256.Sum256(oldData)
		if bytes.Equal(n.hash, oldHash[:]) {
			newHash := sha256.Sum256(newData)
			n.hash = newHash[:]
			return true
		}
		return false
	}

	if n.left.updateLeaf(oldData, newData) || n.right.updateLeaf(oldData, newData) {
		leftHash := n.left.hash
		rightHash := n.right.hash
		hash := sha256.Sum256(append(leftHash, rightHash...))
		n.hash = hash[:]
		return true
	}

	return false
}

func (n *Node) print(level int) {
	if n == nil {
		return
	}

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
	return mt.root.updateLeaf(oldData, newData)
}

func (mt *MerkleTree) Print() {
	mt.root.print(0)
}
