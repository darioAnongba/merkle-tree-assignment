package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type Node struct {
	Left  *Node
	Right *Node
	Hash  []byte
}

func newNode(left, right *Node, data []byte) *Node {
	node := &Node{Left: left, Right: right}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.Hash = hash[:]
	} else {
		prevHashes := append(left.Hash, right.Hash...)
		hash := sha256.Sum256(prevHashes)
		node.Hash = hash[:]
	}

	return node
}

func (n *Node) generateProof(data []byte, path *[][]byte) bool {
	if n.Left == nil && n.Right == nil {
		hash := sha256.Sum256(data)
		return bytes.Equal(n.Hash, hash[:])
	}
	if n.Left.generateProof(data, path) {
		*path = append(*path, append([]byte{0x00}, n.Right.Hash...))
		return true
	}
	if n.Right.generateProof(data, path) {
		*path = append(*path, append([]byte{0x01}, n.Left.Hash...))
		return true
	}

	return false
}

func (n *Node) updateLeaf(oldData, newData []byte) bool {
	if n.Left == nil && n.Right == nil {
		oldHash := sha256.Sum256(oldData)
		if bytes.Equal(n.Hash, oldHash[:]) {
			newHash := sha256.Sum256(newData)
			n.Hash = newHash[:]
			return true
		}
		return false
	}

	if n.Left.updateLeaf(oldData, newData) || n.Right.updateLeaf(oldData, newData) {
		leftHash := n.Left.Hash
		rightHash := n.Right.Hash
		hash := sha256.Sum256(append(leftHash, rightHash...))
		n.Hash = hash[:]
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

	fmt.Printf("%sHash: %s\n", indent, hex.EncodeToString(n.Hash))

	if n.Left != nil || n.Right != nil {
		fmt.Printf("%sL:\n", indent)
		n.Left.print(level + 1)

		fmt.Printf("%sR:\n", indent)
		n.Right.print(level + 1)
	}
}

type MerkleTree struct {
	Root *Node
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

	return &MerkleTree{Root: nodes[0]}
}

func (mt *MerkleTree) GenerateProof(data []byte) ([][]byte, bool) {
	var path [][]byte
	found := mt.Root.generateProof(data, &path)

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
	return mt.Root.updateLeaf(oldData, newData)
}

func (mt *MerkleTree) Print() {
	mt.Root.print(0)
}
