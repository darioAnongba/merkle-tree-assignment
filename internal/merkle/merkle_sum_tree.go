package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type SumNode struct {
	hash  []byte
	sum   int
	left  *SumNode
	right *SumNode
}

func newSumNode(left, right *SumNode, data []byte, value int) *SumNode {
	node := &SumNode{left: left, right: right}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.hash = hash[:]
		node.sum = value
	} else {
		combinedHash := append(left.hash, right.hash...)
		hash := sha256.Sum256(combinedHash)
		node.hash = hash[:]
		node.sum = left.sum + right.sum
	}

	return node
}

func (n *SumNode) generateProof(data []byte, path *[][]byte, sums *[]int) bool {
	if n.left == nil && n.right == nil {
		hash := sha256.Sum256(data)
		return bytes.Equal(n.hash, hash[:])
	}
	if n.left != nil && n.left.generateProof(data, path, sums) {
		*path = append(*path, append([]byte{0x00}, n.right.hash...))
		*sums = append(*sums, n.right.sum)
		return true
	}
	if n.right != nil && n.right.generateProof(data, path, sums) {
		*path = append(*path, append([]byte{0x01}, n.left.hash...))
		*sums = append(*sums, n.left.sum)
		return true
	}

	return false
}

func (n *SumNode) updateHashAndSum() {
	if n.left == nil && n.right == nil {
		return
	}
	combinedHash := append(n.left.hash, n.right.hash...)
	hash := sha256.Sum256(combinedHash)
	n.hash = hash[:]
	n.sum = n.left.sum + n.right.sum
}

func (n *SumNode) updateLeaf(oldData []byte, newData []byte, newValue int) bool {
	if n.left == nil && n.right == nil {
		hash := sha256.Sum256(oldData)
		if bytes.Equal(n.hash, hash[:]) {
			newHash := sha256.Sum256(newData)
			n.hash = newHash[:]
			n.sum = newValue
			return true
		}
		return false
	}
	if n.left != nil && n.left.updateLeaf(oldData, newData, newValue) {
		n.updateHashAndSum()
		return true
	}
	if n.right != nil && n.right.updateLeaf(oldData, newData, newValue) {
		n.updateHashAndSum()
		return true
	}
	return false
}

func (n *SumNode) print(level int) {
	if n == nil {
		return
	}

	indent := ""
	for i := 0; i < level; i++ {
		indent += "    "
	}

	fmt.Printf("%sHash: %s\n", indent, hex.EncodeToString(n.hash))
	fmt.Printf("%sSum: %d\n", indent, n.sum)

	if n.left != nil || n.right != nil {
		fmt.Printf("%sL:\n", indent)
		n.left.print(level + 1)

		fmt.Printf("%sR:\n", indent)
		n.right.print(level + 1)
	}
}

type MerkleSumTree struct {
	root *SumNode
}

func NewMerkleSumTree(data [][]byte, values []int) *MerkleSumTree {
	var nodes []*SumNode

	for i, datum := range data {
		nodes = append(nodes, newSumNode(nil, nil, datum, values[i]))
	}

	for len(nodes) > 1 {
		var newLevel []*SumNode
		for i := 0; i < len(nodes); i += 2 {
			if i+1 == len(nodes) {
				newLevel = append(newLevel, nodes[i])
			} else {
				newLevel = append(newLevel, newSumNode(nodes[i], nodes[i+1], nil, 0))
			}
		}
		nodes = newLevel
	}

	tree := &MerkleSumTree{root: nodes[0]}
	return tree
}

func (mst *MerkleSumTree) RootHash() []byte {
	return mst.root.hash
}

func (mst *MerkleSumTree) RootSum() int {
	return mst.root.sum
}

func (mst *MerkleSumTree) GenerateProof(data []byte) ([][]byte, []int, bool) {
	var path [][]byte
	var sums []int
	found := mst.root.generateProof(data, &path, &sums)

	return path, sums, found
}

func (mst *MerkleSumTree) Update(oldData []byte, newData []byte, newValue int) bool {
	return mst.root.updateLeaf(oldData, newData, newValue)
}
func (mst *MerkleSumTree) Print() {
	mst.root.print(0)
}

func VerifySumProof(data []byte, expectedValue int, proof [][]byte, sums []int, rootHash []byte, rootSum int) bool {
	hash := sha256.Sum256(data)
	computedHash := hash[:]
	computedSum := expectedValue

	for i, p := range proof {
		if p[0] == 0x00 {
			computedHash = append(computedHash, p[1:]...)
		} else {
			computedHash = append(p[1:], computedHash...)
		}
		hash := sha256.Sum256(computedHash)
		computedHash = hash[:]
		computedSum += sums[i]
	}

	return bytes.Equal(computedHash, rootHash) && computedSum == rootSum
}
