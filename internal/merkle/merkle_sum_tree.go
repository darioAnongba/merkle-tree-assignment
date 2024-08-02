package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type SumNode struct {
	Hash  []byte
	Sum   int
	Left  *SumNode
	Right *SumNode
}

func newSumNode(left, right *SumNode, data []byte, value int) *SumNode {
	node := &SumNode{Left: left, Right: right}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.Hash = hash[:]
		node.Sum = value
	} else {
		combinedHash := append(left.Hash, right.Hash...)
		hash := sha256.Sum256(combinedHash)
		node.Hash = hash[:]
		node.Sum = left.Sum + right.Sum
	}

	return node
}

func (n *SumNode) generateProof(data []byte, path *[][]byte, sums *[]int) bool {
	if n.Left == nil && n.Right == nil {
		hash := sha256.Sum256(data)
		return bytes.Equal(n.Hash, hash[:])
	}
	if n.Left != nil && n.Left.generateProof(data, path, sums) {
		*path = append(*path, append([]byte{0x00}, n.Right.Hash...))
		*sums = append(*sums, n.Right.Sum)
		return true
	}
	if n.Right != nil && n.Right.generateProof(data, path, sums) {
		*path = append(*path, append([]byte{0x01}, n.Left.Hash...))
		*sums = append(*sums, n.Left.Sum)
		return true
	}

	return false
}

func (n *SumNode) updateHashAndSum() {
	if n.Left == nil && n.Right == nil {
		return
	}
	combinedHash := append(n.Left.Hash, n.Right.Hash...)
	hash := sha256.Sum256(combinedHash)
	n.Hash = hash[:]
	n.Sum = n.Left.Sum + n.Right.Sum
}

func (n *SumNode) updateLeaf(oldData []byte, newData []byte, newValue int) bool {
	if n.Left == nil && n.Right == nil {
		hash := sha256.Sum256(oldData)
		if bytes.Equal(n.Hash, hash[:]) {
			newHash := sha256.Sum256(newData)
			n.Hash = newHash[:]
			n.Sum = newValue
			return true
		}
		return false
	}
	if n.Left != nil && n.Left.updateLeaf(oldData, newData, newValue) {
		n.updateHashAndSum()
		return true
	}
	if n.Right != nil && n.Right.updateLeaf(oldData, newData, newValue) {
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

	fmt.Printf("%sHash: %s\n", indent, hex.EncodeToString(n.Hash))
	fmt.Printf("%sSum: %d\n", indent, n.Sum)

	if n.Left != nil || n.Right != nil {
		fmt.Printf("%sL:\n", indent)
		n.Left.print(level + 1)

		fmt.Printf("%sR:\n", indent)
		n.Right.print(level + 1)
	}
}

type MerkleSumTree struct {
	Root *SumNode
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

	tree := &MerkleSumTree{Root: nodes[0]}
	return tree
}

func (mst *MerkleSumTree) GenerateProof(data []byte) ([][]byte, []int, bool) {
	var path [][]byte
	var sums []int
	found := mst.Root.generateProof(data, &path, &sums)

	return path, sums, found
}

func (mst *MerkleSumTree) Update(oldData []byte, newData []byte, newValue int) bool {
	return mst.Root.updateLeaf(oldData, newData, newValue)
}
func (mst *MerkleSumTree) Print() {
	mst.Root.print(0)
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
