package main

import (
	"fmt"
	"merkle-tree-assignment/internal/merkle"
)

func main() {
	data := [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
	}
	values := []int{1, 2, 3, 4}

	tree := merkle.NewMerkleTree(data)
	fmt.Println("------- Merkle Tree")

	proof, found := tree.GenerateProof([]byte("a"))
	if found {
		fmt.Printf("Proof for 'a': %x\n", proof)
	}

	valid := merkle.VerifyProof([]byte("a"), proof, tree.RootHash())
	fmt.Printf("Proof valid: %v\n", valid)

	updated := tree.Update([]byte("a"), []byte("e"))
	if updated {
		fmt.Printf("Updated root hash: %x\n", tree.RootHash())
	}

	proof, found = tree.GenerateProof([]byte("e"))
	if found {
		fmt.Printf("Proof for 'e': %x\n", proof)
	}

	valid = merkle.VerifyProof([]byte("e"), proof, tree.RootHash())
	fmt.Printf("Proof valid: %v\n", valid)

	sumTtree := merkle.NewMerkleSumTree(data, values)
	fmt.Println("------- Merke Sum Tree")

	proof, sums, found := sumTtree.GenerateProof([]byte("a"))
	if found {
		fmt.Printf("Proof for 'a': %x\n", proof)
		fmt.Printf("Sums for 'a': %v\n", sums)
	}

	sumTreeValid := merkle.VerifySumProof([]byte("a"), values[0], proof, sums, sumTtree.RootHash(), sumTtree.RootSum())
	fmt.Printf("Proof valid: %v\n", sumTreeValid)

	updated = sumTtree.Update([]byte("a"), []byte("e"), 10)
	if updated {
		fmt.Printf("Updated root hash: %x\n", tree.RootHash())
	}

	proof, sums, found = sumTtree.GenerateProof([]byte("e"))
	if found {
		fmt.Printf("Proof for 'e': %x\n", proof)
		fmt.Printf("Sums for 'e': %v\n", sums)
	}

	valid = merkle.VerifySumProof([]byte("e"), 10, proof, sums, sumTtree.RootHash(), sumTtree.RootSum())
	fmt.Printf("Proof valid: %v\n", valid)

	sparseTree := merkle.NewSparseMerkleTree()
	fmt.Println("------- Sparse Merkle Tree")

	sparseTree.Update(0, []byte("a"))
	sparseTree.Update(1, []byte("b"))
	sparseTree.Update(2, []byte("c"))
	sparseTree.Update(3, []byte("d"))

	leafIndex := 3
	proof = sparseTree.GenerateProof(leafIndex)
	fmt.Printf("Proof for leaf index %d: %x\n", leafIndex, proof)

	valid = merkle.VerifySparseProof([]byte("d"), leafIndex, proof, sparseTree.RootHash())
	fmt.Printf("Proof valid: %v\n", valid)

	leafIndex = 32323
	proof = sparseTree.GenerateProof(leafIndex)
	fmt.Printf("Proof for leaf index %d: %x\n", leafIndex, proof)

	valid = merkle.VerifySparseProofNonExistence(leafIndex, proof, sparseTree.RootHash())
	fmt.Printf("Proof of non-existence valid: %v\n", valid)

}
