# Merkle Tree Assignment

This project implements a Merkle Trees in Go, generating a Merkle proof, verifying a Merkle proof, and updating a leaf node.

## Folder Structure

```
merkle-tree-assignment/
├── cmd/
│   └── merkle-tree/
│       └── main.go
├── internal/
│   └── merkle/
│       ├── merkle_tree.go
│       ├── merkle_sum_tree.go
│       └── sparse_merkle_tree.go
├── tests/
│   ├── merkle_tree_test.go
│   ├── merkle_sum_tree_test.go
│   └── sparse_merkle_tree_test.go
├── go.mod
└── go.sum
```

## Usage

To run the main program, use:

```sh
make tidy
make run
```

## Choice of Hash function

For the implementation of the Merkle tree in this project, the **SHA-256** hash function from the Go `crypto/sha256` package was chosen.

### 1. Security

SHA-256 provides 256-bit security, which far exceeds the 128-bit security requirement mentioned in the assignment. A hash function of strictly 128-bit security such as MD5 is not recommended for due to known vulnerabilities.

### 2. Properties

SHA-256 has the following cryptographic properties that are essential for a secure Merkle tree:

- **Collision resistance**: It is computationally infeasible to find two different inputs that hash to the same output.
- **Preimage resistance**: Given a hash value, it is computationally infeasible to find an input that hashes to that value.
- **Second Preimage resistance**: Given an input and its hash, it is computationally infeasible to find a different input with the same hash.

These properties ensure the integrity and security of the data within the Merkle tree.

## Merkle Trees

### Merkle Tree

Minimal Merkle tree implementation. Useful to verify the integrity of data.

### Merkle Sum Tree

Merkle sum trees are a type of merkle tree that contains numeric values at each leaf, and each node also carries the sum of the values below it. At the root of the Merkle sum tree is the sum of total values in the tree. Merkle Sum trees allow efficient verification of conservation (non-inflation) by committing to quantities associated with leaves.

- Useful for verifying aggregated data
- Each node contains both a hash and a sum of the values of its subtree

Implementation considerations:

- Maintain sums at each node
- Include sums in proof and verification processes

### Sparse Merkle Tree

A Sparse (meaning ‘thinly scattered’) Merkle tree is a data structure in which it can be proven that specific data doesn't exist within a merkle tree. An SMT is an authenticated key-value store, meaning that the key, or location, of a leaf and the content of the leaf are bound to each other.

- Efficient proofs for non-membership
- Typically used to represent large state spaces

Implementation considerations:

- Use a default value for non-existent leaves
- Maintain only the non-default (non-empty) leaves in memory
