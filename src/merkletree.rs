
#![allow(dead_code)]
#![allow(unused_variables)]

use sha2::Digest;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

/// Each element in Merkle Tree is a node
#[derive(Debug, Clone)]
pub struct Node {
    /// each Node has a hash value:
    /// - which is either hash of leaf(when left and right are `None`)
    /// - or hash of its concatenated children from left and right
    value: Hash,
    /// a Node in Merkle Tree might have a children node to the left
    left: Option<Box<Node>>,
    /// a Node in Merkle Tree might have a children node to the right
    right: Option<Box<Node>>,
}

/// The Merkle Tree is really just the top level root that will grow to the left or right
pub struct MerkleTree {
    /// Merkle Tree starts from a top level root Node
    root: Node,
}

/// Which side to put Hash on when concatenating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatenating
    hashes: Vec<(HashDirection, Hash)>,
}

impl MerkleTree {
    /// Gets root hash for this tree
    pub fn root(&self) -> Hash {
        self.root.value.clone()
    }

    /// Constructs a Merkle tree from given input data
    pub fn construct(input: &[Data]) -> MerkleTree {
        let mut leaves = input
            .iter()
            .map(hash_data)
            .map(|hash| {
                Node {
                    value: hash,
                    left: None,
                    right: None,
                }
            })
            .collect::<Vec<Node>>();


        while leaves.len() > 1{
            let mut new_nodes = Vec::with_capacity(leaves.len() / 2);

            for chunk in leaves.chunks_exact(2) {
                let left = chunk[0].clone();
                let right = chunk[1].clone();
                new_nodes.push(Node{
                    value: hash_concat(&left.value, &right.value),
                    left: Some(Box::new(left)),
                    right: Some(Box::new(right))
                });
            }

            if leaves.len() % 2 == 1 {
                new_nodes.push( Node{
                    value: leaves.last().unwrap().value.clone(),
                    left: None,
                    right: None
                });
            }
            leaves = new_nodes
        }

        MerkleTree{
            root: leaves.pop().unwrap()
        }
    }

    /// Verifies that the given input data produces the given root hash
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        let mt = MerkleTree::construct(input);
        let hash: Vec<u8> = mt.root();
        hash.eq(root_hash)
    }

    /// Verifies that the given data and proof_path correctly produce the given root_hash
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let mut hashed_data = hash_data(data);
        for (hash_direction, hash) in &proof.hashes {
            match hash_direction {
                HashDirection::Left => { hashed_data = hash_concat(&hash, &hashed_data) },
                HashDirection::Right => { hashed_data = hash_concat(&hashed_data, &hash) }
            }
        };
        hashed_data.eq(root_hash)
    }

    /// Returns a list of hashes that can be used to prove that the given data is in this tree
    pub fn prove(&self, data: &Data) -> Option<Proof> {
        // todo!("Exercise 3")
        let leaf = hash_data(data);
        let proofs = traverse_and_collect_proofs(&self.root, &leaf);
        proofs
    }
}

/// recursive function to traverse the Merkle Tree through its children Nodes
/// if Leaf is found, it returns a `Proof` which contains a list of hash proofs
/// if Leaf is not found in Merkle Tree, then it returns `None` proofs
fn traverse_and_collect_proofs<'a>(node: &'a Node, searched_leaf: &'a Hash) -> Option<Proof> {
    if node.left.is_some() {
        // going deeper to the left Node and searching for Leaf
        let proofs = traverse_and_collect_proofs(&node.left.as_ref().unwrap(), searched_leaf);
        if proofs.is_some() {
            // collecting proofs during bubbling up
            let mut proof = proofs.unwrap();
            let value: &Hash = node.right.as_ref().unwrap().value.as_ref();
            proof.hashes.push((HashDirection::Right, value.clone()));
            return Some(proof)
        }
    }
    if node.right.is_some() {
        // going deeper to the right Node and searching for Leaf
        let proofs = traverse_and_collect_proofs(&node.right.as_ref().unwrap(), searched_leaf);
        if proofs.is_some() {
            // collecting proofs during bubbling up
            let mut proof = proofs.unwrap();
            let value: &Hash = node.left.as_ref().unwrap().value.as_ref();
            proof.hashes.push((HashDirection::Left, value.clone()));
            return Some(proof)
        }
    }
    if node.left.is_none() && node.right.is_none() && node.value.eq(searched_leaf) {
        // we just found the Leaf in Merkle tree, lets start to bubble up collecting proofs on the way up
        return Some(Proof{
            hashes: vec![]
        })
    }
    // we just traversed entire Merkle tree without finding Leaf, therefore return None `Proof`
    None
}

/// hashing the input Leafs
fn hash_data(data: &Data) -> Hash {
    sha2::Sha256::digest(data).to_vec()
}

/// concatenating left and right hash values to create a new parent value
fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_data(n: usize) -> Vec<Data> {
        let mut data = vec![];
        for i in 0..n {
            data.push(vec![i as u8]);
        }
        data
    }

    #[test]
    fn test_constructions() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(3);
        let tree = MerkleTree::construct(&data);
        let expected_root = "773a93ac37ea78b3f14ac31872c83886b0a0f1fec562c4e848e023c889c2ce9f";
        assert_eq!(hex::encode(tree.root()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root()), expected_root);
    }

    #[test]
    fn test_verify_function_with_single_element_should_return_true() {
        let data = example_data(1);
        let hash = hash_data(&data[0]);
        assert_eq!(MerkleTree::verify(&data, &hash), true);
    }

    #[test]
    fn test_verify_function_with_two_elements_and_non_concatenated_hash_should_return_false() {
        let data2 = example_data(2);
        let hash2 = hash_data(&data2[0]);
        assert_eq!(MerkleTree::verify(&data2, &hash2), false);
    }

    #[test]
    fn test_verify_function_with_two_elements_and_concatenated_hash_should_return_true() {
        let data = example_data(2);
        let hash1 = hash_data(&data[0]);
        let hash2 = hash_data(&data[1]);
        let root = hash_concat(&hash1, &hash2);
        assert_eq!(MerkleTree::verify(&data, &root), true);
    }

    #[test]
    fn test_verify_function_with_two_elements_and_wrongly_concatenated_hash_should_return_false() {
        let data = example_data(2);
        let hash1 = hash_data(&data[1]);
        let hash2 = hash_data(&data[0]);
        let root = hash_concat(&hash1, &hash2);
        assert_eq!(MerkleTree::verify(&data, &root), false);
    }

    #[test]
    fn test_verify_proof_with_two_elements_and_correct_proof_should_return_true() {
        let data = example_data(2);
        let tree = MerkleTree::construct(&data);
        let hash2 = hash_data(&data[1]);
        let proof = Proof {
            hashes: vec![(HashDirection::Right, hash2)]
        };
        let actual = MerkleTree::verify_proof(&data[0], &proof, &tree.root());
        assert_eq!(true, actual);
    }

    #[test]
    fn test_verify_proof_with_two_elements_and_incorrect_proof_should_return_false() {
        let data = example_data(2);
        let tree = MerkleTree::construct(&data);
        let hash2 = hash_data(&data[1]);
        let proof = Proof {
            hashes: vec![(HashDirection::Left, hash2)]
        };
        let actual = MerkleTree::verify_proof(&data[0], &proof, &tree.root());
        assert_eq!(false, actual);
    }

    #[test]
    fn test_verify_proof_with_more_elements_and_correct_proof_should_return_true() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let hash1 = hash_data(&data[0]);
        let hash2 = hash_data(&data[1]);
        let hash5 = hash_concat(&hash1, &hash2);
        let hash4 = hash_data(&data[3]);
        let proof = Proof {
            hashes: vec![
                (HashDirection::Right, hash4),
                (HashDirection::Left, hash5)
            ]
        };
        let actual = MerkleTree::verify_proof(&data[2], &proof, &tree.root());
        assert_eq!(true, actual);
    }

    #[test]
    fn test_prove_that_two_nodes_will_return_proofs() {
        let data = example_data(2);
        let tree = MerkleTree::construct(&data);
        let actual = tree.prove(&data[0]);

        let hash2 = hash_data(&data[1]);
        let expected = Proof {
            hashes: vec![(HashDirection::Right, hash2)]
        };
        assert_eq!(expected.hashes, actual.expect("this should return Proof").hashes)
    }

    #[test]
    fn test_prove_that_eight_nodes_with_correct_proofs_will_prove_the_leaf() {
        let data = example_data(8);
                   // H15(root)
              // H13             H14
          // H9      H10     H11     H12
        // H1  H2  H3  H4  H5  H6  H7  H8
        // 0   1   2   3   4   5   6   7
        let tree = MerkleTree::construct(&data);
        let hash1 = hash_data(&data[0]);
        let hash2 = hash_data(&data[1]);
        let hash3 = hash_data(&data[2]);
        let hash4 = hash_data(&data[3]);
        let hash5 = hash_data(&data[4]);
        let hash6 = hash_data(&data[5]);
        let hash7 = hash_data(&data[6]);
        let hash8 = hash_data(&data[7]);
        let hash9 = hash_concat(&hash1, &hash2);
        let hash10 = hash_concat(&hash3, &hash4);
        let hash11 = hash_concat(&hash5, &hash6);
        let hash12 = hash_concat(&hash7, &hash8);
        let hash13 = hash_concat(&hash9, &hash10);
        let hash14 = hash_concat(&hash11, &hash12);
        let root_hash = hash_concat(&hash13, &hash14);

        let actual = tree.prove(&data[1]);
        let expected = Proof {
            hashes: vec![
                (HashDirection::Left, hash1),
                (HashDirection::Right, hash10),
                (HashDirection::Right, hash14)
            ]
        };
        assert_eq!(expected.hashes, actual.expect("this should return Proof").hashes);


        let actual = tree.prove(&data[4]);
        let expected = Proof {
            hashes: vec![
                (HashDirection::Right, hash6),
                (HashDirection::Right, hash12),
                (HashDirection::Left, hash13)
            ]
        };
        assert_eq!(expected.hashes, actual.expect("this should return Proof").hashes);

        assert_eq!(tree.root(), root_hash);
    }
}