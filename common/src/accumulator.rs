//! This module provides a generic framework, and a Merkle-tree based implementation,
//! for vector accumulators. This allows a party (the verifier) to outsource the storage
//! of the vector to another party (the prover). The verifier only maintains a single
//! hash that commits to the entire vector, and retrieves the elements of the vector,
//! or updates their content, by sending requests to the prover.
//! Each retrieval or update operation is guaranteed by an accompanied proof, that is
//! produced by the prover.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use serde::{Serialize, Deserialize, Serializer, Deserializer, de::DeserializeOwned};

/// A trait representing a cryptographic hasher that produces a fixed-size output.
pub trait Hasher<const OUTPUT_SIZE: usize>: Sized {
    /// Creates a new instance of the hasher.
    fn new() -> Self;

    /// Updates the hasher with the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes to be hashed.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hashing process and returns the output as an array of bytes.
    fn finalize(self) -> [u8; OUTPUT_SIZE];
    
    /// Convenience method to hash data in a single step.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes to be hashed.
    ///
    /// # Returns
    ///
    /// A fixed-size output array of bytes representing the hash.
    fn hash(data: &[u8]) -> [u8; OUTPUT_SIZE] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// A wrapper type for fixed-size byte arrays used to represent hash outputs.
///
/// This wrapper allows implementing serialization and deserialization traits
/// for byte arrays of arbitrary lengths, which is not natively supported by Serde.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashOutput<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for HashOutput<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for HashOutput<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let slice: &[u8] = Deserialize::deserialize(deserializer)?;
        let array: [u8; N] = slice.try_into().map_err(|_| serde::de::Error::custom("Incorrect length"))?;
        Ok(HashOutput(array))
    }
}

/// A trait representing a cryptographic vector accumulator, that can generate and verify
/// proofs of inclusion and updates.
pub trait VectorAccumulator<T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned> {
    /// The type representing an inclusion proof.
    type InclusionProof: Serialize + DeserializeOwned;

    /// The type representing an update proof.
    type UpdateProof: Serialize + DeserializeOwned;

    /// Creates a new accumulator with the given data.
    fn new(data: Vec<T>) -> Self;

    /// Returns the a reference to the i-th element in the vector, or None if the index is out of bounds.
    fn get(&self, index: usize) -> Option<&T>;

    /// Returns the size of the vector.
    fn size(&self) -> usize;

    /// Returns the root hash of the accumulator.
    fn root(&self) -> Vec<u8>;

    /// Generates a proof of inclusion for an element at the given index.
    /// Returns the inclusion proof, or an error string if the index is out of bounds.
    fn prove(&self, index: usize) -> Result<Self::InclusionProof, &'static str>;

    /// Verifies an inclusion proof. This associated function is called by the verifier,
    /// rather than the owner of the instance.
    ///
    /// # Arguments
    ///
    /// * `root` - The expected root hash of the accumulator.
    /// * `proof` - The inclusion proof to verify.
    /// * `value` - The value of tje element.
    /// * `index` - The index of the element.
    /// * `size` - The size of the accumulator.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise.
    fn verify_inclusion_proof(root: &[u8], proof: &Self::InclusionProof, value: &T, index: usize, size: usize) -> bool;

    /// Updates the accumulator by replacing the element at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the element to be updated.
    /// * `value` - The new value to replace the existing element.
    ///
    /// # Returns
    ///
    /// An update proof, or an error string if the index is out of bounds.
    fn update(&mut self, index: usize, value: T) -> Result<Self::UpdateProof, &'static str>;

    /// Verifies an update proof. This associated function is called by the verifier,
    /// rather than the owner of the instance.
    ///
    /// # Arguments
    ///
    /// * `new_root` - The expected new root hash after the update.
    /// * `update_proof` - The update proof to verify.
    /// * `old_value` - The old value of the element before the update.
    /// * `new_value` - The new value of the element after the update.
    /// * `index` - The index of the element.
    /// * `size` - The size of the accumulator.
    ///
    /// # Returns
    ///
    /// `true` if the update proof is valid, `false` otherwise.
    fn verify_update_proof(
        new_root: &[u8],
        update_proof: &Self::UpdateProof,
        old_value: &T,
        new_value: &T,
        index: usize,
        size: usize,
    ) -> bool;
}

/// A Merkle tree-based implementation of the `VectorAccumulator` trait.
pub struct MerkleAccumulator<H: Hasher<OUTPUT_SIZE>, T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned, const OUTPUT_SIZE: usize> {
    data: Vec<T>,
    tree: Vec<HashOutput<OUTPUT_SIZE>>,
    _marker: PhantomData<H>,
}

impl<H: Hasher<OUTPUT_SIZE>, T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned, const OUTPUT_SIZE: usize> VectorAccumulator<T> for MerkleAccumulator<H, T, OUTPUT_SIZE> {
    type InclusionProof = Vec<HashOutput<OUTPUT_SIZE>>;
    type UpdateProof = (Self::InclusionProof, Vec<u8>);

    /// Creates a new `MerkleAccumulator` with the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - A vector of elements to be included in the Merkle tree.
    fn new(data: Vec<T>) -> Self {
        let mut ma = MerkleAccumulator {
            data,
            tree: Vec::new(),
            _marker: PhantomData,
        };
        ma.build_tree();
        ma
    }

    fn get(&self, index: usize) -> Option<&T> {
        self.data.get(index)
    }

    fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns the root hash of the Merkle tree.
    fn root(&self) -> Vec<u8> {
        self.tree[0].0.to_vec()
    }

    /// Generates a proof of inclusion for an element at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the element for which to generate a proof.
    ///
    /// # Returns
    ///
    /// An inclusion proof as a vector of hash outputs.
    fn prove(&self, index: usize) -> Result<Self::InclusionProof, &'static str> {
        if index >= self.data.len() {
            return Err("Index out of bounds");
        }

        let mut proof = Vec::new();
        let n = self.data.len();
        let mut pos = n - 1 + index;

        while pos > 0 {
            if pos % 2 == 0 {
                proof.push(self.tree[pos - 1].clone());
            } else {
                proof.push(self.tree[pos + 1].clone());
            }
            pos = (pos - 1) / 2;
        }
        Ok(proof)
    }

    /// Verifies an inclusion proof for a given element and index
    fn verify_inclusion_proof(root: &[u8], proof: &Self::InclusionProof, element: &T, index: usize, size: usize) -> bool {
        let mut hash = Self::hash_leaf(element);
        let mut pos = size - 1 + index;
    
        for sibling_hash in proof.iter() {
            let (left, right) = if pos % 2 == 0 {
                (sibling_hash, &hash)
            } else {
                (&hash, sibling_hash)
            };
            hash = Self::hash_internal_node(left, right).into();
            pos = (pos - 1) / 2;
        }
    
        hash.0 == root
    }

    /// Updates the Merkle tree by replacing the element at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the element to be updated.
    /// * `value` - The new value to replace the existing element.
    ///
    /// # Returns
    ///
    /// An update proof, or an error string if the index is out of bounds.
    fn update(&mut self, index: usize, value: T) -> Result<Self::UpdateProof, &'static str> {
        if index >= self.data.len() {
            return Err("Index out of bounds");
        }

        let old_root = self.root();

        let merkle_proof = self.prove(index)?;  // Capture proof before update
        self.data[index] = value;
        let n = self.data.len();
        let mut pos = n - 1 + index;
        self.tree[pos] = Self::hash_leaf(&self.data[index]);

        while pos > 0 {
            pos = (pos - 1) / 2;
            self.tree[pos] = Self::hash_internal_node(&self.tree[2 * pos + 1], &self.tree[2 * pos + 2]);
        }

        Ok((merkle_proof, old_root))
    }

    /// Verifies an update proof.
    fn verify_update_proof(
        new_root: &[u8],
        update_proof: &Self::UpdateProof,
        old_value: &T,
        new_value: &T,
        index: usize,
        size: usize,
    ) -> bool {
        let (proof, old_root) = update_proof;

        // verify that the old value was correct, and that the same proof is correct for the new value (with the new root)
        Self::verify_inclusion_proof(old_root, proof, old_value, index, size) &&
        Self::verify_inclusion_proof(new_root, proof, new_value, index, size)
    }
}

impl<H: Hasher<OUTPUT_SIZE>, T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned, const OUTPUT_SIZE: usize> MerkleAccumulator<H, T, OUTPUT_SIZE> {
    /// Constructs the Merkle tree from the provided data.
    fn build_tree(&mut self) {
        let n = self.data.len();
        let leaves = self.data.iter().map(|x| Self::hash_leaf(x)).collect::<Vec<_>>();

        self.tree = vec![HashOutput([0u8; OUTPUT_SIZE]); 2 * n - 1];
        self.tree[n - 1..].clone_from_slice(&leaves);

        for i in (0..n - 1).rev() {
            self.tree[i] = Self::hash_internal_node(&self.tree[2 * i + 1], &self.tree[2 * i + 2]);
        }
    }

    /// Computes the hash for a leaf node. A 0x00 byte is prepended to the data before hashing the element.
    fn hash_leaf(data: &T) -> HashOutput<OUTPUT_SIZE> {
        let mut hasher = H::new();
        hasher.update(&[0x00]);
        hasher.update(data.as_ref());
        HashOutput(hasher.finalize())
    }

    /// Computes the hash for an internal node. A 0x01 byte is prepended to the data before hashing the child nodes.
    fn hash_internal_node(left: &HashOutput<OUTPUT_SIZE>, right: &HashOutput<OUTPUT_SIZE>) -> HashOutput<OUTPUT_SIZE> {
        // prepend a 0x01 byte to the data before hashing internal nodes
        let mut hasher = H::new();
        hasher.update(&[0x01]);
        hasher.update(&left.0);
        hasher.update(&right.0);
        HashOutput(hasher.finalize())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use sha2::{Digest, Sha256};

    // Example implementation of the Hasher trait using SHA-256
    pub struct Sha256Hasher {
        hasher: Sha256,
    }

    impl Hasher<32> for Sha256Hasher {
        fn new() -> Self {
            Sha256Hasher {
                hasher: Sha256::new(),
            }
        }

        fn update(&mut self, data: &[u8]) {
            self.hasher.update(data);
        }

        fn finalize(self) -> [u8; 32] {
            let result = self.hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        }
    }

    // utility function to generate test vectors of different length
    fn generate_test_data(size: usize) -> Vec<Vec<u8>> {
        (1..=size)
            .map(|i| format!("data{}", i).into_bytes())
            .collect()
    }

    #[test]
    fn test_out_of_bounds_proof_generation() {
        let data = generate_test_data(3);
        let ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
    
        // Trying to prove an element at an out-of-bounds index should return an error
        assert!(ma.prove(3).is_err());
    }
    
    #[test]
    fn test_out_of_bounds_update() {
        let data = generate_test_data(3);
        let mut ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
    
        // Trying to update an element at an out-of-bounds index should return an error
        assert!(ma.update(3, b"new_data".to_vec()).is_err());
    }
    
    #[test]
    fn test_verify_incorrect_proof() {
        let data = generate_test_data(4);
    
        let ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
        let root = ma.root();
    
        // Generate a proof for one element and try to verify it with another
        let proof = ma.prove(0).unwrap();
        assert!(!MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
            &root,
            &proof,
            &data[1],
            1,
            data.len()
        ));
    }
    
    #[test]
    fn test_update_proof_with_incorrect_values() {
        let data = generate_test_data(4);
    
        let mut ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
        let old_root = ma.root();
    
        // Update an element
        let new_data = b"new_data".to_vec();
        let update_proof = ma.update(2, new_data.clone()).unwrap();
        let new_root = ma.root();
    
        // Verify update proof is false with incorrect old root
        assert!(!MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
            &old_root, // Incorrect old root
            &update_proof,
            &data[2],
            &new_data,
            2,
            data.len()
        ));

        // Verify update proof is false with incorrect old value
        assert!(!MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
            &new_root,
            &update_proof,
            &data[0], // Incorrect old value
            &new_data,
            2,
            data.len()
        ));
    
        // Verify update proof is false with incorrect new value
        assert!(!MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
            &new_root,
            &update_proof,
            &data[2],
            &data[0], // Incorrect new value
            2,
            data.len()
        ));
    }

    #[test]
    fn test_merkle_accumulator() {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
        ];

        let mut ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());

        let root = ma.root();

        let proof = ma.prove(2).unwrap();
        assert!(MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(&root, &proof, &data[2], 2, data.len()));

        // Update an element and check if root changes
        let new_data = b"new_data".to_vec();
        let update_proof = ma.update(2, new_data.clone()).unwrap();
        let new_root = ma.root();
        assert_ne!(root, new_root);

        let new_proof = ma.prove(2).unwrap();
        assert!(MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(&new_root, &new_proof, &new_data, 2, data.len()));

        // Verify the update proof
        assert!(MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
            &new_root,
            &update_proof,
            &data[2],
            &new_data,
            2,
            data.len()
        ));

        // Test that serializing/deserializing inclusion proofs and update proofs works
        let serialized_proof: Vec<u8> = postcard::to_allocvec(&proof).unwrap();
        let deserialized_proof: Vec<HashOutput<32>> = postcard::from_bytes(&serialized_proof).unwrap();
        assert_eq!(proof, deserialized_proof);

        let serialized_update_proof = postcard::to_allocvec(&update_proof).unwrap();
        let deserialized_update_proof: (Vec<HashOutput<32>>, Vec<u8>) = postcard::from_bytes(&serialized_update_proof).unwrap();
        assert_eq!(update_proof, deserialized_update_proof);
    }
}
