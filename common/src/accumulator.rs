//! This module provides a generic framework, and a Merkle-tree based implementation,
//! for vector accumulators. This allows a party (the verifier) to outsource the storage
//! of the vector to another party (the prover). The verifier only maintains a single
//! hash that commits to the entire vector, and retrieves the elements of the vector,
//! or updates their content, by sending requests to the prover.
//! Each retrieval or update operation is guaranteed by an accompanied proof, that is
//! produced by the prover.

use alloc::{vec, vec::Vec};
use core::{error::Error, fmt, marker::PhantomData, mem::MaybeUninit, ops::Deref};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub enum AccumulatorError {
    IndexOutOfBounds,
}

impl fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccumulatorError::IndexOutOfBounds => write!(f, "Index out of bounds"),
        }
    }
}

impl Error for AccumulatorError {}

/// A trait representing a cryptographic hasher that produces a fixed-size output.
pub trait Hasher<const OUTPUT_SIZE: usize>: Sized {
    /// Creates a new instance of the hasher.
    fn new() -> Self;

    /// Updates the hasher with the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes to be hashed.
    fn update(&mut self, data: &[u8]) -> &mut Self;

    /// Finalizes the hashing process and writes the output to an array of bytes.
    fn digest(self, out: &mut [u8; OUTPUT_SIZE]);

    /// Finalizes the hashing process and returns the output as an array of bytes.
    fn finalize(self) -> [u8; OUTPUT_SIZE] {
        let mut out = MaybeUninit::<[u8; OUTPUT_SIZE]>::uninit();
        // SAFETY: the call to `digest` will fully initialize the output array.
        let out_ref = unsafe { &mut *out.as_mut_ptr() };
        self.digest(out_ref);
        unsafe { out.assume_init() }
    }

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

/// A trait for implementations to allow reusing the same hasher instance.
pub trait ResettableHasher<const OUTPUT_SIZE: usize>: Hasher<OUTPUT_SIZE> {
    /// Reset to the same state as `Self::new()`.
    ///
    /// Note: it is not guaranteed that the result will be byte-for-byte identical to
    /// a new instance produced by `Self::new()`, but it is guaranteed that the
    /// hasher will produce the same output after `reset()` as a new instance would,
    /// if fed the same input data.
    fn reset(&mut self);

    /// Finalize the hashing process, saving the output in the provided array.
    /// If the hasher will be reused for a new hash, the `reset` method MUST be called
    /// before the next `update` call.
    fn digest_inplace<'a, 'b>(&'a mut self, out: &'b mut [u8; OUTPUT_SIZE]);

    /// Finalize the hashing process, returning the output as an array of bytes.
    /// If the hasher will be reused for a new hash, the `reset` method MUST be called
    /// before the next `update` call.
    fn finalize_inplace(&mut self) -> [u8; OUTPUT_SIZE] {
        let mut out = MaybeUninit::<[u8; OUTPUT_SIZE]>::uninit();
        let out_ref = unsafe { &mut *out.as_mut_ptr() };
        self.digest_inplace(out_ref);
        unsafe { out.assume_init() }
    }
}

/// A wrapper type for fixed-size byte arrays used to represent hash outputs.
///
/// This wrapper allows implementing serialization and deserialization traits
/// for byte arrays of arbitrary lengths, which is not natively supported by Serde.
#[repr(transparent)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashOutput<const N: usize>(pub [u8; N]);

impl<const N: usize> Deref for HashOutput<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> HashOutput<N> {
    pub fn as_hash_output(array: &[u8; N]) -> &Self {
        unsafe { core::mem::transmute(array) }
    }
}

impl<const N: usize> From<[u8; N]> for HashOutput<N> {
    fn from(array: [u8; N]) -> Self {
        HashOutput(array)
    }
}

impl<const N: usize> From<HashOutput<N>> for [u8; N] {
    fn from(hash: HashOutput<N>) -> Self {
        hash.0
    }
}

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
        let array: [u8; N] = slice
            .try_into()
            .map_err(|_| serde::de::Error::custom("Incorrect length"))?;
        Ok(HashOutput(array))
    }
}

/// A trait representing a cryptographic vector accumulator, that can generate and verify
/// proofs of inclusion and updates.
pub trait VectorAccumulator<
    T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
    const OUTPUT_SIZE: usize,
>
{
    /// The type representing an inclusion proof.
    type InclusionProof: Serialize + DeserializeOwned;

    /// The type representing a reference to an inclusion proof.
    type InclusionProofRef<'a>;

    /// The type representing an update proof.
    type UpdateProof: Serialize + DeserializeOwned;

    /// The type representing a reference to an update proof.
    type UpdateProofRef<'a>;

    /// Creates a new accumulator with the given data.
    fn new(data: Vec<T>) -> Self;

    /// Returns the a reference to the i-th element in the vector, or None if the index is out of bounds.
    fn get(&self, index: usize) -> Option<&T>;

    /// Returns the size of the vector.
    fn size(&self) -> usize;

    /// Returns the root hash of the accumulator.
    fn root(&self) -> &HashOutput<OUTPUT_SIZE>;

    /// Generates a proof of inclusion for an element at the given index.
    /// Returns the inclusion proof, or an error string if the index is out of bounds.
    fn prove(&self, index: usize) -> Result<Self::InclusionProof, AccumulatorError>;

    /// Computes the hash of an element.
    fn hash_element<T_: AsRef<[u8]>>(element: &T_) -> HashOutput<OUTPUT_SIZE>;

    /// Updates the accumulator by replacing the element at the given index.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the element to be updated.
    /// * `value` - The new value to replace the existing element.
    ///
    /// # Returns
    ///
    /// A pair of the update proof and the new root hash, or an error string if the index is out of bounds.
    fn update(
        &mut self,
        index: usize,
        value: T,
    ) -> Result<(Self::UpdateProof, HashOutput<OUTPUT_SIZE>), AccumulatorError>;
}

pub trait VectorAccumulatorVerifier<
    T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
    const OUTPUT_SIZE: usize,
    H: Hasher<OUTPUT_SIZE>,
>
{
    /// The type representing a reference to an inclusion proof.
    type InclusionProofRef<'a>;

    /// The type representing a reference to an update proof.
    type UpdateProofRef<'a>;

    /// Verifies an inclusion proof. This associated function is called by the verifier,
    /// rather than the owner of the instance.
    ///
    /// # Arguments
    ///
    /// * `root` - The expected root hash of the accumulator.
    /// * `proof` - The inclusion proof to verify.
    /// * `value_hash` - The hash of the element.
    /// * `index` - The index of the element.
    /// * `size` - The size of the accumulator.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid, `false` otherwise.
    fn verify_inclusion_proof<'a>(
        root: &HashOutput<OUTPUT_SIZE>,
        proof: Self::InclusionProofRef<'a>,
        value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> bool;

    /// Verifies an update proof. This associated function is called by the verifier,
    /// rather than the owner of the instance.
    ///
    /// # Arguments
    ///
    /// * `old_root` - The old root hash before the update.
    /// * `new_root` - The new root hash before the update.
    /// * `update_proof` - The update proof to verify.
    /// * `old_value_hash` - The hash of the old value of the element before the update.
    /// * `new_value_hash` - The hash of the new value of the element after the update.
    /// * `index` - The index of the element.
    /// * `size` - The size of the accumulator.
    ///
    /// # Returns
    ///
    /// `true` if the update proof is valid, `false` otherwise.
    fn verify_update_proof<'a>(
        old_root: &HashOutput<OUTPUT_SIZE>,
        new_root: &HashOutput<OUTPUT_SIZE>,
        update_proof: Self::UpdateProofRef<'a>,
        old_value_hash: &HashOutput<OUTPUT_SIZE>,
        new_value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> bool;
}

/// Trait for incrementally verifying an inclusion proof.
pub trait InclusionProofVerifier<const OUTPUT_SIZE: usize, H: ResettableHasher<OUTPUT_SIZE>> {
    /// Feeds a single proof element into the verifier.
    fn feed(&mut self, hasher: &mut H, element: &HashOutput<OUTPUT_SIZE>);

    /// Returns `true` if the proof has been verified, `false` otherwise.
    fn verified(&self) -> bool;
}

/// Trait for incrementally verifying an update proof.
pub trait UpdateProofVerifier<const OUTPUT_SIZE: usize, H: ResettableHasher<OUTPUT_SIZE>> {
    /// Feeds a single proof element into the verifier.
    fn feed(&mut self, hasher: &mut H, element: &HashOutput<OUTPUT_SIZE>);

    /// Returns `true` if the proof has been verified, `false` otherwise.
    fn verified(&self) -> bool;
}

/// Trait for vector accumulators that support streaming proof verification.
/// Assumes that the proofs are just lists of hashes.
pub trait StreamingVectorAccumulator<
    T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
    const OUTPUT_SIZE: usize,
    H: ResettableHasher<OUTPUT_SIZE>,
>: VectorAccumulator<T, OUTPUT_SIZE>
{
    type InclusionProofVerifier: InclusionProofVerifier<OUTPUT_SIZE, H>;
    type UpdateProofVerifier: UpdateProofVerifier<OUTPUT_SIZE, H>;

    /// Initiates an inclusion proof verifier with the given parameters.
    fn begin_inclusion_proof(
        root: &HashOutput<OUTPUT_SIZE>,
        value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> Self::InclusionProofVerifier;

    /// Initiates an update proof verifier with the given parameters.
    fn begin_update_proof(
        old_root: &HashOutput<OUTPUT_SIZE>,
        new_root: &HashOutput<OUTPUT_SIZE>,
        old_value_hash: &HashOutput<OUTPUT_SIZE>,
        new_value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> Self::UpdateProofVerifier;
}

// blanket implementation of verify_inclusion_proof and verify_update_proof for a StreamingVectorAccumulator
impl<
        T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
        const OUTPUT_SIZE: usize,
        H: ResettableHasher<OUTPUT_SIZE>,
        S: StreamingVectorAccumulator<T, OUTPUT_SIZE, H>,
    > VectorAccumulatorVerifier<T, OUTPUT_SIZE, H> for S
{
    type InclusionProofRef<'a> = &'a [HashOutput<OUTPUT_SIZE>];
    type UpdateProofRef<'a> = &'a [HashOutput<OUTPUT_SIZE>];

    fn verify_inclusion_proof<'a>(
        root: &HashOutput<OUTPUT_SIZE>,
        proof: Self::InclusionProofRef<'a>,
        value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> bool {
        let mut hasher = H::new();
        let mut verifier = Self::begin_inclusion_proof(root, value_hash, index, size);
        for el in proof.iter() {
            verifier.feed(&mut hasher, el);
        }
        verifier.verified()
    }

    fn verify_update_proof<'a>(
        old_root: &HashOutput<OUTPUT_SIZE>,
        new_root: &HashOutput<OUTPUT_SIZE>,
        update_proof: Self::UpdateProofRef<'a>,
        old_value_hash: &HashOutput<OUTPUT_SIZE>,
        new_value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> bool {
        let mut verifier = Self::begin_update_proof(
            old_root,
            new_root,
            old_value_hash,
            new_value_hash,
            index,
            size,
        );

        let mut hasher = H::new();
        for el in update_proof.iter() {
            verifier.feed(&mut hasher, el);
        }
        verifier.verified()
    }
}

/// Verifier for streaming inclusion proof verification in a Merkle tree.
pub struct MerkleInclusionProofVerifier<H: ResettableHasher<OUTPUT_SIZE>, const OUTPUT_SIZE: usize>
{
    current_hash: HashOutput<OUTPUT_SIZE>, // Current computed hash
    pos: usize,                            // Current position in the tree
    root: HashOutput<OUTPUT_SIZE>,         // Expected root hash
    verified: bool,                        // Whether the proof has been verified
    _marker: PhantomData<H>,
}

impl<H: ResettableHasher<OUTPUT_SIZE>, const OUTPUT_SIZE: usize>
    InclusionProofVerifier<OUTPUT_SIZE, H> for MerkleInclusionProofVerifier<H, OUTPUT_SIZE>
{
    fn feed(&mut self, hasher: &mut H, sibling_hash: &HashOutput<OUTPUT_SIZE>) {
        if self.pos == 0 {
            // Verification already completed; extra elements make the proof invalid

            self.verified = false;
            return;
        }

        // Determine if the current node is a left or right child
        let (left, right) = if self.pos % 2 == 0 {
            (sibling_hash, &self.current_hash) // Even pos: right child
        } else {
            (&self.current_hash, sibling_hash) // Odd pos: left child
        };

        // Compute the parent hash
        hasher.reset();
        hasher.update(&[0x01]); // Internal node prefix
        hasher.update(&left.0);
        hasher.update(&right.0);
        hasher.digest_inplace(&mut self.current_hash.0);

        // Move up the tree
        self.pos = (self.pos - 1) / 2;

        // If at the root, check if the computed hash matches
        if self.pos == 0 {
            self.verified = &self.current_hash == &self.root;
        }
    }

    fn verified(&self) -> bool {
        self.verified
    }
}

/// Verifier for streaming update proof verification in a Merkle tree.
/// An update proof is just a pair of inclusion proofs, one for the old element value and root, the other for
/// the new ones.
pub struct MerkleUpdateProofVerifier<H: ResettableHasher<OUTPUT_SIZE>, const OUTPUT_SIZE: usize> {
    old_verifier: MerkleInclusionProofVerifier<H, OUTPUT_SIZE>,
    new_verifier: MerkleInclusionProofVerifier<H, OUTPUT_SIZE>,
}

impl<H: ResettableHasher<OUTPUT_SIZE>, const OUTPUT_SIZE: usize> UpdateProofVerifier<OUTPUT_SIZE, H>
    for MerkleUpdateProofVerifier<H, OUTPUT_SIZE>
{
    fn feed(&mut self, hasher: &mut H, sibling_hash: &HashOutput<OUTPUT_SIZE>) {
        self.old_verifier.feed(hasher, sibling_hash);
        self.new_verifier.feed(hasher, sibling_hash);
    }

    fn verified(&self) -> bool {
        self.new_verifier.verified() && self.old_verifier.verified()
    }
}

/// A Merkle tree-based implementation of the `VectorAccumulator` trait.
/// The accumulator maintains a vector of data elements and a corresponding Merkle tree, allowing for efficient proofs
/// of inclusion and updates.
///
/// The size of the MerkleAccumulator must be a power of two, and the constructor (implemented in the `new` function of
/// the `VectorAccumulator` trait) will panic if this condition is not met. Therefore, the resulting Merkle tree is
/// complete and perfectly balanced.
pub struct MerkleAccumulator<
    H: Hasher<OUTPUT_SIZE>,
    T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
    const OUTPUT_SIZE: usize,
> {
    data: Vec<T>,
    tree: Vec<HashOutput<OUTPUT_SIZE>>,
    _marker: PhantomData<H>,
}

impl<
        H: ResettableHasher<OUTPUT_SIZE>,
        T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
        const OUTPUT_SIZE: usize,
    > StreamingVectorAccumulator<T, OUTPUT_SIZE, H> for MerkleAccumulator<H, T, OUTPUT_SIZE>
{
    type InclusionProofVerifier = MerkleInclusionProofVerifier<H, OUTPUT_SIZE>;
    type UpdateProofVerifier = MerkleUpdateProofVerifier<H, OUTPUT_SIZE>;

    fn begin_inclusion_proof(
        root: &HashOutput<OUTPUT_SIZE>,
        value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> Self::InclusionProofVerifier {
        let pos = size - 1 + index;
        MerkleInclusionProofVerifier {
            current_hash: value_hash.clone(),
            pos,
            root: root.clone(),
            // a zero-length proof (for a single-element tree) is only valid if the value hash is equal to the root
            verified: size == 1 && value_hash == root,
            _marker: PhantomData,
        }
    }

    fn begin_update_proof(
        old_root: &HashOutput<OUTPUT_SIZE>,
        new_root: &HashOutput<OUTPUT_SIZE>,
        old_value_hash: &HashOutput<OUTPUT_SIZE>,
        new_value_hash: &HashOutput<OUTPUT_SIZE>,
        index: usize,
        size: usize,
    ) -> Self::UpdateProofVerifier {
        let old_verifier = Self::begin_inclusion_proof(old_root, old_value_hash, index, size);
        let new_verifier = Self::begin_inclusion_proof(new_root, new_value_hash, index, size);

        MerkleUpdateProofVerifier {
            old_verifier,
            new_verifier,
        }
    }
}

impl<
        H: Hasher<OUTPUT_SIZE>,
        T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
        const OUTPUT_SIZE: usize,
    > VectorAccumulator<T, OUTPUT_SIZE> for MerkleAccumulator<H, T, OUTPUT_SIZE>
{
    type InclusionProof = Vec<HashOutput<OUTPUT_SIZE>>;
    type InclusionProofRef<'a> = &'a [HashOutput<OUTPUT_SIZE>];

    // the update proof is a Merkle proof (the new root is passed as an argument to the verifier)
    type UpdateProof = Self::InclusionProof;
    type UpdateProofRef<'a> = Self::InclusionProofRef<'a>;

    /// Creates a new `MerkleAccumulator` with the given data.
    ///
    /// # Arguments
    ///
    /// * `data` - A vector of elements to be included in the Merkle tree.
    fn new(data: Vec<T>) -> Self {
        assert!(
            Self::has_valid_leaf_count(data.len()),
            "MerkleAccumulator requires a non-zero power-of-two number of leaves, got {}",
            data.len()
        );
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
    fn root(&self) -> &HashOutput<OUTPUT_SIZE> {
        &self.tree[0]
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
    fn prove(&self, index: usize) -> Result<Self::InclusionProof, AccumulatorError> {
        if index >= self.data.len() {
            return Err(AccumulatorError::IndexOutOfBounds);
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
    fn update(
        &mut self,
        index: usize,
        value: T,
    ) -> Result<(Self::UpdateProof, HashOutput<OUTPUT_SIZE>), AccumulatorError> {
        if index >= self.data.len() {
            return Err(AccumulatorError::IndexOutOfBounds);
        }

        let merkle_proof = self.prove(index)?; // Capture proof before update
        self.data[index] = value;
        let n = self.data.len();
        let mut pos = n - 1 + index;
        self.tree[pos] = Self::hash_leaf(&self.data[index]);

        while pos > 0 {
            pos = (pos - 1) / 2;
            self.tree[pos] =
                Self::hash_internal_node(&self.tree[2 * pos + 1], &self.tree[2 * pos + 2]);
        }

        let new_root = self.root();
        Ok((merkle_proof, new_root.clone()))
    }
    /// Computes the hash of an element.
    #[inline]
    fn hash_element<T_: AsRef<[u8]>>(element: &T_) -> HashOutput<OUTPUT_SIZE> {
        Self::hash_leaf(element)
    }
}

impl<
        H: Hasher<OUTPUT_SIZE>,
        T: AsRef<[u8]> + Clone + Serialize + DeserializeOwned,
        const OUTPUT_SIZE: usize,
    > MerkleAccumulator<H, T, OUTPUT_SIZE>
{
    #[inline]
    fn has_valid_leaf_count(size: usize) -> bool {
        size > 0 && size.is_power_of_two()
    }

    /// Constructs the Merkle tree from the provided data.
    fn build_tree(&mut self) {
        let n = self.data.len();
        debug_assert!(Self::has_valid_leaf_count(n));
        let leaves = self
            .data
            .iter()
            .map(|x| Self::hash_leaf(x))
            .collect::<Vec<_>>();

        self.tree = vec![HashOutput([0u8; OUTPUT_SIZE]); 2 * n - 1];
        self.tree[n - 1..].clone_from_slice(&leaves);

        for i in (0..n - 1).rev() {
            self.tree[i] = Self::hash_internal_node(&self.tree[2 * i + 1], &self.tree[2 * i + 2]);
        }
    }

    /// Computes the hash for a leaf node. A 0x00 byte is prepended to the data before hashing the element.
    fn hash_leaf<T_: AsRef<[u8]>>(data: &T_) -> HashOutput<OUTPUT_SIZE> {
        let mut hasher = H::new();
        hasher.update(&[0x00]);
        hasher.update(data.as_ref());
        HashOutput(hasher.finalize())
    }

    /// Computes the hash for an internal node. A 0x01 byte is prepended to the data before hashing the child nodes.
    fn hash_internal_node(
        left: &HashOutput<OUTPUT_SIZE>,
        right: &HashOutput<OUTPUT_SIZE>,
    ) -> HashOutput<OUTPUT_SIZE> {
        // prepend a 0x01 byte to the data before hashing internal nodes
        let mut hasher = H::new();
        hasher.update(&[0x01]);
        hasher.update(&left.0);
        hasher.update(&right.0);
        HashOutput(hasher.finalize())
    }
}

/// Computes the Merkle root hash from a stream of leaf hashes, without needing to store the entire tree in memory.
///
/// Leaf hashes are fed in order from left to right. Once all leaves have been
/// provided, the computed root can be retrieved.
///
/// The memory occupation is guaranteed to be O(log n) in the number of leaves during the entire lifetime of the object.
pub struct MerkleAccumulatorRootComputer<const OUTPUT_SIZE: usize, H: ResettableHasher<OUTPUT_SIZE>>
{
    n: usize,                             // number of leaves
    cur_size: usize,                      // number of leaves already added
    hashes: Vec<HashOutput<OUTPUT_SIZE>>, // stack of intermediate hashes
    _marker: PhantomData<H>,
}

impl<const OUTPUT_SIZE: usize, H: ResettableHasher<OUTPUT_SIZE>>
    MerkleAccumulatorRootComputer<OUTPUT_SIZE, H>
{
    /// Creates a new `MerkleAccumulatorRootComputer` instance.
    pub fn new(n: usize) -> Self {
        assert!(
            n > 0 && n.is_power_of_two(),
            "MerkleAccumulatorRootComputer requires a non-zero power-of-two number of leaves, got {}",
            n
        );
        MerkleAccumulatorRootComputer::<OUTPUT_SIZE, H> {
            n,
            cur_size: 0,
            hashes: Vec::with_capacity(n.trailing_zeros() as usize),
            _marker: PhantomData,
        }
    }

    /// Feeds a leaf hash into the accumulator. The leaf hashes must be fed in order from left to right.
    ///
    /// This is guaranteed to run in O(log n) time for a single update, while it is guaranteed that the
    /// total number of hashes performed after feeding all leaves is less than 2n.
    ///
    /// # Panics
    ///
    /// Panics if more leaf hashes are fed than the specified number of leaves.
    pub fn feed(&mut self, leaf_hash: &HashOutput<OUTPUT_SIZE>) {
        if self.cur_size >= self.n {
            panic!(
                "Cannot feed more leaf hashes than the specified number of leaves: {}/{}",
                self.cur_size, self.n
            );
        }

        self.hashes.push(leaf_hash.clone());
        self.cur_size += 1;

        // Combine the last d hashes, where d is the number of trailing zeros in the binary representation of cur_size
        let d = self.cur_size.trailing_zeros() as usize;
        debug_assert!(
            d <= self.hashes.len(),
            "Invariant violation: number of trailing zeros cannot exceed the number of hashes in the stack"
        );
        for _ in 0..d {
            let right = self.hashes.pop().unwrap();
            let left = self.hashes.pop().unwrap();
            let combined =
                MerkleAccumulator::<H, Vec<u8>, OUTPUT_SIZE>::hash_internal_node(&left, &right);
            self.hashes.push(combined);
        }
    }

    /// Returns the computed Merkle root hash after all leaf hashes have been fed.
    ///
    /// # Panics
    ///
    /// Panics if called before all leaf hashes have been fed.
    pub fn root(&self) -> HashOutput<OUTPUT_SIZE> {
        if self.cur_size != self.n {
            panic!(
                "Cannot retrieve root before all leaf hashes have been fed: {}/{}",
                self.cur_size, self.n
            );
        }
        self.hashes[0].clone()
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

        fn update(&mut self, data: &[u8]) -> &mut Self {
            self.hasher.update(data);
            self
        }

        fn digest(self, out: &mut [u8; 32]) {
            let result = self.hasher.finalize();
            out.copy_from_slice(&result);
        }
    }

    // implementation by cloning, just for the sake of the tests
    impl ResettableHasher<32> for Sha256Hasher {
        fn reset(&mut self) {
            self.hasher = Sha256::new();
        }

        fn digest_inplace<'a, 'b>(&'a mut self, out: &'b mut [u8; 32]) {
            let h = self.hasher.clone();
            let result = h.finalize();
            out.copy_from_slice(&result);
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
        let data = generate_test_data(4);
        let ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());

        // Trying to prove an element at an out-of-bounds index should return an error
        assert!(ma.prove(4).is_err());
    }

    #[test]
    fn test_out_of_bounds_update() {
        let data = generate_test_data(4);
        let mut ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());

        // Trying to update an element at an out-of-bounds index should return an error
        assert!(ma.update(4, b"new_data".to_vec()).is_err());
    }

    #[test]
    #[should_panic(expected = "power-of-two number of leaves")]
    fn test_new_requires_power_of_two_size() {
        let data = generate_test_data(3);
        let _ = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data);
    }

    #[test]
    fn test_verify_incorrect_proof() {
        let data = generate_test_data(4);

        let ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
        let root = ma.root();

        // Generate a proof for one element and try to verify it with another
        let proof = ma.prove(0).unwrap();
        let elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[1]);
        assert!(
            !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
                &root,
                &proof,
                &elem_hash,
                1,
                data.len()
            )
        );
    }

    #[test]
    fn test_update_proof_with_incorrect_values() {
        let data = generate_test_data(4);

        let mut ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
        let old_root = ma.root().clone();

        // Update an element
        let new_data = b"new_data".to_vec();
        let (update_proof, new_root) = ma.update(2, new_data.clone()).unwrap();

        let old_elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[2]);
        let new_elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&new_data);
        let incorrect_elem_hash =
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[0]);

        // Verify update proof is false with incorrect old root
        assert!(
            !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &new_root, // Incorrect, we pass new_root instead of the old_root
                &new_root,
                &update_proof,
                &old_elem_hash,
                &new_elem_hash,
                2,
                data.len()
            )
        );

        // Verify update proof is false with incorrect old value hash
        assert!(
            !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &old_root,
                &new_root,
                &update_proof,
                &incorrect_elem_hash, // Incorrect old value hash
                &new_elem_hash,
                2,
                data.len()
            )
        );

        // Verify update proof is false with incorrect new value hash
        assert!(
            !MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &old_root,
                &new_root,
                &update_proof,
                &old_elem_hash,
                &incorrect_elem_hash, // Incorrect new value hash
                2,
                data.len()
            )
        );
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

        let root = ma.root().clone();

        let proof = ma.prove(2).unwrap();
        let elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[2]);
        assert!(
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
                &root,
                &proof,
                &elem_hash,
                2,
                data.len()
            )
        );

        // Update an element and check if root changes
        let new_data = b"new_data".to_vec();
        let (update_proof, new_root) = ma.update(2, new_data.clone()).unwrap();
        assert_ne!(root, new_root);

        let new_proof = ma.prove(2).unwrap();
        let new_elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&new_data);
        assert!(
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
                &new_root,
                &new_proof,
                &new_elem_hash,
                2,
                data.len()
            )
        );

        // Verify the update proof
        let old_elem_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[2]);
        assert!(
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &root, // old root
                &new_root,
                &update_proof,
                &old_elem_hash,
                &new_elem_hash,
                2,
                data.len()
            )
        );

        // Test that serializing/deserializing inclusion proofs and update proofs works
        let serialized_proof: Vec<u8> = postcard::to_allocvec(&proof).unwrap();
        let deserialized_proof: Vec<HashOutput<32>> =
            postcard::from_bytes(&serialized_proof).unwrap();
        assert_eq!(proof, deserialized_proof);

        let serialized_update_proof = postcard::to_allocvec(&update_proof).unwrap();
        let deserialized_update_proof: Vec<HashOutput<32>> =
            postcard::from_bytes(&serialized_update_proof).unwrap();
        assert_eq!(update_proof, deserialized_update_proof);
    }

    #[test]
    fn test_size1_accumulator() {
        // If an accumulator has only one element, valid proofs are empty
        let data = vec![b"single_element".to_vec()];
        let ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());

        let root = ma.root().clone();
        let element_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[0]);

        // For a single element, the root should equal the element hash
        assert_eq!(root, element_hash);

        // Generate proof for the single element
        let proof = ma.prove(0).unwrap();

        // Proof should be empty for a single element accumulator
        assert!(proof.is_empty());

        // Verify the empty proof is valid
        assert!(
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_inclusion_proof(
                &root,
                &proof,
                &element_hash,
                0,
                1
            )
        );

        // Test update on single element accumulator
        let new_data = b"updated_element".to_vec();
        let mut ma_mut = ma;
        let (update_proof, new_root) = ma_mut.update(0, new_data.clone()).unwrap();

        // Update proof should also be empty for single element
        assert!(update_proof.is_empty());

        let new_element_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&new_data);

        // Verify update proof
        assert!(
            MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::verify_update_proof(
                &root,
                &new_root,
                &update_proof,
                &element_hash,
                &new_element_hash,
                0,
                1
            )
        );
    }

    #[test]
    fn test_root_computer_matches_merkle_root() {
        let data = generate_test_data(8);
        let ma = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::new(data.clone());
        let expected_root = ma.root().clone();

        let mut root_computer = MerkleAccumulatorRootComputer::<32, Sha256Hasher>::new(data.len());
        for element in data.iter() {
            let leaf_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(element);
            root_computer.feed(&leaf_hash);
        }

        let computed_root = root_computer.root();
        assert_eq!(expected_root, computed_root);
    }

    #[test]
    fn test_root_computer_single_leaf() {
        let data = generate_test_data(1);
        let leaf_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[0]);

        let mut root_computer = MerkleAccumulatorRootComputer::<32, Sha256Hasher>::new(1);
        root_computer.feed(&leaf_hash);
        let computed_root = root_computer.root();

        assert_eq!(leaf_hash, computed_root);
    }

    #[test]
    #[should_panic(expected = "power-of-two number of leaves")]
    fn test_root_computer_requires_power_of_two() {
        let _ = MerkleAccumulatorRootComputer::<32, Sha256Hasher>::new(3);
    }

    #[test]
    #[should_panic(expected = "non-zero power-of-two number of leaves")]
    fn test_root_computer_requires_non_zero() {
        let _ = MerkleAccumulatorRootComputer::<32, Sha256Hasher>::new(0);
    }

    #[test]
    #[should_panic(expected = "Cannot retrieve root before all leaf hashes have been fed")]
    fn test_root_computer_root_before_complete() {
        let data = generate_test_data(4);
        let mut root_computer = MerkleAccumulatorRootComputer::<32, Sha256Hasher>::new(data.len());
        let leaf_hash = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[0]);
        root_computer.feed(&leaf_hash);

        let _ = root_computer.root();
    }

    #[test]
    #[should_panic(expected = "Cannot feed more leaf hashes than the specified number of leaves")]
    fn test_root_computer_overfeed() {
        let data = generate_test_data(2);
        let mut root_computer = MerkleAccumulatorRootComputer::<32, Sha256Hasher>::new(data.len());
        let leaf_hash_0 = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[0]);
        let leaf_hash_1 = MerkleAccumulator::<Sha256Hasher, Vec<u8>, 32>::hash_leaf(&data[1]);

        root_computer.feed(&leaf_hash_0);
        root_computer.feed(&leaf_hash_1);
        root_computer.feed(&leaf_hash_0);
    }
}
