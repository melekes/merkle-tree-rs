// #![deny(missing_docs,
//         missing_debug_implementations, missing_copy_implementations,
//         trivial_casts, trivial_numeric_casts,
//         unsafe_code,
//         unstable_features,
//         unused_import_braces, unused_qualifications)]

#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]

//! Merkle Tree container, implemented as a binary tree

extern crate crypto;
extern crate rustc_serialize;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::fmt;

const LEAF_SIG: u8 = 0u8;
const INTERNAL_SIG: u8 = 1u8;

struct Node
{
    hash: Vec<u8>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Node {
    fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    fn hash_str(&self) -> String {
        use rustc_serialize::hex::ToHex;
        self.hash.as_slice().to_hex()
    }
}

pub struct MerkleTree<H = DefaultHasher> {
    hasher: H,
    root: Node,
}

fn build_leaf_node<T, H>(value: &T, hasher: &mut H) -> Node
    where T: AsBytes, H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[LEAF_SIG]);
    hasher.input(value.as_bytes());
    hasher.result(result.as_mut_slice());

    Node { hash: result, left: None, right: None }
}

fn build_internal_node_with_one_child<H>(left: Node, hasher: &mut H) -> Node
    where H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[INTERNAL_SIG]);
    hasher.input(left.hash.as_slice());
    // if there is no right node, we hash left with itself
    hasher.input(left.hash.as_slice());
    hasher.result(result.as_mut_slice());

    Node { hash: result, left: Some(Box::new(left)), right: None }
}

fn build_internal_node<H>(left: Node, right: Node, hasher: &mut H) -> Node
    where H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[INTERNAL_SIG]);
    hasher.input(left.hash.as_slice());
    hasher.input(right.hash.as_slice());
    hasher.result(result.as_mut_slice());

    Node { hash: result, left: Some(Box::new(left)), right: Some(Box::new(right)) }
}

fn build_upper_level<H>(nodes: &mut Vec<Node>, hasher: &mut H) -> Vec<Node>
    where H: Digest
{
    let mut row = Vec::with_capacity((nodes.len() + 1) / 2);
    while nodes.len() > 0 {
        if nodes.len() > 1 {
            let n1 = nodes.remove(0);
            let n2 = nodes.remove(0);
            row.push(build_internal_node(n1, n2, hasher));
        } else {
            row.push(build_internal_node_with_one_child(nodes.remove(0), hasher));
        }
    }
    row
}

fn build_from_leaves<H>(mut leaves: Vec<Node>, hasher: &mut H) -> Node
    where H: Digest
{
    let mut parents = build_upper_level(&mut leaves, hasher);

    while parents.len() > 1 {
        parents = build_upper_level(&mut parents, hasher);
    }

    parents.remove(0)
}

impl<H> MerkleTree<H>
{
    /// Constructs a tree from values of data. Data could be anything as long as it could be
    /// represented as bytes array.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World";
    /// let _t: MerkleTree = MerkleTree::build(&[block, block]);
    /// ```
    pub fn build<T>(values: &[T]) -> MerkleTree<H>
        where H: Digest + Default, T: AsBytes + fmt::Debug
    {
        let mut hasher = Default::default();
        MerkleTree::build_with_hasher(values, hasher)
    }

    /// Hasher could be any object, which implements `crypto::digest::Digest` trait. You could
    /// write your own hasher if you want specific behaviour (e.g. double SHA256).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[macro_use] extern crate crypto;
    /// # #[macro_use] extern crate merkle_tree;
    /// # fn main() {
    ///     use merkle_tree::MerkleTree;
    ///     use crypto::sha2::Sha512;
    ///     type MT = MerkleTree<Sha512>;
    ///
    ///     let block = "Hello World";
    ///     let _t: MT = MT::build_with_hasher(&[block, block], Sha512::new());
    /// }
    /// ```
    pub fn build_with_hasher<T>(values: &[T], mut hasher: H) -> MerkleTree<H>
        where H: Digest, T: AsBytes + fmt::Debug
    {
        let count_values = values.len();
        assert!(count_values > 1, format!("expected more then 1 value, received {}", count_values));

        let leaves: Vec<Node> = values.iter().map(|v| build_leaf_node(v, &mut hasher)).collect();

        MerkleTree {
            root: build_from_leaves(leaves, &mut hasher),
            hasher: hasher,
        }
    }

    /// Returns root hash of the tree.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World";
    /// let t: MerkleTree = MerkleTree::build(&[block, block]);
    /// assert!(t.root_hash().len() > 0);
    /// ```
    pub fn root_hash(&self) -> Vec<u8> {
        self.root.hash.clone()
    }

    /// Returns root hash of the tree as string.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World";
    /// let t: MerkleTree = MerkleTree::build(&[block, block]);
    /// assert_ne!("", t.root_hash_str());
    /// ```
    pub fn root_hash_str(&self) -> String {
        self.root.hash_str()
    }
}

/// The default [`Hasher`] used by [`MerkleTree`].
pub struct DefaultHasher(Sha256);

impl DefaultHasher {
    /// Creates a new `DefaultHasher`.
    pub fn new() -> DefaultHasher {
        DefaultHasher(Sha256::new())
    }
}

/// Implementation of the Default trait from std library
impl Default for DefaultHasher {
    /// Creates a new `DefaultHasher` using [`DefaultHasher::new`]. See
    /// [`DefaultHasher::new`] documentation for more information.
    ///
    /// [`DefaultHasher::new`]: #method.new
    fn default() -> DefaultHasher {
        DefaultHasher::new()
    }
}

/// Implementation of the Digest trait from crypto library for our DefaultHasher
impl Digest for DefaultHasher {
    #[inline]
    fn input(&mut self, d: &[u8]) {
        self.0.input(d)
    }

    #[inline]
    fn result(&mut self, out: &mut [u8]) {
        self.0.result(out)
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset()
    }

    #[inline]
    fn output_bits(&self) -> usize {
        self.0.output_bits()
    }

    #[inline]
    fn block_size(&self) -> usize {
        self.0.block_size()
    }
}

pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl<'a> AsBytes for &'a str {
    fn as_bytes(&self) -> &[u8] {
        str::as_bytes(&self)
    }
}

impl AsBytes for String {
    fn as_bytes(&self) -> &[u8] {
        String::as_bytes(&self)
    }
}

impl<'a> AsBytes for &'a [u8] {
    fn as_bytes(&self) -> &[u8] {
        *self
    }
}

impl fmt::Debug for Node
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_leaf() {
            write!(f, "{:?}", self.hash_str())
        } else {
            write!(f, "{:?}: (l: {:?}, r: {:?})", self.hash_str(), self.left, self.right)
        }
    }
}

#[cfg(test)]
mod test_tree {
    use super::MerkleTree;
    use super::crypto::sha2::Sha256;

    #[test]
    #[should_panic]
    fn test_0_blocks() {
        let _t: MerkleTree = MerkleTree::build::<String>(&[]);
    }

    #[test]
    fn test_odd_number_of_blocks() {
        let block = "Hello World";
        let _t: MerkleTree = MerkleTree::build(&[block, block, block]);
    }

    #[test]
    fn test_even_number_of_blocks() {
        let block = "Hello World";
        let _t: MerkleTree = MerkleTree::build(&[block, block, block, block]);
    }

    #[test]
    fn test_hash_stays_the_same_if_data_hasnt_been_changed() {
        let block = "Hello World";
        let t: MerkleTree = MerkleTree::build(&[block, block]);
        // root hash should stay the same if data hasn't been changed
        assert_eq!("c9978dc3e2d729207ca4c012de993423f19e7bf02161f7f95cdbf28d1b57b88a", t.root_hash_str());
    }
}
