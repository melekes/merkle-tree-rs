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

use crypto::digest::Digest;
use crypto::sha2::Sha256;

const LEAF_SIG: u8 = 0u8;
const INTERNAL_SIG: u8 = 1u8;

#[derive(Debug)]
struct Node {
    hash: Vec<u8>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

pub struct MerkleTree<H = DefaultHasher> {
    hasher: H,
    root: Node,
    // we need to store read-only links to leafs in order to implement contains API
    // leaves: &'a [&'a Node<'a>],
}

fn build_leaf_node<H>(block: &[u8], hasher: &mut H) -> Node
    where H: Digest
{
    let mut block_hash = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(block);
    hasher.result(block_hash.as_mut_slice());

    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[LEAF_SIG]);
    hasher.input(block_hash.as_slice());
    hasher.result(result.as_mut_slice());

    Node { hash: result, left: None, right: None }
}

fn build_internal_node_with_one_child<H>(child: Node, hasher: &mut H) -> Node
    where H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[INTERNAL_SIG]);
    hasher.input(child.hash.as_slice());
    hasher.result(result.as_mut_slice());

    Node { hash: result, left: Some(Box::new(child)), right: None }
}

fn build_internal_node<H>(child1: Node, child2: Node, hasher: &mut H) -> Node
    where H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[INTERNAL_SIG]);
    hasher.input(child1.hash.as_slice());
    hasher.input(child2.hash.as_slice());
    hasher.result(result.as_mut_slice());

    Node { hash: result, left: Some(Box::new(child1)), right: Some(Box::new(child2)) }
}

fn build_upper_level<H>(nodes: &mut Vec<Node>, hasher: &mut H) -> Vec<Node>
    where H: Digest
{
    // 7 / 2 = 3. We could have applied ceil here, but adding `1` is much easier
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
    /// Constructs a tree from blocks of data. Data could be anything as long as it could be
    /// represented as bytes array.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World".as_bytes();
    /// let _t: MerkleTree = MerkleTree::build_from_blocks(&[&block, &block]);
    /// ```
    pub fn build_from_blocks(blocks: &[&[u8]]) -> MerkleTree<H>
        where H: Digest + Default
    {
        let count_blocks = blocks.len();
        assert!(count_blocks > 1, format!("expected more then 1 block, received {}", count_blocks));

        let mut hasher = Default::default();
        let leaves: Vec<Node> = blocks.iter().map(|b| build_leaf_node(*b, &mut hasher)).collect();
        MerkleTree {
            // leaves: leaves.iter().map(|l| &l).collect(),
            root: build_from_leaves(leaves, &mut hasher),
            hasher: hasher
        }
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
    ///     let block = "Hello World".as_bytes();
    ///     let _t: MT = MT::build_from_blocks_with_hasher(&[&block, &block], Sha512::new());
    /// }
    /// ```
    pub fn build_from_blocks_with_hasher(blocks: &[&[u8]], mut hasher: H) -> MerkleTree<H>
        where H: Digest
    {
        let count_blocks = blocks.len();
        assert!(count_blocks > 1, format!("expected more then 1 block, received {}", count_blocks));

        let leaves: Vec<Node> = blocks.iter().map(|b| build_leaf_node(*b, &mut hasher)).collect();
        MerkleTree {
            // leaves: leaves.iter().map(|l| &l).collect().as_slice(),
            root: build_from_leaves(leaves, &mut hasher),
            hasher: hasher
        }
    }

}

/// The default [`Hasher`] used by [`MerkleTree`].
// #[derive(Debug)]
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

#[cfg(test)]
mod test_tree {
    use super::MerkleTree;
    use super::crypto::sha2::Sha256;

    #[test]
    #[should_panic]
    fn test_0_blocks() {
        let _t: MerkleTree = MerkleTree::build_from_blocks(&[]);
    }
}
