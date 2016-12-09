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

const LEAF_SIG: u8 = 0u8;
const INTERNAL_SIG: u8 = 1u8;

type Node = Vec<u8>;

pub struct MerkleTree<H = DefaultHasher> {
    hasher: H,
    nodes: Vec<Node>,
    count_internal_nodes: usize,
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

    result
}

fn build_internal_node_with_one_child<H>(child: &Node, hasher: &mut H) -> Node
    where H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[INTERNAL_SIG]);
    hasher.input(child.as_slice());
    hasher.result(result.as_mut_slice());

    result
}

fn build_internal_node<H>(child1: &Node, child2: &Node, hasher: &mut H) -> Node
    where H: Digest
{
    let mut result = vec![0u8; hasher.output_bits() / 8];

    hasher.reset();
    hasher.input(&[INTERNAL_SIG]);
    hasher.input(child1.as_slice());
    hasher.input(child2.as_slice());
    hasher.result(result.as_mut_slice());

    result
}

fn build_upper_level<H>(nodes: &[Node], hasher: &mut H) -> Vec<Node>
    where H: Digest
{
    // 7 / 2 = 3. We could have applied ceil here, but adding `1` is much easier
    let mut row = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0;
    while i < nodes.len() {
        if i+1 < nodes.len() {
            row.push(build_internal_node(&nodes[i], &nodes[i+1], hasher));
            i += 2;
        } else {
            row.push(build_internal_node_with_one_child(&nodes[i], hasher));
            i += 1;
        }
    }

    if row.len() > 1 && row.len() % 2 != 0 {
        let last_node = row.last().unwrap().clone();
        row.push(last_node);
    }

    row
}

fn build_internal_nodes<H>(nodes: &mut Vec<Node>, count_internal_nodes: usize, hasher: &mut H)
    where H: Digest
{
    let mut parents = build_upper_level(&nodes[count_internal_nodes..], hasher);

    let mut upper_level_start = count_internal_nodes - parents.len();
    let mut upper_level_end = upper_level_start + parents.len();
    nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);

    while parents.len() > 1 {
        parents = build_upper_level(parents.as_slice(), hasher);

        upper_level_start -= parents.len() - 1;
        upper_level_end = upper_level_start + parents.len();
        nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);
    }

    nodes[0] = parents.remove(0);
}

fn next_power_of_2(n: usize) -> usize {
    let mut v = n;
    v -= 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v += 1;
    v
}

fn calculate_internal_nodes_count(count_blocks: usize) -> usize {
    next_power_of_2(count_blocks) - 1
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
        let mut hasher = Default::default();
        MerkleTree::build_from_blocks_with_hasher(blocks, hasher)
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

        let count_internal_nodes = calculate_internal_nodes_count(count_blocks);

        let mut nodes = vec![Vec::new(); count_internal_nodes + count_blocks];

        // build leafs
        let mut block_idx = count_internal_nodes;
        for b in blocks {
            nodes[block_idx] = build_leaf_node(*b, &mut hasher);
            block_idx += 1;
        }

        build_internal_nodes(&mut nodes, count_internal_nodes, &mut hasher);

        MerkleTree {
            hasher: hasher,
            nodes: nodes,
            count_internal_nodes: count_internal_nodes
        }
    }


    /// Returns root hash of the tree.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World".as_bytes();
    /// let t: MerkleTree = MerkleTree::build_from_blocks(&[&block, &block]);
    /// assert!(t.root_hash().len() > 0);
    /// ```
    pub fn root_hash(&self) -> Vec<u8> {
        self.nodes[0].clone()
    }

    /// Returns root hash of the tree as string.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let block = "Hello World".as_bytes();
    /// let t: MerkleTree = MerkleTree::build_from_blocks(&[&block, &block]);
    /// assert_ne!("", t.root_hash_str());
    /// ```
    pub fn root_hash_str(&self) -> String {
        use rustc_serialize::hex::ToHex;

        self.nodes[0].clone().as_slice().to_hex()
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

    #[test]
    fn test_odd_number_of_blocks() {
        let block = "Hello World".as_bytes();
        let _t: MerkleTree = MerkleTree::build_from_blocks(&[&block, &block, &block]);
    }

    #[test]
    fn test_even_number_of_blocks() {
        let block = "Hello World".as_bytes();
        let _t: MerkleTree = MerkleTree::build_from_blocks(&[&block, &block, &block, &block]);
    }

    #[test]
    fn test_hash_stays_the_same_if_data_hasnt_been_changed() {
        let block = "Hello World".as_bytes();
        let t: MerkleTree = MerkleTree::build_from_blocks(&[&block, &block]);
        // root hash should stay the same if data hasn't been changed
        assert_eq!("6b86e6e9c1bc3f101c2ff7d686fd648e76236e9f7a9d5bc9fb997cd22ddb0c1c", t.root_hash_str());
    }
}
