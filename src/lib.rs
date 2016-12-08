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

const LEAF_SIG_TYPE: u8 = 0u8;
const INTERNAL_SIG_TYPE: u8 = 1u8;

enum NodeType {
    Leaf,
    Internal
}

struct Node {
    hash: *const [u8],
    _type: NodeType,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

pub struct MerkleTree<H = DefaultHasher> {
    hasher: H,
    root: Node,
    leaves: Vec<Node>,
}

fn build_from_leaves(leaves: &Vec<Node>) -> Node {
    // let mut iter = leaves.iter().take(2);
    // for chunk in leaves.chunks(2) {
    //     if chunk.size() == 2 {
    //         chunk[0]
    //     } else {

    //     }


    // }
    Node { hash: &[0u8], _type: NodeType::Internal, left: None, right: None }
}

impl<H> MerkleTree<H>
{
    /// Constructs a tree from the leaves. Primary usage would be to compute hashes of data blocks (or
    /// files) and pass them as `raw_leaves`.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let t: MerkleTree = MerkleTree::from_leaves(&[&[1u8]]);
    /// ```
    pub fn from_leaves(raw_leaves: &[&[u8]]) -> MerkleTree<H>
        where H: Digest + Default
    {
        let leaves: Vec<Node> = raw_leaves.iter().map(|l| Node { hash: *l, _type: NodeType::Leaf, left: None, right: None }).collect();
        MerkleTree {
            hasher: Default::default(),
            root: build_from_leaves(&leaves),
            leaves: leaves
        }
    }

    /// Hasher could be any object, which implements `crypto::digest::Digest` trait. You could
    /// write your own hasher if you want specific behaviour (double SHA256).
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
    ///     let t: MT = MT::from_leaves_with_hasher(&[&[1u8]], Sha512::new());
    /// }
    /// ```
    pub fn from_leaves_with_hasher(raw_leaves: &[&[u8]], hasher: H) -> MerkleTree<H>
        where H: Digest
    {
        let leaves: Vec<Node> = raw_leaves.iter().map(|l| Node { hash: *l, _type: NodeType::Leaf, left: None, right: None }).collect();
        MerkleTree {
            hasher: hasher,
            root: build_from_leaves(&leaves),
            leaves: leaves
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

impl Default for DefaultHasher {
    /// Creates a new `DefaultHasher` using [`DefaultHasher::new`]. See
    /// [`DefaultHasher::new`] documentation for more information.
    ///
    /// [`DefaultHasher::new`]: #method.new
    fn default() -> DefaultHasher {
        DefaultHasher::new()
    }
}

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
    fn test_build_from_leaves() {
    }
}
