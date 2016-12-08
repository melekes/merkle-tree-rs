/// Merkle Tree implementation, implemented as a binary tree

extern crate crypto;

use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;

struct Node {
    hash: *const [u8],
    left: *mut Node,
    right: *mut Node,
}

struct MerkleTree<H = DefaultHasher> {
    hasher: H,
    root: Node,
}

impl<H> MerkleTree<H>
    where H: Digest
{
    fn new(root: Node) -> MerkleTree<H>
        where H: Default
    {
        MerkleTree {
            hasher: Default::default(),
            root: root,
        }
    }

    fn with_hasher(root: Node, hasher: H) -> MerkleTree<H> {
        MerkleTree {
            hasher: hasher,
            root: root,
        }
    }
}

/// The default [`Hasher`] used by [`MerkleTree`].
#[derive(Debug)]
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
        let t = MerkleTree::new(Node {});
    }
}
