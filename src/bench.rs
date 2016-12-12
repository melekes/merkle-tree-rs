#![cfg(test)]

extern crate test;

use self::test::Bencher;

use std::iter;
use super::MerkleTree;

#[bench]
fn build(b: &mut Bencher) {
    let block = "Hello World";
    let blocks: Vec<&str> = iter::repeat(block).take(100).collect();

    b.iter(|| {
        let n = test::black_box(100);
        for _i in 0..n {
            let _t: MerkleTree = MerkleTree::build(blocks.as_slice());
        }
    });
}
