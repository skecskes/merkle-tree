use crate::merkletree::{Data, MerkleTree};

pub mod merkletree;

fn main() {
    let mut data: Vec<Data> = vec![];
    for i in 0..4 {
        data.push(vec![i as u8]);
    }
    let _mt = MerkleTree::construct(&data);
    print!("Hello World!")
}
