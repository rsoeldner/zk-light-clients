#![no_main]

use aptos_lc_core::crypto::hash::HashValue;
use aptos_lc_core::merkle::proof::SparseMerkleProof;
wp1_zkvm::entrypoint!(main);

pub fn main() {
    let sparse_merkle_proof = wp1_zkvm::io::read::<SparseMerkleProof>();
    let key = wp1_zkvm::io::read::<[u8; 32]>();
    let leaf_value_hash = wp1_zkvm::io::read::<[u8; 32]>();
    let expected_root_hash = wp1_zkvm::io::read::<[u8; 32]>();

    let reconstructed_root_hash = sparse_merkle_proof
        .verify_by_hash(
            HashValue::from_slice(expected_root_hash)
                .expect("expected_root_hash: could not use input to create HashValue"),
            HashValue::from_slice(key).expect("key: could not use input to create HashValue"),
            HashValue::from_slice(leaf_value_hash)
                .expect("leaf_value_hash: could not use input to create HashValue"),
        )
        .expect("verify_by_hash: could not verify proof");

    wp1_zkvm::io::commit(&reconstructed_root_hash);
}
