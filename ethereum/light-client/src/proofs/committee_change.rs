// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Sync Committee Prover module
//!
//! This module provides the prover implementation for the sync committee change proof. The prover
//! is responsible for generating, executing, proving, and verifying proofs for the light client.

use crate::proofs::error::ProverError;
use crate::proofs::{ProofType, Prover, ProvingMode};
use anyhow::Result;
use ethereum_lc_core::crypto::hash::HashValue;
use ethereum_lc_core::deserialization_error;
use ethereum_lc_core::types::error::TypesError;
use ethereum_lc_core::types::store::LightClientStore;
use ethereum_lc_core::types::update::Update;
use ethereum_lc_core::types::utils::{extract_u32, OFFSET_BYTE_LENGTH};
use ethereum_programs::COMMITTEE_CHANGE_PROGRAM;
use getset::CopyGetters;
use sphinx_sdk::{
    ProverClient, SphinxProvingKey, SphinxPublicValues, SphinxStdin, SphinxVerifyingKey,
};

/// The prover for the sync committee change proof.
pub struct CommitteeChangeProver {
    client: ProverClient,
    keys: (SphinxProvingKey, SphinxVerifyingKey),
}

impl Default for CommitteeChangeProver {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitteeChangeProver {
    /// Create a new `CommitteeChangeProver`.
    ///
    /// # Returns
    ///
    /// A new `CommitteeChangeProver`.
    pub fn new() -> Self {
        let client = ProverClient::new();
        let keys = client.setup(COMMITTEE_CHANGE_PROGRAM);

        Self { client, keys }
    }

    /// Gets a `SphinxVerifyingKey`.
    ///
    /// # Returns
    ///
    /// A `SphinxVerifyingKey` that can be used for verifying the committee-change proof.
    pub const fn get_vk(&self) -> &SphinxVerifyingKey {
        &self.keys.1
    }
}

/// The input for the sync committee change proof.
#[derive(Debug, Eq, PartialEq)]
pub struct CommitteeChangeIn {
    store: LightClientStore,
    update: Update,
}

impl CommitteeChangeIn {
    /// Create a new `CommitteeChangeIn`.
    ///
    /// # Arguments
    ///
    /// * `store` - The `LightClientStore` that wil be passed to the program.
    /// * `update` - The `Update` that will be passed to the program.
    ///
    /// # Returns
    ///
    /// A new `CommitteeChangeIn`.
    pub const fn new(store: LightClientStore, update: Update) -> Self {
        Self { store, update }
    }

    /// Serialize the `CommitteeChangeIn` struct to SSZ bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the SSZ serialized `CommitteeChangeIn` struct.
    pub fn to_ssz_bytes(&self) -> Result<Vec<u8>, TypesError> {
        let mut bytes = vec![];

        let store_offset: u32 = (OFFSET_BYTE_LENGTH * 2) as u32;
        let store_bytes = self.store.to_ssz_bytes()?;
        bytes.extend_from_slice(&store_offset.to_le_bytes());

        let update_offset = store_offset + store_bytes.len() as u32;
        let update_bytes = self.update.to_ssz_bytes()?;
        bytes.extend_from_slice(&update_offset.to_le_bytes());

        bytes.extend_from_slice(&store_bytes);
        bytes.extend_from_slice(&update_bytes);

        Ok(bytes)
    }

    /// Deserialize a `CommitteeChangeIn` struct from SSZ bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The SSZ encoded bytes.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the deserialized `CommitteeChangeIn` struct or a `TypesError`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, TypesError> {
        let cursor = 0;
        let (cursor, store_offset) = extract_u32("CommmitteeChangeIn", bytes, cursor)?;
        let (cursor, update_offset) = extract_u32("CommmitteeChangeIn", bytes, cursor)?;

        // Deserialize the Light Client store
        if cursor != store_offset as usize {
            return Err(deserialization_error!(
                "CommmitteeChangeIn",
                "Invalid offset for store"
            ));
        }
        let store = LightClientStore::from_ssz_bytes(&bytes[cursor..update_offset as usize])?;

        // Deserialize the Update
        let update = Update::from_ssz_bytes(&bytes[update_offset as usize..])?;

        Ok(Self { store, update })
    }
}

/// The output for the sync committee change proof.
#[derive(Debug, Clone, Copy, CopyGetters)]
#[getset(get_copy = "pub")]
pub struct CommitteeChangeOut {
    finalized_block_height: u64,
    signer_sync_committee: HashValue,
    new_sync_committee: HashValue,
    new_next_sync_committee: HashValue,
}

impl From<&mut SphinxPublicValues> for CommitteeChangeOut {
    fn from(public_values: &mut SphinxPublicValues) -> Self {
        let finalized_block_height = public_values.read::<u64>();
        let signer_sync_committee = HashValue::new(public_values.read::<[u8; 32]>());
        let new_sync_committee = HashValue::new(public_values.read::<[u8; 32]>());
        let new_next_sync_committee = HashValue::new(public_values.read::<[u8; 32]>());

        Self {
            finalized_block_height,
            signer_sync_committee,
            new_sync_committee,
            new_next_sync_committee,
        }
    }
}

impl Prover for CommitteeChangeProver {
    const PROGRAM: &'static [u8] = COMMITTEE_CHANGE_PROGRAM;
    type Error = ProverError;
    type StdIn = CommitteeChangeIn;
    type StdOut = CommitteeChangeOut;

    fn generate_sphinx_stdin(&self, inputs: &Self::StdIn) -> Result<SphinxStdin, Self::Error> {
        let mut stdin = SphinxStdin::new();
        stdin.write(
            &inputs
                .store
                .to_ssz_bytes()
                .map_err(|err| ProverError::SphinxInput { source: err.into() })?,
        );
        stdin.write(
            &inputs
                .update
                .to_ssz_bytes()
                .map_err(|err| ProverError::SphinxInput { source: err.into() })?,
        );
        Ok(stdin)
    }

    fn execute(&self, inputs: &Self::StdIn) -> Result<Self::StdOut, Self::Error> {
        sphinx_sdk::utils::setup_logger();

        let stdin = self.generate_sphinx_stdin(inputs)?;

        let (mut public_values, _) = self
            .client
            .execute(Self::PROGRAM, stdin)
            .run()
            .map_err(|err| ProverError::Execution { source: err.into() })?;

        Ok(CommitteeChangeOut::from(&mut public_values))
    }

    fn prove(&self, inputs: &Self::StdIn, mode: ProvingMode) -> Result<ProofType, Self::Error> {
        let stdin = self.generate_sphinx_stdin(inputs)?;

        match mode {
            ProvingMode::STARK => self
                .client
                .prove(&self.keys.0, stdin)
                .run()
                .map_err(|err| ProverError::Proving {
                    proof_type: mode.into(),
                    source: err.into(),
                })
                .map(ProofType::STARK),
            ProvingMode::SNARK => self
                .client
                .prove(&self.keys.0, stdin)
                .plonk()
                .run()
                .map_err(|err| ProverError::Proving {
                    proof_type: mode.into(),
                    source: err.into(),
                })
                .map(ProofType::SNARK),
        }
    }

    fn verify(&self, proof: &ProofType) -> Result<(), Self::Error> {
        let vk = &self.keys.1;

        match proof {
            ProofType::STARK(proof) => self
                .client
                .verify(proof, vk)
                .map_err(|err| ProverError::Verification { source: err.into() }),
            ProofType::SNARK(proof) => self
                .client
                .verify(proof, vk)
                .map_err(|err| ProverError::Verification { source: err.into() }),
        }
    }
}

#[cfg(all(test, feature = "ethereum"))]
mod test {
    use super::*;
    use crate::test_utils::generate_committee_change_test_assets;
    use ethereum_lc_core::crypto::hash::keccak256_hash;

    #[test]
    fn test_execute_committee_change() {
        let mut test_assets = generate_committee_change_test_assets();

        test_assets
            .store
            .process_light_client_update(&test_assets.update)
            .unwrap();

        let prover = CommitteeChangeProver::new();

        let new_period_inputs = CommitteeChangeIn {
            store: test_assets.store.clone(),
            update: test_assets.update_new_period.clone(),
        };

        let new_period_output = prover.execute(&new_period_inputs).unwrap();

        assert_eq!(
            &new_period_output.finalized_block_height,
            test_assets
                .update_new_period
                .finalized_header()
                .beacon()
                .slot()
        );
        assert_eq!(
            new_period_output.signer_sync_committee,
            keccak256_hash(&test_assets.store.current_sync_committee().to_ssz_bytes()).unwrap()
        );
        assert_eq!(
            new_period_output.new_sync_committee,
            keccak256_hash(
                &test_assets
                    .store
                    .next_sync_committee()
                    .clone()
                    .unwrap()
                    .to_ssz_bytes()
            )
            .unwrap()
        );
        assert_eq!(
            new_period_output.new_next_sync_committee,
            keccak256_hash(
                &test_assets
                    .update_new_period
                    .next_sync_committee()
                    .to_ssz_bytes()
            )
            .unwrap()
        );
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_stark_committee_change() {
        use std::time::Instant;

        let mut test_assets = generate_committee_change_test_assets();

        test_assets
            .store
            .process_light_client_update(&test_assets.update)
            .unwrap();

        let prover = CommitteeChangeProver::new();

        let new_period_inputs = CommitteeChangeIn {
            store: test_assets.store.clone(),
            update: test_assets.update_new_period.clone(),
        };

        println!("Starting STARK proving for sync committee change...");
        let start = Instant::now();

        let _ = prover
            .prove(&new_period_inputs, ProvingMode::STARK)
            .unwrap();
        println!("Proving took {:?}", start.elapsed());
    }

    #[test]
    #[ignore = "This test is too slow for CI"]
    fn test_prove_snark_committee_change() {
        use std::time::Instant;

        let mut test_assets = generate_committee_change_test_assets();

        test_assets
            .store
            .process_light_client_update(&test_assets.update)
            .unwrap();

        let prover = CommitteeChangeProver::new();

        let new_period_inputs = CommitteeChangeIn {
            store: test_assets.store.clone(),
            update: test_assets.update_new_period.clone(),
        };

        println!("Starting SNARK proving for sync committee change...");
        let start = Instant::now();

        let _ = prover
            .prove(&new_period_inputs, ProvingMode::SNARK)
            .unwrap();
        println!("Proving took {:?}", start.elapsed());
    }
}
