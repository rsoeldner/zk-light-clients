// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::hash::HashValue;
use thiserror::Error;

/// Errors possible during type manipulation.
#[derive(Debug, Error)]
pub enum TypesError {
    #[error("Failed to deserialize {structure}: {source}")]
    DeserializationError {
        structure: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Failed to convert {from} to {to}: {source}")]
    ConversionError {
        from: String,
        to: String,
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Received data of invalid length for {structure}. Expected {expected}, got {actual}.")]
    InvalidLength {
        structure: String,
        expected: usize,
        actual: usize,
    },
    #[error("Received too much data to deserialize {structure}. Maximum {maximum}, got {actual}.")]
    OverLength {
        structure: String,
        maximum: usize,
        actual: usize,
    },
    #[error(
        "Received too little data to deserialize {structure}. Minimum {minimum}, got {actual}."
    )]
    UnderLength {
        structure: String,
        minimum: usize,
        actual: usize,
    },
}

/// Macro to create a `TypesError::DeserializationError` with the given structure and source.
#[macro_export]
macro_rules! deserialization_error {
    ($structure:expr, $source:expr) => {
        TypesError::DeserializationError {
            structure: String::from($structure),
            source: $source.into(),
        }
    };
}

/// Errors possible while validating data.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid base64 string, error while trying to decode it: {source}")]
    InvalidBase64 {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error("Target for block was not reached: expected less or equal than {target} got {hash}")]
    TargetNotMet { target: String, hash: String },
    #[error("Error while trying to set chain block header: currently handling {size} chains, got chain {chain}"
    )]
    NonValidChain { size: usize, chain: usize },
    #[error("Error while trying to set chain block header: expected block height {expected}, got {actual} "
    )]
    DifferentHeight { expected: usize, actual: usize },
    #[error("Error while trying to compute a hash: {source}")]
    HashError {
        #[source]
        source: Box<dyn std::error::Error + Sync + Send>,
    },
    #[error(
        "Expected at least 3 layer block headers  and an odd total number of elements. Got {size}"
    )]
    InvalidLayerBlockHeadersList { size: usize },
    #[error("Expects at least 1 layer block headers.")]
    InvalidChainBlockHeadersList,
    #[error(
        "Invalid chain block height. Got layer height {layer_height}, chain height {chain_height}"
    )]
    InvalidChainBlockHeight {
        layer_height: u64,
        chain_height: u64,
    },
    #[error("Invalid chain block hash. Computed: {computed}, stored: {stored}")]
    InvalidChainBlockHash {
        computed: HashValue,
        stored: HashValue,
    },
    #[error("Invalid chain block parent hash. Computed: {computed}, stored: {stored}")]
    InvalidParentHash {
        computed: HashValue,
        stored: HashValue,
    },
    #[error("Missing parent hash in the chain block header list at index {index}")]
    MissingParentHeader { index: usize },
    #[error("Invalid position value in Merkle Proof. Expected 0 or 1, got {value}")]
    InvalidPosition { value: u8 },
    #[error("Error in adjacent parent chain records at layer height {layer}, chain {chain}")]
    InvalidAdjacentChainRecords { chain: usize, layer: usize },
    #[error("Expected the block height to be a multiple of {epoch_length}, got {height}")]
    InvalidEpochStartHeight { height: u64, epoch_length: u64 },
    #[error("Invalid difficulty adjustment for a new epoch.")]
    InvalidDifficultyAdjustment,
    #[error("Invalid number of chain. Expected {expected}, got {actual} ")]
    InvalidChainNumber { expected: usize, actual: usize },
}
