use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::NBR_VALIDATORS;
use serde::Serialize;
use std::hint::black_box;
use std::time::Instant;
use wp1_sdk::{ProverClient, SP1Proof, SP1Stdin};

struct ProvingAssets {
    client: ProverClient,
    ledger_info_with_signature: Vec<u8>,
}

impl ProvingAssets {
    fn new() -> Self {
        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, NBR_VALIDATORS).unwrap();
        aptos_wrapper.generate_traffic().unwrap();
        aptos_wrapper.commit_new_epoch().unwrap();

        let ledger_info_with_signature = aptos_wrapper.get_latest_li_bytes().unwrap();

        let client = ProverClient::new();

        Self {
            client,
            ledger_info_with_signature,
        }
    }

    fn prove(&self) -> SP1Proof {
        let mut stdin = SP1Stdin::new();

        stdin.write(&self.ledger_info_with_signature);

        let (pk, _) = self.client.setup(aptos_programs::bench::BYTES);
        self.client.prove(&pk, stdin).unwrap()
    }

    fn verify(&self, proof: &SP1Proof) {
        let (_, vk) = self.client.setup(aptos_programs::bench::BYTES);
        self.client.verify(proof, &vk).expect("Verification failed");
    }
}

#[derive(Serialize)]
struct Timings {
    proving_time: u128,
    verifying_time: u128,
}

fn main() {
    let proving_assets = ProvingAssets::new();

    let start_prove = Instant::now();
    let proof = proving_assets.prove();
    let proving_time = start_prove.elapsed();

    let start_verify = Instant::now();
    proving_assets.verify(black_box(&proof));
    let verifying_time = start_verify.elapsed();

    // Print results in JSON format.
    let timings = Timings {
        proving_time: proving_time.as_millis(),
        verifying_time: verifying_time.as_millis(),
    };

    let json_output = serde_json::to_string(&timings).unwrap();
    println!("{}", json_output);
}