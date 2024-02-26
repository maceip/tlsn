
use authdecode::{
    backend::{
        halo2,
        halo2::{
            prover::Prover as Halo2ProverBackend, verifier::Verifier as Halo2VerififerBackend,
            onetimesetup::OneTimeSetup,
        },
        mock::{MockProverBackend, MockVerifierBackend},
    },
    encodings::{ActiveEncodings, Encoding, FullEncodings, ToActiveEncodings},
    prover::{
        backend::Backend as ProverBackend,
        error::ProverError,
        prover::{ProofInput, Prover},
        InitData, ToInitData,
    },
    utils::{choose, u8vec_to_boolvec},
    verifier::{backend::Backend as VerifierBackend, verifier::Verifier},
};

use std::env;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
use hex::encode;
use num::BigUint;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
const PLAINTEXT_SIZE: usize = 1000;


struct DummyEncodingsVerifier {}
    impl authdecode::prover::EncodingVerifier for DummyEncodingsVerifier {
        fn init(&self, init_data: InitData) {}

        fn verify(
            &self,
            _encodings: &FullEncodings,
        ) -> Result<(), authdecode::prover::EncodingVerifierError> {
            Ok(())
        }
    }


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();
        env::set_var("RAYON_NUM_THREADS", "1");
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        let plaintext: Vec<u8> = core::iter::repeat_with(|| rng.gen::<u8>())
        .take(PLAINTEXT_SIZE)
        .collect();

        let full_encodings: Vec<[u128; 2]> = core::iter::repeat_with(|| rng.gen::<[u128; 2]>())
        .take(PLAINTEXT_SIZE * 8)
        .collect();
    let full_encodings = full_encodings
        .into_iter()
        .map(|pair| {
            [
                Encoding::new(BigUint::from(pair[0])),
                Encoding::new(BigUint::from(pair[1])),
            ]
        })
        .collect::<Vec<_>>();
    let full_encodings = FullEncodings::new(full_encodings);

    // Prover's active encodings.
    let active_encodings = full_encodings.encode(&u8vec_to_boolvec(&plaintext));

    let params = OneTimeSetup::params();
    let proving_key = OneTimeSetup::proving_key(params.clone());
    let verification_key = OneTimeSetup::verification_key(params);



    let h2proverBackend = Halo2ProverBackend::new(proving_key);
    let h2verifierBackend = Halo2VerififerBackend::new(verification_key);

    let prover = Prover::new(Box::new(h2proverBackend));
    let verifier = Verifier::new(Box::new(h2verifierBackend));


    let (prover, commitments) = prover.commit(vec![(plaintext, active_encodings)]).unwrap();

    let (verifier, verification_data) = verifier
    .receive_commitments(
        commitments,
        vec![full_encodings.clone()],
        InitData::new(vec![1u8; 100]),
    )
    .unwrap();

let prover = prover
    .check(verification_data, DummyEncodingsVerifier {})
    .unwrap();

let (prover, proof_sets) = prover.prove().unwrap();

let verifier = verifier.verify(proof_sets).unwrap();

}