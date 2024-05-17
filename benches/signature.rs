use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use hbs_lms::signature::Verifier;
use hbs_lms::{
    keygen, HashChain, HssParameter, LmotsAlgorithm, LmsAlgorithm, Poseidon256_256, Seed,
    Sha256_256,
};
use hbs_lms::{signature::SignerMut, SigningKey, VerifyingKey};
use hbs_lms::circuits::{keygen_sign, circuit_verify};
use rand::{rngs::OsRng, RngCore};

const MESSAGE: [u8; 32] = [42u8; 32];
const LMOTS_PARAMS: [LmotsAlgorithm; 4] = [
    LmotsAlgorithm::LmotsW1,
    LmotsAlgorithm::LmotsW2,
    LmotsAlgorithm::LmotsW4,
    LmotsAlgorithm::LmotsW8,
];
const LMS_PARAMS: [LmsAlgorithm; 1] = [LmsAlgorithm::LmsH10];

fn bench_keygen<H: HashChain>(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen_".to_owned() + H::NAME);
    group.sample_size(10);

    for &lms in LMS_PARAMS.iter() {
        for &lmots in LMOTS_PARAMS.iter() {
            group.bench_function(format!("{:?}{:?}", lms, lmots), |b| {
                b.iter(|| {
                    generate_key::<H>(&[HssParameter::new(lmots, lms)], None);
                })
            });
        }
    }
    group.finish();
}

fn bench_sign<H: HashChain>(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_".to_owned() + H::NAME);
    group.sample_size(10);

    for &lms in LMS_PARAMS.iter() {
        for &lmots in LMOTS_PARAMS.iter() {
            let (mut signing_key, _) = generate_key::<H>(&[HssParameter::new(lmots, lms)], None);
            group.bench_function(format!("{:?}{:?}", lms, lmots), |b| {
                b.iter(|| {
                    signing_key.try_sign(&MESSAGE).unwrap();
                })
            });
        }
    }
    group.finish();
}

fn bench_verify<H: HashChain>(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_".to_owned() + H::NAME);
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for &lms in LMS_PARAMS.iter() {
        for &lmots in LMOTS_PARAMS.iter() {
            group.bench_function(format!("{:?}{:?}", lms, lmots), |b| {
                let (mut signing_key, verifying_key) =
                    generate_key::<H>(&[HssParameter::new(lmots, lms)], None);
                let sig = signing_key.try_sign(&MESSAGE).unwrap();
                b.iter(|| {
                    verifying_key.verify(&MESSAGE, &sig).unwrap();
                })
            });
        }
    }
    group.finish();
}

fn bench_zk_verify_poseidon256_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("zk_verify_poseidon256_256");
    group.sample_size(10);
    let (verifying_key, signature) = keygen_sign(&MESSAGE);
    group.bench_function("h10w1", |b| {
        b.iter(|| {
            verify_in_zk_circuit(&MESSAGE, &verifying_key, &signature);
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_keygen::<Sha256_256>,
    bench_keygen::<Poseidon256_256>,
    bench_sign::<Sha256_256>,
    bench_sign::<Poseidon256_256>,
    bench_verify::<Sha256_256>,
    bench_verify::<Poseidon256_256>,
    bench_zk_verify_poseidon256_256,
);
criterion_main!(benches);

fn generate_key<H: HashChain>(
    hss_parameter: &[HssParameter<H>],
    aux_data: Option<&mut &mut [u8]>,
) -> (SigningKey<H>, VerifyingKey<H>) {
    let mut seed = Seed::default();
    OsRng.fill_bytes(seed.as_mut_slice());
    let (signing_key, verfiying_key) = keygen::<H>(hss_parameter, &seed, aux_data).unwrap();
    (signing_key, verfiying_key)
}
