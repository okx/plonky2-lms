use crate::keygen;
use crate::signature::SignerMut;
use crate::util::helper::test_helper::gen_random_seed;

use crate::{HssParameter, LmotsAlgorithm, LmsAlgorithm, Poseidon256_256, Signature, VerifyingKey};
use plonky2::field::extension::Extendable;

use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use self::constants::{D, F};
use self::lms::{
    build_lms_verify_circuit, LmsPublicKeyProvingInput, LmsPublicKeyTarget,
    LmsSignatureProvingInput, LmsSignatureTarget, MessageProvingInput, MessageTarget,
};

pub mod constants;
mod lm_ots;
mod lms;
mod utils;

/// Keygen and Signing always in Rust, outside zk circuits
pub fn keygen_sign(message: &[u8]) -> (VerifyingKey<Poseidon256_256>, Signature) {
    let seed = gen_random_seed::<Poseidon256_256>();
    let (mut signing_key, verifying_key) = keygen::<Poseidon256_256>(
        &[HssParameter::new(
            LmotsAlgorithm::LmotsW1,
            LmsAlgorithm::LmsH10,
        )],
        &seed,
        None,
    )
    .unwrap();

    let signature = signing_key.try_sign(message).unwrap();

    (verifying_key, signature)
}

/// Verify HSS signature in plonky2 circuit
pub fn circuit_verify(
    builder: &mut CircuitBuilder<F, D>,
    pw: &mut PartialWitness<F>,
    message: &[u8; 32],
    hss_pubkey: &VerifyingKey<Poseidon256_256>,
    hss_sig: &Signature,
) {
    // Currently only implement LMS in circuit, we decode HSS pk and signature in Rust
    // HSS Level L = 1
    let lms_signature = LmsSignatureProvingInput::<F, D>::new(&hss_sig);
    let lms_pubkey = LmsPublicKeyProvingInput::<F, D>::new(&hss_pubkey);
    let lms_message: MessageProvingInput<F, D> = MessageProvingInput::new(&message);
    let inputs = VerifyProvingInputs {
        message: lms_message,
        lms_signature,
        lms_pubkey,
    };
    let targets = VerifyTargets::new::<F, D>(builder);
    targets.set_proving_inputs(pw, &inputs);
}

#[derive(Debug)]
pub struct VerifyTargets {
    pub message: MessageTarget,
    pub lms_signature: LmsSignatureTarget,
    pub lms_pubkey: LmsPublicKeyTarget,
}

impl VerifyTargets {
    /// Build LMS signature verification circuit
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> VerifyTargets {
        let message = MessageTarget::new(builder);
        let lms_signature = LmsSignatureTarget::new(builder);
        let lms_pubkey = LmsPublicKeyTarget::new(builder);
        build_lms_verify_circuit(builder, &lms_signature, &lms_pubkey, &message);

        VerifyTargets {
            message,
            lms_signature,
            lms_pubkey,
        }
    }
    pub fn set_proving_inputs<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        proving_input: &VerifyProvingInputs<F, D>,
    ) {
        self.message.set_proving_inputs(pw, &proving_input.message);
        self.lms_signature
            .set_proving_inputs(pw, &proving_input.lms_signature);
        self.lms_pubkey
            .set_proving_inputs(pw, &proving_input.lms_pubkey);
    }
}

#[derive(Debug)]
pub struct VerifyProvingInputs<F: RichField + Extendable<D>, const D: usize> {
    pub message: MessageProvingInput<F, D>,
    pub lms_signature: LmsSignatureProvingInput<F, D>,
    pub lms_pubkey: LmsPublicKeyProvingInput<F, D>,
}

#[cfg(test)]
mod tests {
    use signature::Verifier;

    use self::utils::test_util::run_circuit_test;

    use super::*;

    const MESSAGE: [u8; 32] = [42u8; 32];

    #[test]
    fn test_circuit_verify() {
        let (hss_pubkey, hss_sig) = keygen_sign(&MESSAGE);
        run_circuit_test(|builder, pw| {
            circuit_verify(builder, pw, &MESSAGE, &hss_pubkey, &hss_sig);
        })
    }

    #[test]
    fn test_rust_verify() {
        let (verifying_key, signature) = keygen_sign(&MESSAGE);
        assert!(verifying_key.verify(&MESSAGE, &signature).is_ok());
    }
}
