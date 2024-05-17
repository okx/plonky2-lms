use itertools::Itertools;
use plonky2::hash::hash_types::HashOut;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::util::helper::read_and_advance;

use super::constants::*;
use super::lms::MessageTarget;
use super::utils::{u8_to_1f, u8_to_hashout, u8_to_hashout_array};

pub type MessageHashWithChecksum = [Target; POSEIDON_HASH_OUTPUT_SIZE_BYTES + 2];

#[derive(Debug)]
pub struct LmotsSignatureProvingInput<F: RichField + Extendable<D>, const D: usize> {
    pub lmots_parameter: F,
    pub randomizer: HashOut<F>,
    pub data: [HashOut<F>; LMOTS_HASH_CHAIN_COUNT],
}

impl<F: RichField + Extendable<D>, const D: usize> LmotsSignatureProvingInput<F, D> {
    pub fn new(data: &[u8]) -> Self {
        let mut idx = 0;
        let lmots_parameter = F::from_canonical_u32(u32::from_be_bytes(
            read_and_advance(data, 4, &mut idx).try_into().unwrap(),
        ));
        let randomizer = u8_to_hashout(read_and_advance(data, 32, &mut idx));
        let sig_data: [HashOut<F>; LMOTS_HASH_CHAIN_COUNT] = u8_to_hashout_array(&data[idx..])
            .as_slice()
            .try_into()
            .unwrap();
        Self {
            lmots_parameter,
            randomizer,
            data: sig_data,
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct LmotsSignatureTarget {
    pub lmots_parameter: Target,
    pub randomizer: HashOutTarget,
    pub data: [HashOutTarget; LMOTS_HASH_CHAIN_COUNT],
}

impl From<LmotsSignatureTarget> for Vec<Target> {
    fn from(signature: LmotsSignatureTarget) -> Vec<Target> {
        let mut result = vec![];
        result.push(signature.lmots_parameter);
        result.extend(signature.randomizer.elements);
        result.extend(signature.data.iter().map(|x| x.elements).flatten());
        result
    }
}

impl LmotsSignatureTarget {
    pub const fn size() -> usize {
        LMOTS_SIG_LEN
    }
    /// Parse LMOTS signature without checking parameters in circuit
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let target = LmotsSignatureTarget {
            lmots_parameter: builder.add_virtual_target(),
            randomizer: builder.add_virtual_hash(),
            data: builder
                .add_virtual_hashes(LMOTS_HASH_CHAIN_COUNT)
                .try_into()
                .unwrap(),
        };
        // Check: lmots_parameter
        let lmots_type = builder.constant(F::from_canonical_usize(LMOTS_TYPE));
        builder.connect(target.lmots_parameter, lmots_type);

        target
    }
    pub fn set_proving_inputs<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        proving_input: &LmotsSignatureProvingInput<F, D>,
    ) {
        pw.set_target(self.lmots_parameter, proving_input.lmots_parameter);
        pw.set_hash_target(self.randomizer, proving_input.randomizer);
        self.data
            .iter()
            .zip_eq(proving_input.data.iter())
            .for_each(|(&target, &data)| {
                pw.set_hash_target(target, data);
            });
    }
}

fn message_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lms_tree_identifier: &[Target; 2],
    lms_leaf_identifier: &Target,
    lmots_sig_randomizer: &HashOutTarget,
    message: &MessageTarget,
) -> HashOutTarget {
    let d_mesg = builder.constant(u8_to_1f(&D_MESG));
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [
            lms_tree_identifier.to_vec(),
            vec![*lms_leaf_identifier],
            vec![d_mesg],
            lmots_sig_randomizer.elements.to_vec(),
            Vec::<Target>::from(*message),
        ]
        .concat(),
    )
}

fn message_hash_with_checksum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    lms_tree_identifier: &[Target; 2],
    lms_leaf_identifier: &Target,
    lmots_sig_randomizer: &HashOutTarget,
    message: &MessageTarget,
) -> MessageHashWithChecksum {
    let message_hash = message_hash(
        builder,
        lms_tree_identifier,
        lms_leaf_identifier,
        lmots_sig_randomizer,
        message,
    );
    append_checksum(builder, message_hash)
}

fn compute_hash_chain_array<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signature: &LmotsSignatureTarget,
    lms_tree_identifier: &[Target; 2],
    lms_leaf_identifier: &Target,
    message_hash_with_checksum: &MessageHashWithChecksum,
) -> Vec<HashOutTarget> {
    let mut hash_chain_array: Vec<HashOutTarget> = vec![];

    for i in 0..LMOTS_HASH_CHAIN_COUNT {
        let a: BoolTarget = coef(builder, &message_hash_with_checksum.to_vec(), i);
        // a == 0 / 1
        let initial = signature.data[i];
        // j = a..2^w-1 = a..1
        // fix w = 1
        assert_eq!(LMOTS_WINTERNITZ, 1);
        // if a = 0: compute one hash, result = hash
        let i_target = builder.constant(F::from_canonical_usize(i));
        let j_zero = builder.zero();
        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            [
                lms_tree_identifier.to_vec(),
                vec![*lms_leaf_identifier, i_target, j_zero],
                initial.elements.to_vec(),
            ]
            .concat(),
        );
        // if a = 1: result = initial
        let result = select_hashout_target(builder, a, initial, hash);
        hash_chain_array.push(result);
    }

    hash_chain_array
}

/// Algorithm 4b: Computing a Public Key Candidate Kc from a
/// Signature, Message, Signature Typecode pubtype, and Identifiers I, q
pub fn generate_lmots_public_key_candidate<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signature: &LmotsSignatureTarget,
    lms_tree_identifier: &[Target; 2],
    lms_leaf_identifier: &Target,
    message: &MessageTarget,
) -> HashOutTarget {
    // 3. Compute the string Kc as follows:
    let message_hash_with_checksum = message_hash_with_checksum(
        builder,
        lms_tree_identifier,
        lms_leaf_identifier,
        &signature.randomizer,
        message,
    );
    let hash_chain_array = compute_hash_chain_array(
        builder,
        signature,
        lms_tree_identifier,
        lms_leaf_identifier,
        &message_hash_with_checksum,
    );
    // compute and return kc
    let d_pblc = builder.constant(u8_to_1f(&D_PBLC));
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [
            lms_tree_identifier.to_vec(),
            vec![*lms_leaf_identifier],
            vec![d_pblc],
            hash_chain_array
                .iter()
                .map(|hash| hash.elements.to_vec())
                .flatten()
                .collect(),
        ]
        .concat(),
    )
}

/// Append checksum to message hash, cast message hash unit from 8 bytes to 1 bytes
///
/// Returns: [message_hash; 32] + [checksum_high; 1] + [checksum_low; 1], all targets < 2^8
fn append_checksum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message_hash: HashOutTarget,
) -> [Target; POSEIDON_HASH_OUTPUT_SIZE_BYTES + 2] {
    let mut result: Vec<Target> = split_hashout_target_to_targets(builder, message_hash).to_vec();
    // result[32..34] = checksum
    let (checksum_low, checksum_high) = checksum(builder, &result);
    // Big endian
    result.push(checksum_high);
    result.push(checksum_low);
    result.try_into().unwrap()
}

/// message_hash_bytes elements should < 2^8
/// Return (checksum_low < 2^8, checksum_high < 2^8)
fn checksum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message_hash_bytes: &Vec<Target>,
) -> (Target, Target) {
    let mut checksum = builder.constant(F::ZERO);
    const ROUND: usize = POSEIDON_HASH_OUTPUT_SIZE_BYTES * 8 / LMOTS_WINTERNITZ;
    const MAX_WORD_SIZE: usize = 1 << LMOTS_WINTERNITZ - 1;
    for i in 0..ROUND {
        let coef = coef(builder, message_hash_bytes, i);
        // sum = sum + MAX_WORD_SIZE - coef
        checksum = builder.add_const(checksum, F::from_canonical_usize(MAX_WORD_SIZE));
        checksum = builder.sub(checksum, coef.target);
    }
    checksum = builder.mul_const(
        F::from_canonical_u32(1 << LMOTS_CHECKSUM_LEFT_SHIFT),
        checksum,
    );
    builder.split_low_high(checksum, 8, 2 * 8)
}

/// Fix w = 1, coef(string, i) is the i-th bit of string
///
/// byte_string: each Target < 2^8
///
/// Return 0 or 1
pub fn coef<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    byte_string: &Vec<Target>,
    i: usize,
) -> BoolTarget {
    assert_eq!(LMOTS_WINTERNITZ, 1);
    // Split 8 bits to 8 limbs, each limb with 1 bit
    let result_arr = builder.split_le_base::<0b10>(byte_string[i / 8], 8);
    // Big endian!
    // Since split_le_base return little endian, we should reverse the result
    let result = result_arr[7 - (i % 8)];
    BoolTarget::new_unsafe(result)
}

/// Select Gate for HashOutTarget
///
/// a == 1: return x
///
/// a == 0: return y
pub fn select_hashout_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: BoolTarget,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    let not_a = builder.not(a);
    // result = !a * y + a * x
    let result = y
        .elements
        .iter()
        .enumerate()
        .map(|(i, &y)| {
            let ax = builder.mul(a.target, x.elements[i]);
            builder.mul_add(not_a.target, y, ax)
        })
        .collect::<Vec<_>>();
    HashOutTarget::from_vec(result)
}

/// Split each Target into 8, big endian
///
/// [Target; 4] --> [Target; 32]
pub fn split_hashout_target_to_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    hash_out: HashOutTarget,
) -> [Target; 32] {
    let mut result = vec![];
    hash_out.elements.iter().for_each(|&target| {
        // Target -> [Target; 8]
        // Split 8 bytes to 8 limbs, each limb with 1 bytes
        let mut cur = target;
        let mut tmp_result = vec![];
        for i in 0..8 {
            let (low_byte, nxt) = builder.split_low_high(cur, 8, 64 - i * 8);
            tmp_result.push(low_byte);
            cur = nxt;
        }
        // Big endian
        tmp_result.reverse();
        result.extend(tmp_result.iter());
    });
    result.try_into().unwrap()
}
#[cfg(test)]
mod test {

    use std::u8;

    use super::*;
    use crate::circuits::constants::{D, F};
    use crate::circuits::keygen_sign;
    use crate::circuits::lms::{
        LmsPublicKeyProvingInput, LmsPublicKeyTarget, LmsSignatureProvingInput, LmsSignatureTarget,
        MessageProvingInput,
    };
    use crate::circuits::utils::test_util::run_circuit_test;
    use crate::circuits::utils::u8_to_f;
    use crate::{
        get_message_hash,
        lm_ots::verify::{generate_public_key_candidate, get_hash_chain_array},
        HashChain, InMemoryHssPublicKey, InMemoryHssSignature, InMemoryLmsSignature,
        LmotsParameter, Poseidon256_256,
    };
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::HashOut;
    use plonky2::iop::witness::WitnessWrite;

    use sha2::digest::Update;

    #[test]
    fn test_signature_target() {
        run_circuit_test(|builder, pw| {
            let target = LmotsSignatureTarget::new(builder);
            pw.set_target(target.lmots_parameter, F::from_canonical_usize(LMOTS_TYPE));
        })
    }

    #[test]
    #[should_panic]
    fn test_signature_target_invalid_lmots_parameter() {
        run_circuit_test(|builder, pw| {
            let target = LmotsSignatureTarget::new(builder);
            pw.set_target(target.lmots_parameter, F::from_canonical_usize(1000));
        })
    }

    #[test]
    fn test_select_hashout_target() {
        run_circuit_test(|builder, _pw| {
            let x = HashOutTarget::from_vec(vec![builder.constant(F::from_canonical_u32(10)); 4]);
            let y = HashOutTarget::from_vec(vec![builder.constant(F::from_canonical_u32(20)); 4]);
            let select_x = builder._true();
            let should_be_x = select_hashout_target(builder, select_x, x, y);
            builder.connect_hashes(should_be_x, x);
            let select_y = builder._false();
            let should_be_y = select_hashout_target(builder, select_y, x, y);
            builder.connect_hashes(should_be_y, y);
        })
    }

    #[test]
    fn test_coef() {
        run_circuit_test(|builder, _pw| {
            // Big endian
            let byte_string = vec![
                builder.constant(F::from_canonical_u8(0b01000001)),
                builder.constant(F::from_canonical_u8(0b00000001)),
            ];
            let bit_0 = coef(builder, &byte_string, 0);
            let bit_1 = coef(builder, &byte_string, 1);
            let bit_2 = coef(builder, &byte_string, 2);
            let bit_7 = coef(builder, &byte_string, 7);
            let bit_8 = coef(builder, &byte_string, 8);
            let bit_15 = coef(builder, &byte_string, 15);
            let zero = builder.zero();
            let one = builder.one();
            builder.connect(bit_0.target, zero);
            builder.connect(bit_1.target, one);
            builder.connect(bit_2.target, zero);
            builder.connect(bit_7.target, one);
            builder.connect(bit_8.target, zero);
            builder.connect(bit_15.target, one);
        });
    }

    #[test]
    fn test_generate_lmots_public_key_candidate() {
        run_circuit_test(|builder, pw| {
            let message = [0u8; 32];
            let (hss_pubkey, hss_sig) = keygen_sign(&message);
            let rust_output = {
                let hss_pubkey =
                    InMemoryHssPublicKey::<Poseidon256_256>::new(&hss_pubkey.as_slice()).unwrap();
                let hss_sig =
                    InMemoryHssSignature::<Poseidon256_256>::new(&hss_sig.as_ref()).unwrap();
                let lms_sig: InMemoryLmsSignature<'_, Poseidon256_256> = hss_sig.signature;
                let rust_result = generate_public_key_candidate::<Poseidon256_256>(
                    &lms_sig.lmots_signature,
                    &hss_pubkey.public_key.lms_tree_identifier,
                    lms_sig.lms_leaf_identifier,
                    &message,
                )
                .to_vec();
                rust_result
            };

            let message_target = MessageTarget::new(builder);
            let lms_sig_target = LmsSignatureTarget::new(builder);
            let lms_pubkey_target = LmsPublicKeyTarget::new(builder);
            let circuit_output = generate_lmots_public_key_candidate(
                builder,
                &lms_sig_target.lmots_signature,
                &lms_pubkey_target.lms_tree_identifier,
                &lms_sig_target.lms_leaf_identifier,
                &message_target,
            );
            // Set Inputs
            let message_input: MessageProvingInput<F, D> = MessageProvingInput::new(&message);
            let lms_sig_input: LmsSignatureProvingInput<F, D> =
                LmsSignatureProvingInput::new(&hss_sig);
            let lms_pubkey_input: LmsPublicKeyProvingInput<F, D> =
                LmsPublicKeyProvingInput::new(&hss_pubkey);
            lms_sig_target
                .lmots_signature
                .set_proving_inputs(pw, &lms_sig_input.lmots_signature);
            pw.set_target_arr(
                &lms_pubkey_target.lms_tree_identifier,
                &lms_pubkey_input.lms_tree_identifier,
            );
            pw.set_target(
                lms_sig_target.lms_leaf_identifier,
                lms_sig_input.lms_leaf_identifier,
            );
            message_target.set_proving_inputs(pw, &message_input);

            // Assert rust output == circuit output
            let rust_output = HashOut::from_vec(u8_to_f::<F, D>(rust_output.as_slice()));
            pw.set_hash_target(circuit_output, rust_output);
        });
    }

    #[test]
    fn test_split_hashout_target_to_targets() {
        run_circuit_test(|builder, pw| {
            let data = vec![
                0x8070605040302010,
                0x1020304050607080,
                0x9876543210,
                0x123456789012345,
            ];
            let hash_out = HashOutTarget::from_vec(
                data.iter()
                    .map(|&x| builder.constant(F::from_canonical_u64(x)))
                    .collect(),
            );
            let target = split_hashout_target_to_targets(builder, hash_out);
            let expected = data
                .iter()
                .flat_map(|&x| x.to_be_bytes())
                .map(F::from_canonical_u8)
                .collect::<Vec<F>>();
            println!("{:?}", expected);
            pw.set_target_arr(&target, &expected);
        });
    }

    fn new_lmots_parameter() -> LmotsParameter<Poseidon256_256> {
        LmotsParameter::new(
            LMOTS_TYPE as u32,
            LMOTS_WINTERNITZ as u8,
            LMOTS_HASH_CHAIN_COUNT as u16,
            LMOTS_CHECKSUM_LEFT_SHIFT as u8,
        )
    }

    #[test]
    fn test_checksum() {
        run_circuit_test(|builder, pw| {
            let message_hash = vec![
                0x8070605040302010,
                0x1020304050607080,
                0x9876543210,
                0x123456789012345,
            ];
            // In Circuit
            let hashout = HashOutTarget::from_vec(
                message_hash
                    .iter()
                    .map(|&x| builder.constant(F::from_canonical_u64(x)))
                    .collect(),
            );
            let message_hash_bytes = split_hashout_target_to_targets(builder, hashout).to_vec();
            let (checksum_low, checksum_high) = checksum(builder, &message_hash_bytes);

            // In Rust
            let lmots_param = new_lmots_parameter();
            let byte_string = message_hash
                .iter()
                .flat_map(|&x| x.to_be_bytes())
                .collect::<Vec<u8>>();
            let expected = lmots_param.checksum(byte_string.as_slice());

            // Assert rust output == circuit output
            pw.set_target(
                checksum_high,
                F::from_canonical_u8(((expected >> 8) & 0xff) as u8),
            );
            pw.set_target(checksum_low, F::from_canonical_u8((expected & 0xff) as u8));
        });
    }

    #[test]
    fn test_message_hash() {
        run_circuit_test(|builder, pw| {
            // Inputs
            let message = [0u8; 32];
            let lms_tree_identifier = [0u8; 16];
            let lms_leaf_identifier = [0u8; 4];
            let randomizer = [0u8; 32];

            let rust_output = {
                let lmots_param = new_lmots_parameter();
                get_message_hash(
                    &lmots_param,
                    &lms_tree_identifier,
                    &lms_leaf_identifier,
                    &randomizer,
                    &message,
                )
            };

            // Build circuit
            let message_target = MessageTarget::new(builder);
            let lms_tree_identifier_target: [Target; 2] = builder.add_virtual_target_arr();
            let lms_leaf_identifier_target = builder.add_virtual_target();
            let randomizer_target = builder.add_virtual_hash();
            let circuit_output: HashOutTarget = message_hash::<F, D>(
                builder,
                &lms_tree_identifier_target,
                &lms_leaf_identifier_target,
                &randomizer_target,
                &message_target,
            );
            // Set circuit inputs
            message_target.set_proving_inputs(pw, &MessageProvingInput::<F, D>::new(&message));
            pw.set_target_arr(
                &lms_tree_identifier_target,
                &u8_to_f::<F, D>(&lms_tree_identifier),
            );
            pw.set_target(
                lms_leaf_identifier_target,
                u8_to_f::<F, D>(&lms_leaf_identifier)[0],
            );
            pw.set_hash_target(randomizer_target, u8_to_hashout::<F, D>(&randomizer));

            // Assert rust output == circuit output
            pw.set_hash_target(
                circuit_output,
                u8_to_hashout::<F, D>(rust_output.as_slice()),
            );
        });
    }

    #[test]
    fn test_poseidon_hash_consistency() {
        run_circuit_test(|builder, pw| {
            let u64_val = 0x1234567890abcdef;
            let u32_val = 0x12345678;
            let u16_val = 0x1234;
            let u8_val = 0x12;
            let u64_target = builder.constant(F::from_canonical_u64(u64_val));
            let u32_target = builder.constant(F::from_canonical_u32(u32_val));
            let u16_target = builder.constant(F::from_canonical_u16(u16_val));
            let u8_target = builder.constant(F::from_canonical_u8(u8_val));
            let hash_target = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
                u64_target, u32_target, u16_target, u8_target,
            ]);

            let mut hasher: Poseidon256_256 = Default::default();
            hasher.update(&u64_val.to_be_bytes());
            hasher.update(&u32_val.to_be_bytes());
            hasher.update(&u16_val.to_be_bytes());
            hasher.update(&u8_val.to_be_bytes());
            let hash_val = hasher.finalize_reset();

            pw.set_hash_target(hash_target, u8_to_hashout::<F, D>(hash_val.as_slice()));
        })
    }

    #[test]
    fn test_compute_hash_chain_array() {
        run_circuit_test(|builder, pw| {
            // Inputs
            let message_hash_with_checksum = [0u8; 34];
            let (hss_pubkey, hss_sig) = keygen_sign(&message_hash_with_checksum[..32]);
            let rust_result = {
                let hss_pubkey =
                    InMemoryHssPublicKey::<Poseidon256_256>::new(&hss_pubkey.as_slice()).unwrap();
                let hss_sig =
                    InMemoryHssSignature::<Poseidon256_256>::new(&hss_sig.as_ref()).unwrap();
                let lms_sig = &hss_sig.signature;
                let lmots_sig = &hss_sig.signature.lmots_signature;
                let lmots_parameter = &lmots_sig.lmots_parameter;
                let lms_tree_identifier = hss_pubkey.public_key.lms_tree_identifier;
                let lms_leaf_identifier = &lms_sig.lms_leaf_identifier.to_be_bytes();
                get_hash_chain_array(
                    lmots_sig,
                    lmots_parameter,
                    lms_tree_identifier,
                    lms_leaf_identifier,
                    &message_hash_with_checksum,
                )
            };

            // Build circuit
            let lmots_sig_target = LmotsSignatureTarget::new(builder);
            let message_hash_with_checksum_target: MessageHashWithChecksum =
                builder.add_virtual_target_arr();
            let lms_tree_identifier_target: [Target; 2] = builder.add_virtual_target_arr();
            let lms_leaf_identifier_target = builder.add_virtual_target();
            let circuit_output = compute_hash_chain_array::<F, D>(
                builder,
                &lmots_sig_target,
                &lms_tree_identifier_target,
                &lms_leaf_identifier_target,
                &message_hash_with_checksum_target,
            );
            // Set circuit inputs
            let lms_sig_input: LmsSignatureProvingInput<F, D> =
                LmsSignatureProvingInput::new(&hss_sig);
            let lms_pubkey_input: LmsPublicKeyProvingInput<F, D> =
                LmsPublicKeyProvingInput::new(&hss_pubkey);
            lmots_sig_target.set_proving_inputs(pw, &lms_sig_input.lmots_signature);
            pw.set_target_arr(
                &lms_tree_identifier_target,
                &lms_pubkey_input.lms_tree_identifier,
            );
            pw.set_target(
                lms_leaf_identifier_target,
                lms_sig_input.lms_leaf_identifier,
            );
            let message_hash_with_checksum = message_hash_with_checksum
                .iter()
                .map(|&n| F::from_canonical_u8(n))
                .collect::<Vec<_>>();
            pw.set_target_arr(
                &message_hash_with_checksum_target,
                &message_hash_with_checksum,
            );

            // Assert rust output == circuit output
            circuit_output
                .iter()
                .zip_eq(rust_result.iter())
                .for_each(|(&target, &ref data)| {
                    pw.set_hash_target(target, u8_to_hashout::<F, D>(&data));
                });
        });
    }
}
