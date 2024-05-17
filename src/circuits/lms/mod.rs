use core::convert::TryInto;

use crate::{circuits::utils::u8_to_hashout_array, util::helper::read_and_advance, Poseidon256_256, Signature, VerifyingKey};
use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::{
        hash_types::{HashOut, HashOutTarget, RichField},
        poseidon::PoseidonHash,
    },
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use super::{
    constants::*,
    lm_ots::{
        generate_lmots_public_key_candidate, select_hashout_target, LmotsSignatureProvingInput,
        LmotsSignatureTarget,
    },
    utils::{assert_greater, u8_to_1f, u8_to_f, u8_to_hashout},
};

#[derive(Debug)]
pub struct MessageProvingInput<F: RichField + Extendable<D>, const D: usize>(HashOut<F>);

impl<F: RichField + Extendable<D>, const D: usize> MessageProvingInput<F, D> {
    pub fn new(message: &[u8; 32]) -> Self {
        Self(u8_to_hashout(message))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MessageTarget(pub HashOutTarget);

impl From<MessageTarget> for Vec<Target> {
    fn from(message: MessageTarget) -> Vec<Target> {
        message.0.elements.to_vec()
    }
}

impl MessageTarget {
    pub const fn size() -> usize {
        4
    }
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self(builder.add_virtual_hash())
    }
    pub fn set_proving_inputs<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        proving_input: &MessageProvingInput<F, D>,
    ) {
        pw.set_hash_target(self.0, proving_input.0);
    }
}

#[derive(Debug)]
pub struct LmsSignatureProvingInput<F: RichField + Extendable<D>, const D: usize> {
    // 0
    pub lms_leaf_identifier: F,
    // 4
    pub lmots_signature: LmotsSignatureProvingInput<F, D>,
    // 8 + LMOTS_SIG_LEN
    pub lms_parameter: F,
    // 8 + LMOTS_SIG_LEN + 4
    pub authentication_path: [HashOut<F>; LMS_TREE_HEIGHT],
}

impl<F: RichField + Extendable<D>, const D: usize> LmsSignatureProvingInput<F, D> {
    pub fn new(hss_signature: &Signature) -> Self {
        let data = hss_signature.as_ref();
        let mut idx = 0;
        // In HSS Signature, the first 4 bytes = hss_level - 1
        let hss_level =
            u32::from_be_bytes(read_and_advance(data, 4, &mut idx).try_into().unwrap()) + 1;
        assert_eq!(hss_level, 1);
        // Parsing Lms Signature like 5.4.2 Algorithm 6a
        let lms_leaf_identifier = F::from_canonical_u32(u32::from_be_bytes(
            read_and_advance(data, 4, &mut idx).try_into().unwrap(),
        ));
        let lmots_signature = LmotsSignatureProvingInput::<F, D>::new(read_and_advance(
            data,
            LMOTS_SIG_LEN_BYTES,
            &mut idx,
        ));
        let lms_parameter = F::from_canonical_u32(u32::from_be_bytes(
            read_and_advance(data, 4, &mut idx).try_into().unwrap(),
        ));
        let authentication_path: [HashOut<F>; LMS_TREE_HEIGHT] =
            u8_to_hashout_array(&data[idx..]).try_into().unwrap();
        Self {
            lms_leaf_identifier,
            lmots_signature,
            lms_parameter,
            authentication_path,
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct LmsSignatureTarget {
    pub lms_leaf_identifier: Target,
    pub lmots_signature: LmotsSignatureTarget,
    pub lms_parameter: Target,
    pub authentication_path: [HashOutTarget; LMS_TREE_HEIGHT],
}

impl From<LmsSignatureTarget> for Vec<Target> {
    fn from(signature: LmsSignatureTarget) -> Vec<Target> {
        vec![
            vec![signature.lms_leaf_identifier],
            Vec::<Target>::from(signature.lmots_signature),
            vec![signature.lms_parameter],
            signature
                .authentication_path
                .iter()
                .map(|x| x.elements.to_vec())
                .flatten()
                .collect::<Vec<_>>(),
        ]
        .concat()
    }
}

impl LmsSignatureTarget {
    /// Occupy how many Target
    pub const fn size() -> usize {
        LMS_SIGNATURE_LEN
    }
    /// Check LMS parameters in circuits
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let target = LmsSignatureTarget {
            lms_leaf_identifier: builder.add_virtual_target(),
            lmots_signature: LmotsSignatureTarget::new(builder),
            lms_parameter: builder.add_virtual_target(),
            authentication_path: builder
                .add_virtual_hashes(LMS_TREE_HEIGHT)
                .try_into()
                .unwrap(),
        };
        // Check: lms_parameter
        let lms_type = builder.constant(F::from_canonical_usize(LMS_TYPE));
        builder.connect(target.lms_parameter, lms_type);
        // Check: lms_leaf_identifier < 2^h
        let lms_leaf_identifier_max =
            builder.constant(F::from_canonical_u64((1 << LMS_TREE_HEIGHT) - 1));
        assert_greater(builder, lms_leaf_identifier_max, target.lms_leaf_identifier);

        target
    }
    pub fn set_proving_inputs<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        proving_input: &LmsSignatureProvingInput<F, D>,
    ) {
        pw.set_target(self.lms_leaf_identifier, proving_input.lms_leaf_identifier);
        self.lmots_signature
            .set_proving_inputs(pw, &proving_input.lmots_signature);
        pw.set_target(self.lms_parameter, proving_input.lms_parameter);
        self.authentication_path
            .iter()
            .zip_eq(proving_input.authentication_path.iter())
            .for_each(|(&target, &val)| {
                pw.set_hash_target(target, val);
            });
    }
}

#[derive(Debug)]
pub struct LmsPublicKeyProvingInput<F: RichField + Extendable<D>, const D: usize> {
    pub lms_parameter: F,
    pub lmots_parameter: F,
    pub lms_tree_identifier: [F; 2],
    pub key: HashOut<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> LmsPublicKeyProvingInput<F, D> {
    pub fn new(hss_pubkey: &VerifyingKey<Poseidon256_256>) -> Self {
        let data = hss_pubkey.as_slice();
        let mut idx = 0;
        let hss_level = u32::from_be_bytes(read_and_advance(data, 4, &mut idx).try_into().unwrap());
        assert_eq!(hss_level, 1);
        let lms_parameter = F::from_canonical_u32(u32::from_be_bytes(
            read_and_advance(data, 4,  &mut idx).try_into().unwrap(),
        ));
        let lmots_parameter = F::from_canonical_u32(u32::from_be_bytes(
            read_and_advance(data, 4, &mut idx).try_into().unwrap(),
        ));
        let lms_tree_identifier = u8_to_f(read_and_advance(data, 16, &mut idx))
            .try_into()
            .unwrap();
        let key = HashOut::from_vec(u8_to_f(&data[idx..]));
        Self {
            lms_parameter,
            lmots_parameter,
            lms_tree_identifier,
            key,
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct LmsPublicKeyTarget {
    // Total 56 bytes = 7 targets
    /// 4 bytes pubtype
    pub lms_parameter: Target,
    /// 4 bytes ots_typecode
    pub lmots_parameter: Target,
    /// 16 bytes tree identifier I
    pub lms_tree_identifier: [Target; 2],
    /// 32 bytes key T[1]
    pub key: HashOutTarget,
}

impl From<LmsPublicKeyTarget> for Vec<Target> {
    fn from(pubkey: LmsPublicKeyTarget) -> Vec<Target> {
        vec![
            vec![
                pubkey.lms_parameter,
                pubkey.lmots_parameter,
                pubkey.lms_tree_identifier[0],
                pubkey.lms_tree_identifier[1],
            ],
            pubkey.key.elements.to_vec(),
        ]
        .concat()
    }
}
impl LmsPublicKeyTarget {
    pub const fn size() -> usize {
        LMS_PUBKEY_LEN
    }
    /// Check lms & lm_ots parameters in circuits
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let target = LmsPublicKeyTarget {
            lms_parameter: builder.add_virtual_target(),
            lmots_parameter: builder.add_virtual_target(),
            lms_tree_identifier: [builder.add_virtual_target(), builder.add_virtual_target()],
            key: builder.add_virtual_hash(),
        };
        // Check: lms_parameter
        let lms_type = builder.constant(F::from_canonical_usize(LMS_TYPE));
        builder.connect(target.lms_parameter, lms_type);
        // Check: lmots_parameter
        let lmots_type = builder.constant(F::from_canonical_usize(LMOTS_TYPE));
        builder.connect(target.lmots_parameter, lmots_type);

        target
    }
    pub fn set_proving_inputs<F: RichField + Extendable<D>, const D: usize>(
        &self,
        pw: &mut PartialWitness<F>,
        proving_input: &LmsPublicKeyProvingInput<F, D>,
    ) {
        pw.set_target(self.lms_parameter, proving_input.lms_parameter);
        pw.set_target(self.lmots_parameter, proving_input.lmots_parameter);
        pw.set_target_arr(&self.lms_tree_identifier,&proving_input.lms_tree_identifier);
        pw.set_hash_target(self.key, proving_input.key);
    }
}

/// Verify LMS signature in circuit level
///
/// Algorithm 6: LMS Signature Verification
pub fn build_lms_verify_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signature: &LmsSignatureTarget,
    pubkey: &LmsPublicKeyTarget,
    message: &MessageTarget,
) {
    // 1 and 2 already checked in LmsPublicKeyTarget::new()
    // Check lms and lmots parameters in signature and pubkey
    builder.connect(
        signature.lmots_signature.lmots_parameter,
        pubkey.lmots_parameter,
    );
    builder.connect(signature.lms_parameter, pubkey.lms_parameter);

    //  3. Compute the LMS Public Key Candidate Tc from the signature,
    //  message, identifier, pubtype, and ots_typecode, using
    //  Algorithm 6a.
    let public_key_canditate =
        generate_lms_public_key_candiate(builder, &signature, &pubkey, &message);
    // 4. Check if Tc is equal to T[1]
    builder.connect_hashes(public_key_canditate, pubkey.key);
}

/// Algorithm 6a: Computing an LMS Public Key Candidate from a Signature,
/// Message, Identifier, and Algorithm Typecodes
fn generate_lms_public_key_candiate<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signature: &LmsSignatureTarget,
    public_key: &LmsPublicKeyTarget,
    message: &MessageTarget,
) -> HashOutTarget {
    // 1 and 2 already checked in LmsSignatureTarget::new()

    // 3. Kc = candidate public key computed by applying Algorithm 4b
    // to the signature lmots_signature, the message, and the
    // identifiers I, q
    let ots_public_key_candidate = generate_lmots_public_key_candidate(
        builder,
        &signature.lmots_signature,
        &public_key.lms_tree_identifier,
        &signature.lms_leaf_identifier,
        message,
    );

    // 4. Compute the candidate LMS root value Tc as follows:
    let leaves = builder.constant(F::from_canonical_usize(1 << LMS_TREE_HEIGHT));
    let mut node_num = builder.add(leaves, signature.lms_leaf_identifier);
    let d_leaf = builder.constant(u8_to_1f(&D_LEAF));
    let mut tmp = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [
            public_key.lms_tree_identifier.to_vec(),
            vec![node_num],
            vec![d_leaf],
            ots_public_key_candidate.elements.to_vec(),
        ]
        .concat(),
    );
    let d_intr = builder.constant(u8_to_1f(&D_INTR));
    for i in 0..LMS_TREE_HEIGHT {
        let (node_num_lsb, half_node_num) =
            builder.split_low_high(node_num, 1, LMS_TREE_HEIGHT + 1 - i);
        let hash_odd = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            [
                public_key.lms_tree_identifier.to_vec(),
                vec![half_node_num],
                vec![d_intr],
                signature.authentication_path[i].elements.to_vec(),
                tmp.elements.to_vec(),
            ]
            .concat(),
        );
        let hash_even = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            [
                public_key.lms_tree_identifier.to_vec(),
                vec![half_node_num],
                vec![d_intr],
                tmp.elements.to_vec(),
                signature.authentication_path[i].elements.to_vec(),
            ]
            .concat(),
        );
        let is_node_num_odd = BoolTarget::new_unsafe(node_num_lsb);
        tmp = select_hashout_target(builder, is_node_num_odd, hash_odd, hash_even);
        node_num = half_node_num;
    }
    // Tc = tmp
    tmp
}

#[cfg(test)]
mod test {
    use crate::{circuits::{keygen_sign, utils::{hashout_to_u8, test_util::run_circuit_test}}, InMemoryHssPublicKey, InMemoryHssSignature, InMemoryLmsSignature};
    use plonky2::{field::types::PrimeField64, iop::witness::WitnessWrite};

    use super::*;
    use plonky2::field::types::Field;

    #[test]
    fn test_signature_target() {
        run_circuit_test(|builder, pw| {
            let target = LmsSignatureTarget::new(builder);
            pw.set_target(target.lms_parameter, F::from_canonical_usize(LMS_TYPE));
            pw.set_target(
                target.lms_leaf_identifier,
                F::from_canonical_u32((1 << LMS_TREE_HEIGHT) - 1),
            );
        })
    }

    #[test]
    #[should_panic]
    fn test_signature_target_invalid_lms_type() {
        run_circuit_test(|builder, pw| {
            let target = LmsSignatureTarget::new(builder);
            pw.set_target(
                target.lms_parameter,
                F::from_canonical_usize(LMS_TYPE + 100),
            );
        });
    }

    #[test]
    #[should_panic]
    fn test_signature_target_invalid_lms_leaf_identifier() {
        run_circuit_test(|builder, pw| {
            let target = LmsSignatureTarget::new(builder);
            pw.set_target(
                target.lms_leaf_identifier,
                F::from_canonical_u32(1 << LMS_TREE_HEIGHT),
            );
            pw.set_target(
                target.lms_leaf_identifier,
                F::from_canonical_u32((1 << LMS_TREE_HEIGHT) + 10),
            );
        });
    }

    #[test]
    fn test_public_key_target() {
        run_circuit_test(|builder, pw| {
            let target = LmsPublicKeyTarget::new(builder);
            pw.set_target(target.lms_parameter, F::from_canonical_usize(LMS_TYPE));
            pw.set_target(target.lmots_parameter, F::from_canonical_usize(LMOTS_TYPE));
        });
    }

    #[test]
    #[should_panic]
    fn test_public_key_target_invalid_lms_type() {
        run_circuit_test(|builder, pw| {
            let target = LmsPublicKeyTarget::new(builder);
            pw.set_target(
                target.lms_parameter,
                F::from_canonical_usize(LMS_TYPE + 100),
            );
        });
    }

    #[test]
    #[should_panic]
    fn test_public_key_target_invalid_lmots_type() {
        run_circuit_test(|builder, pw| {
            let target = LmsPublicKeyTarget::new(builder);
            pw.set_target(
                target.lmots_parameter,
                F::from_canonical_usize(LMOTS_TYPE + 100),
            );
        });
    }

    #[test]
    fn test_parse_public_key() {
        let message = [0u8; 32];
        let (hss_pubkey, _) = keygen_sign(&message);
        let hss = InMemoryHssPublicKey::<Poseidon256_256>::new(&hss_pubkey.as_slice()).unwrap();
        let lms = hss.public_key;

        let proving_input: LmsPublicKeyProvingInput<F, D> =
            LmsPublicKeyProvingInput::new(&hss_pubkey);
        assert_eq!(
            proving_input.lms_parameter,
            F::from_canonical_u32(lms.lms_parameter.get_type_id())
        );
        assert_eq!(
            proving_input.lmots_parameter,
            F::from_canonical_u32(lms.lmots_parameter.get_type_id())
        );
        let lms_tree_identifier = proving_input
            .lms_tree_identifier
            .iter()
            .map(|x| x.to_canonical_u64().to_be_bytes())
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(lms_tree_identifier, lms.lms_tree_identifier.to_vec());
        let lms_key = hashout_to_u8(&proving_input.key);
        assert_eq!(lms_key, lms.key.to_vec());
    }

    #[test]
    fn test_parse_signature() {
        let message = [0u8; 32];
        let (_, hss_signature) = keygen_sign(&message);
        let hss = InMemoryHssSignature::<Poseidon256_256>::new(&hss_signature.as_ref()).unwrap();
        let lms: InMemoryLmsSignature<'_, Poseidon256_256> = hss.signature;

        let proving_input: LmsSignatureProvingInput<F, D> =
            LmsSignatureProvingInput::new(&hss_signature);
        assert_eq!(
            proving_input.lms_leaf_identifier,
            F::from_canonical_u32(lms.lms_leaf_identifier)
        );
        // Also check LMOTS signature
        assert_eq!(
            proving_input.lmots_signature.lmots_parameter,
            F::from_canonical_u32(lms.lmots_signature.lmots_parameter.get_type_id())
        );
        let randomizer = hashout_to_u8(&proving_input.lmots_signature.randomizer);
        assert_eq!(
            randomizer,
            lms.lmots_signature.signature_randomizer.to_vec(),
        );
        let lmots_data = hashout_arr_to_u8(&proving_input.lmots_signature.data);
        assert_eq!(lmots_data, lms.lmots_signature.signature_data.to_vec());
        assert_eq!(
            proving_input.lms_parameter,
            F::from_canonical_u32(lms.lms_parameter.get_type_id())
        );
        let lms_auth_path = hashout_arr_to_u8(&proving_input.authentication_path);
        assert_eq!(lms_auth_path, lms.authentication_path.to_vec());
    }

    fn hashout_arr_to_u8(hashout_arr: &[HashOut<F>]) -> Vec<u8> {
        hashout_arr
            .iter()
            .map(hashout_to_u8)
            .flatten()
            .collect::<Vec<_>>()
    }
}
