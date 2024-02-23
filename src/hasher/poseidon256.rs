extern crate alloc;
use core::convert::TryFrom;

use alloc::vec;
use alloc::vec::Vec;
use digest::generic_array::GenericArray;
use tinyvec::ArrayVec;

use sha2::digest::{
    typenum::U32, FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update,
};

use crate::constants::MAX_HASH_SIZE;

use super::HashChain;

use plonky2::{
    field::types::{Field, PrimeField64},
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
};

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Poseidon256_256 {
    message: ArrayVec<[u8; 10000]>,
}

impl HashChain for Poseidon256_256 {
    const OUTPUT_SIZE: u16 = 32;
    const BLOCK_SIZE: u16 = 64;
    fn finalize(self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        ArrayVec::try_from(&self.finalize_fixed()[..(Self::OUTPUT_SIZE as usize)]).unwrap()
    }
    fn finalize_reset(&mut self) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        ArrayVec::try_from(&self.finalize_fixed_reset()[..(Self::OUTPUT_SIZE as usize)]).unwrap()
    }
}
impl OutputSizeUser for Poseidon256_256 {
    type OutputSize = U32;
}
impl FixedOutput for Poseidon256_256 {
    fn finalize_into(self, out: &mut Output<Self>) {
        let f_message = u8_slice_to_f(&self.message.as_slice());
        let hashout = PoseidonHash::hash_no_pad(f_message.as_slice());
        // convert HashOut to GenericArray
        *out = GenericArray::clone_from_slice(hashout_to_u8(&hashout).as_slice());
    }
}
impl Reset for Poseidon256_256 {
    fn reset(&mut self) {
        self.message.clear();
    }
}
impl FixedOutputReset for Poseidon256_256 {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let f_message = u8_slice_to_f(&self.message.as_slice());
        let hashout = PoseidonHash::hash_no_pad(f_message.as_slice());
        // convert HashOut to GenericArray
        *out = GenericArray::clone_from_slice(hashout_to_u8(&hashout).as_slice());
        self.reset();
    }
}
impl Update for Poseidon256_256 {
    fn update(&mut self, data: &[u8]) {
        // if data.len % 8 ! = 0
        // Fill the rest with 0
        // So that each 8 bytes can be converted to 1 Goldilocks F
        let data = fill_leading_zero(data);
        self.message.extend_from_slice(data.as_slice());
    }
}

/// Big endian, fill 0 to the left
pub fn fill_leading_zero(data: &[u8]) -> Vec<u8> {
    let mut data = data.to_vec();
    if data.len() % 8 != 0 {
        let last = data.len() - data.len() % 8;
        data.splice(last..last, vec![0u8; 8 - data.len() % 8]);
    }
    data
}

/// Convert 8u8 to F
/// data should be multiple of 8
pub fn u8_slice_to_f(data: &[u8]) -> Vec<F> {
    data.chunks_exact(8)
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            bytes[..8].copy_from_slice(chunk);
            F::from_canonical_u64(u64::from_be_bytes(bytes))
        })
        .collect::<Vec<F>>()
}

pub fn hashout_to_u8(hashout: &HashOut<F>) -> Vec<u8> {
    hashout
        .elements
        .iter()
        .map(|x| x.to_canonical_u64().to_be_bytes())
        .flatten()
        .collect::<Vec<_>>()
}

#[allow(dead_code)]
pub fn u8_to_hashout(data: &[u8]) -> HashOut<F> {
    HashOut::from_vec(u8_slice_to_f(data))
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use digest::Update;

    use plonky2::{
        hash::poseidon::PoseidonHash,
        plonk::config::Hasher,
    };

    #[test]
    fn test_single_hash() {
        let mut hash_chain: Poseidon256_256 = Default::default();
        let message = b"hello world";
        hash_chain.update(message);
        let left = hash_chain.finalize().to_vec();
        let f_message = u8_slice_to_f(&fill_leading_zero(message).as_slice());
        let right = hashout_to_u8(&PoseidonHash::hash_no_pad(f_message.as_slice()));
        assert_eq!(left, right);
        assert_ne!(left, vec![0u8; 32]);
    }

    #[test]
    fn test_multi_hash() {
        let mut hash_chain: Poseidon256_256 = Default::default();
        let message: [u64; 4] = [1, 234, 5678, 12345678];
        let f_message = message.map(|m| F::from_canonical_u64(m));
        message.iter().for_each(|m| {
            hash_chain.update(&m.to_be_bytes());
        });
        assert_eq!(
            u8_slice_to_f(hash_chain.message.as_slice()),
            f_message.to_vec()
        );
        let left = hash_chain.finalize().to_vec();
        let right = hashout_to_u8(&PoseidonHash::hash_no_pad(&f_message));
        assert_eq!(left, right);
        assert_ne!(left, vec![0u8; 32]);
    }
}
