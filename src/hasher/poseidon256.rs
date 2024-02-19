use core::convert::TryFrom;
extern crate alloc;
use alloc::vec::Vec;
use digest::generic_array::GenericArray;
use tinyvec::ArrayVec;

use sha2::digest::{
    typenum::U32, FixedOutput, FixedOutputReset, Output, OutputSizeUser, Reset, Update,
};

use crate::constants::MAX_HASH_SIZE;

use super::HashChain;

use plonky2::{
    field::types::Field,
    hash::poseidon::PoseidonHash,
    plonk::config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig},
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
        let f_message = convert_u8_to_f(&self.message.as_slice());
        let hashout = PoseidonHash::hash_no_pad(f_message.as_slice());
        // convert HashOut to GenericArray
        *out = GenericArray::clone_from_slice(hashout.to_bytes().as_slice());
    }
}
impl Reset for Poseidon256_256 {
    fn reset(&mut self) {
        self.message.clear();
    }
}
impl FixedOutputReset for Poseidon256_256 {
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let f_message = convert_u8_to_f(&self.message.as_slice());
        let hashout = PoseidonHash::hash_no_pad(f_message.as_slice());
        // convert HashOut to GenericArray
        *out = GenericArray::clone_from_slice(hashout.to_bytes().as_slice());
        self.reset();
    }
}
impl Update for Poseidon256_256 {
    fn update(&mut self, data: &[u8]) {
        self.message.extend_from_slice(data);
    }
}

fn convert_u8_to_f(data: &[u8]) -> Vec<F> {
    data.chunks(8)
        .map(|chunk| {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            F::from_canonical_u64(u64::from_le_bytes(bytes))
        })
        .collect::<Vec<F>>()
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use digest::Update;

    use plonky2::{
        hash::poseidon::PoseidonHash,
        plonk::config::{GenericHashOut, Hasher},
    };

    #[test]
    fn test_hash() {
        let mut hash_chain: Poseidon256_256 = Default::default();
        let message = b"hello world";
        hash_chain.update(message);
        let left = hash_chain.finalize().to_vec();
        let f_message = convert_u8_to_f(message);
        let right = PoseidonHash::hash_no_pad(f_message.as_slice()).to_bytes();
        assert_eq!(left, right);
        assert_ne!(left, vec![0u8; 32]);
    }
}
