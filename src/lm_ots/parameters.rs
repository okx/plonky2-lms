use core::fmt::Debug;
use core::marker::PhantomData;

use tinyvec::ArrayVec;

use crate::constants::get_hash_chain_count;
use crate::{
    constants::{FastVerifyCached, MAX_HASH_SIZE},
    hasher::HashChain,
    util::coef::coef,
};

use crate::util::coef::coef_helper;

/// Specifies the used Winternitz parameter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LmotsAlgorithm {
    LmotsReserved = 0,
    LmotsW1 = 1,
    LmotsW2 = 2,
    LmotsW4 = 3,
    LmotsW8 = 4,
}

impl Debug for LmotsAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LmotsAlgorithm::LmotsReserved => write!(f, "LmotsReserved"),
            LmotsAlgorithm::LmotsW1 => write!(f, "W1"),
            LmotsAlgorithm::LmotsW2 => write!(f, "W2"),
            LmotsAlgorithm::LmotsW4 => write!(f, "W4"),
            LmotsAlgorithm::LmotsW8 => write!(f, "W8"),
        }
    }

}
impl Default for LmotsAlgorithm {
    fn default() -> Self {
        LmotsAlgorithm::LmotsReserved
    }
}

impl From<u32> for LmotsAlgorithm {
    fn from(_type: u32) -> Self {
        match _type {
            1 => LmotsAlgorithm::LmotsW1,
            2 => LmotsAlgorithm::LmotsW2,
            3 => LmotsAlgorithm::LmotsW4,
            4 => LmotsAlgorithm::LmotsW8,
            _ => LmotsAlgorithm::LmotsReserved,
        }
    }
}

impl LmotsAlgorithm {
    pub fn construct_default_parameter<H: HashChain>() -> LmotsParameter<H> {
        LmotsAlgorithm::LmotsW1.construct_parameter().unwrap()
    }

    pub fn construct_parameter<H: HashChain>(&self) -> Option<LmotsParameter<H>> {
        match *self {
            LmotsAlgorithm::LmotsReserved => None,
            LmotsAlgorithm::LmotsW1 => Some(LmotsParameter::new(
                1,
                1,
                get_hash_chain_count(1, H::OUTPUT_SIZE as usize) as u16,
                7,
            )),
            LmotsAlgorithm::LmotsW2 => Some(LmotsParameter::new(
                2,
                2,
                get_hash_chain_count(2, H::OUTPUT_SIZE as usize) as u16,
                6,
            )),
            LmotsAlgorithm::LmotsW4 => Some(LmotsParameter::new(
                3,
                4,
                get_hash_chain_count(4, H::OUTPUT_SIZE as usize) as u16,
                4,
            )),
            LmotsAlgorithm::LmotsW8 => Some(LmotsParameter::new(
                4,
                8,
                get_hash_chain_count(8, H::OUTPUT_SIZE as usize) as u16,
                0,
            )),
        }
    }

    pub fn get_from_type<H: HashChain>(_type: u32) -> Option<LmotsParameter<H>> {
        match _type {
            1 => LmotsAlgorithm::LmotsW1.construct_parameter(),
            2 => LmotsAlgorithm::LmotsW2.construct_parameter(),
            3 => LmotsAlgorithm::LmotsW4.construct_parameter(),
            4 => LmotsAlgorithm::LmotsW8.construct_parameter(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LmotsParameter<H: HashChain> {
    type_id: u32,
    winternitz: u8,
    hash_chain_count: u16,
    checksum_left_shift: u8,
    phantom_data: PhantomData<H>,
}

// Manually implement Copy because HashChain trait does not.
// However, it does not make a difference, because we don't hold a instance for HashChain.
impl<H: HashChain> Copy for LmotsParameter<H> {}

impl<H: HashChain> LmotsParameter<H> {
    const HASH_FUNCTION_OUTPUT_SIZE: u16 = H::OUTPUT_SIZE;

    pub fn new(
        type_id: u32,
        winternitz: u8,
        hash_chain_count: u16,
        checksum_left_shift: u8,
    ) -> Self {
        Self {
            type_id,
            winternitz,
            hash_chain_count,
            checksum_left_shift,
            phantom_data: PhantomData,
        }
    }

    pub fn get_type_id(&self) -> u32 {
        self.type_id
    }

    pub fn get_winternitz(&self) -> u8 {
        self.winternitz
    }

    pub fn get_hash_chain_count(&self) -> u16 {
        self.hash_chain_count
    }

    pub fn get_checksum_left_shift(&self) -> u8 {
        self.checksum_left_shift
    }

    pub fn get_hash_function_output_size(&self) -> usize {
        Self::HASH_FUNCTION_OUTPUT_SIZE as usize
    }

    pub fn fast_verify_eval_init(&self) -> FastVerifyCached {
        let max = (Self::HASH_FUNCTION_OUTPUT_SIZE * 8) / self.get_winternitz() as u16;

        let max_word_size = (1 << self.get_winternitz()) - 1;
        let sum = max * max_word_size;

        let mut coef = ArrayVec::new();
        for i in 0..self.get_hash_chain_count() {
            coef.push(coef_helper(i, self.get_winternitz()));
        }

        (max, sum, coef)
    }

    pub fn fast_verify_eval(
        &self,
        byte_string: &[u8],
        fast_verify_cached: &FastVerifyCached,
    ) -> u16 {
        let (max, sum, coef) = fast_verify_cached;
        let mut total_hash_chain_iterations = 0;

        for i in 0..*max {
            let (index, shift, mask) = coef[i as usize];
            let hash_chain_length = ((byte_string[index] as u64 >> shift) & mask) as u16;
            total_hash_chain_iterations += hash_chain_length;
        }

        let mut checksum = *sum - total_hash_chain_iterations;
        checksum <<= self.get_checksum_left_shift();
        let checksum = [(checksum >> 8 & 0xff) as u8, (checksum & 0xff) as u8];

        for i in *max..self.get_hash_chain_count() {
            let (index, shift, mask) = coef[i as usize];
            let hash_chain_length = ((checksum[index - 32] as u64 >> shift) & mask) as u16;
            total_hash_chain_iterations += hash_chain_length;
        }

        total_hash_chain_iterations
    }

    pub fn checksum(&self, byte_string: &[u8]) -> u16 {
        let mut sum = 0_u16;

        let max = (Self::HASH_FUNCTION_OUTPUT_SIZE * 8) / self.get_winternitz() as u16;

        let max_word_size: u64 = (1 << self.get_winternitz()) - 1;

        for i in 0..max {
            sum += (max_word_size - coef(byte_string, i, self.get_winternitz())) as u16;
        }

        sum << self.get_checksum_left_shift()
    }

    pub fn append_checksum_to(&self, byte_string: &[u8]) -> ArrayVec<[u8; MAX_HASH_SIZE + 2]> {
        let mut result = ArrayVec::new();

        let checksum = self.checksum(byte_string);

        result.extend_from_slice(byte_string);

        result.extend_from_slice(&[(checksum >> 8 & 0xff) as u8]);
        result.extend_from_slice(&[(checksum & 0xff) as u8]);

        result
    }

    pub fn get_hasher(&self) -> H {
        H::default()
    }
}

impl<H: HashChain> Default for LmotsParameter<H> {
    fn default() -> Self {
        LmotsAlgorithm::LmotsW1.construct_parameter().unwrap()
    }
}
