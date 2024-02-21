use core::{
    convert::TryFrom,
    fmt::Debug,
};
use digest::{FixedOutput, Update};
use tinyvec::ArrayVec;

use crate::constants::MAX_HASH_SIZE;

pub mod poseidon256;
pub mod sha256;
pub mod shake256;

pub struct HashChainData<'a> {
    lms_tree_identifier: &'a [u8],
    lms_leaf_identifier: &'a [u8],
}

/**
 *
 * This trait is used inside the library to generate hashes. Default implementations are available with [`sha256::Sha256`] and [`shake256::Shake256`].
 * It can be used to outsource calculations to hardware accelerators.
 *
 *
 * Requires PartialEq, to use compare within the tests.
 * This is required as long as this [issue](https://github.com/rust-lang/rust/issues/26925) is
 * open.
 * */
pub trait HashChain:
    Debug + Default + Clone + PartialEq + Send + Sync + FixedOutput + Update
{
    const OUTPUT_SIZE: u16;
    const BLOCK_SIZE: u16;

    fn finalize(self) -> ArrayVec<[u8; MAX_HASH_SIZE]>;
    fn finalize_reset(&mut self) -> ArrayVec<[u8; MAX_HASH_SIZE]>;

    fn prepare_hash_chain_data<'a>(
        lms_tree_identifier: &'a [u8],
        lms_leaf_identifier: &'a [u8],
    ) -> HashChainData<'a> {
        HashChainData {
            lms_tree_identifier,
            lms_leaf_identifier,
        }
    }

    fn do_hash_chain(
        &mut self,
        hc_data: &mut HashChainData,
        hash_chain_id: u16,
        initial_value: &[u8],
        from: usize,
        to: usize,
    ) -> ArrayVec<[u8; MAX_HASH_SIZE]> {
        let mut tmp = ArrayVec::try_from(initial_value).unwrap();
        for j in from..to {
            self.update(hc_data.lms_tree_identifier);
            self.update(hc_data.lms_leaf_identifier);
            self.update(&hash_chain_id.to_le_bytes());
            self.update(&j.to_le_bytes());
            self.update(tmp.as_slice());
            tmp = self.finalize_reset();
        }
        tmp
    }
}
