use crate::constants::MAX_M;
use crate::util::dynamic_array::DynamicArray;
use crate::util::hash::Hasher;
use crate::{
    constants::{D_INTR, D_LEAF},
    util::ustr::u32str,
};

use super::definitions::LmsPrivateKey;

pub fn get_tree_element(index: usize, private_key: &LmsPrivateKey) -> DynamicArray<u8, MAX_M> {
    let mut hasher = private_key.lms_type.get_parameter().get_hasher();

    hasher.update(&private_key.I);
    hasher.update(&u32str(index as u32));

    let max_private_keys = private_key.lms_type.get_parameter().number_of_lm_ots_keys();

    if index >= max_private_keys {
        hasher.update(&D_LEAF);
        let lms_ots_private_key = crate::lm_ots::generate_private_key(
            u32str((index - max_private_keys) as u32),
            private_key.I,
            private_key.seed,
            private_key.lm_ots_type,
        );
        let lm_ots_public_key = crate::lm_ots::generate_public_key(&lms_ots_private_key);
        hasher.update(&lm_ots_public_key.key.get_slice());
    } else {
        hasher.update(&D_INTR);
        let left = get_tree_element(2 * index, private_key);
        let right = get_tree_element(2 * index + 1, private_key);

        hasher.update(&left.get_slice());
        hasher.update(&right.get_slice());
    }

    DynamicArray::from_slice(&hasher.finalize())
}