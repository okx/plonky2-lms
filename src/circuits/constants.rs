use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

pub const LMS_TREE_HEIGHT: usize = 10;

// Big endian, they are used in hash
pub const D_PBLC: [u8; 8] = [0, 0, 0, 0, 0, 0, 0x80, 0x80];
pub const D_MESG: [u8; 8] = [0, 0, 0, 0, 0, 0, 0x81, 0x81];
pub const D_LEAF: [u8; 8] = [0, 0, 0, 0, 0, 0, 0x82, 0x82];
pub const D_INTR: [u8; 8] = [0, 0, 0, 0, 0, 0, 0x83, 0x83];

/* LMS */
/*
enum lms_algorithm_type {
    lms_reserved       = 0,
    lms_sha256_n32_h5  = 5,
    lms_sha256_n32_h10 = 6,
    lms_sha256_n32_h15 = 7,
    lms_sha256_n32_h20 = 8,
    lms_sha256_n32_h25 = 9
};
*/
// Fix LMS tree height = 10
pub const LMS_TYPE: usize = 6;
pub const LMS_AUTH_PATH_LEN: usize = LMS_TREE_HEIGHT * LMOTS_KEY_LEN;
pub const LMS_SIGNATURE_LEN: usize = 1 + LMOTS_SIG_LEN + 1 + LMS_AUTH_PATH_LEN;
/// LMS public key 56 bytes = 7 targets
pub const LMS_PUBKEY_LEN: usize = 7;

/* LMOTS */
pub const POSEIDON_HASH_OUTPUT_SIZE_BYTES: usize = 32;
/// Goldilocks Field size
pub const FIELD_SIZE_BYTES: usize = 8;
pub const LMOTS_KEY_LEN: usize = POSEIDON_HASH_OUTPUT_SIZE_BYTES / FIELD_SIZE_BYTES;

/// LMOTS Param W1: fast speed but large signature size
pub const LMOTS_TYPE: usize = 1;
pub const LMOTS_WINTERNITZ: usize = 1;
pub const LMOTS_CHECKSUM_LEFT_SHIFT: usize = 7;
/// Calculated using the formula from RFC 8554 Appendix B
/// https://datatracker.ietf.org/doc/html/rfc8554#appendix-B
pub const LMOTS_HASH_CHAIN_COUNT: usize = 265;

pub const LMOTS_SIG_LEN_BYTES: usize =
    4 + (POSEIDON_HASH_OUTPUT_SIZE_BYTES * (1 + LMOTS_HASH_CHAIN_COUNT));
pub const LMOTS_SIG_LEN: usize = 1 + 4 * (1 + LMOTS_HASH_CHAIN_COUNT);
// const LMOTS_SIG_DATA_LEN: usize = LMOTS_SIG_LEN - LMOTS_KEY_LEN;

// Plonky2 constants
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub const D: usize = 2;

pub const MAX_POSITIVE_AMOUNT_LOG: usize = 62;
