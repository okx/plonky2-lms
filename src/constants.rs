use core::mem::size_of;

use crate::lm_ots::definitions::{IType, Seed};

pub const D_PBLC: [u8; 2] = [0x80, 0x80];
pub const D_MESG: [u8; 2] = [0x81, 0x81];
pub const D_LEAF: [u8; 2] = [0x82, 0x82];
pub const D_INTR: [u8; 2] = [0x83, 0x83];

pub const MAX_N: usize = 32;
pub const MAX_P: usize = 265;

pub const MAX_M: usize = 32;
pub const MAX_H: usize = 25;

pub const MAX_PRIV_KEY_LENGTH: usize = 4 + 4 + size_of::<IType>() + 4 + size_of::<Seed>();