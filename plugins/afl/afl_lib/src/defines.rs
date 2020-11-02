pub const HAVOC_MAX_MULT: u32 = 16;
pub const ARITH_MAX: u8 = 35;
pub const HAVOC_MIN: usize = 16;
pub const HAVOC_CYCLES: u16 = 256;
pub const HAVOC_CYCLES_INIT: u16 = 1024;
pub const HAVOC_STACK_POW2: usize = 7;
pub const HAVOC_BLK_SMALL: u32 = 32;
pub const HAVOC_BLK_MEDIUM: u32 = 128;
pub const HAVOC_BLK_LARGE: u32 = 500;
pub const HAVOC_BLK_XL: u32 = 32768;
pub const MAX_FILE: u32 = 1024 * 1024;

pub const CAL_CYCLES: u8 = 8;
pub const CAL_CYCLES_LONG: u8 = 40;
pub const MAP_SIZE_POW2: usize = 16;
pub const MAP_SIZE: usize = 1 << MAP_SIZE_POW2;
pub const HASH_CONST: u32 = 0xa5b35705;