use std::path::PathBuf;

/// Represents generic info for a specific input
pub struct CfInputInfo {
    /// A unique identifier for this file
    pub uid: Vec<u8>,
    /// Contents of the input
    pub contents: Option<CfInput>,
    /// Path to the input if it is on disk
    pub path: Option<PathBuf>,
    /// Size of the contents of the input
    pub len: usize,
}

#[derive(PartialEq, PartialOrd, Eq, Ord)]
pub struct InputPriority {
    /// The arbitrary priority for this input
    pub weight: usize,
    /// The index of the input
    pub idx: usize,
}
impl InputPriority {
    pub fn from(weight: usize, idx: usize) -> Self {
        Self { weight, idx }
    }
}

/// Represents the contents of an input
pub type CfInput = Vec<u8>;

/// Represents generic info for a specific input
pub struct CfNewInput {
    /// Contents of the input
    pub contents: Option<&'static CfInput>,
    /// Path to the input
    pub path: Option<PathBuf>,
}

#[allow(clippy::missing_safety_doc)]
pub trait MutateUtil {
    /// Sets the byte at idx to val
    unsafe fn set_byte(&mut self, idx: usize, val: u8) -> u8;
    /// Sets the word at byte offset idx to val
    unsafe fn set_word(&mut self, idx: usize, val: u16) -> u16;
    /// Sets the dword at byte offset idx to val
    unsafe fn set_dword(&mut self, idx: usize, val: u32) -> u32;
    /// Flips bit at bit idx
    unsafe fn flip_bit(&mut self, bit_idx: usize) -> u8;
    /// Flips byte at byte idx
    unsafe fn flip_byte(&mut self, idx: usize) -> u8;
    /// Flips word at byte idx
    unsafe fn flip_word(&mut self, idx: usize) -> u16;
    /// Flips dword at byte idx
    unsafe fn flip_dword(&mut self, idx: usize) -> u32;
    /// Adds val to byte at byte idx
    unsafe fn add_byte(&mut self, idx: usize, val: u8) -> u8;
    /// Subs val to byte at byte idx
    unsafe fn sub_byte(&mut self, idx: usize, val: u8) -> u8;
    /// Adds val to word at byte idx
    unsafe fn add_word(&mut self, idx: usize, val: u16) -> u16;
    /// Subs val to word at byte idx
    unsafe fn sub_word(&mut self, idx: usize, val: u16) -> u16;
    /// Adds val to dword at byte idx
    unsafe fn add_dword(&mut self, idx: usize, val: u32) -> u32;
    /// Subs val to dword at byte idx
    unsafe fn sub_dword(&mut self, idx: usize, val: u32) -> u32;
}

//use std::convert::AsMut;
impl<B: AsMut<[u8]>> MutateUtil for B {
    #[inline]
    unsafe fn set_byte(&mut self, idx: usize, val: u8) -> u8 {
        let ptr = self.as_mut().get_unchecked_mut(idx);
        let orig = *ptr;
        *ptr = val;
        orig
    }
    #[inline]
    unsafe fn set_word(&mut self, idx: usize, val: u16) -> u16{
        let ptr = self.as_mut().as_mut_ptr().add(idx) as *mut u16;
        let orig = *ptr;
        *ptr = val;
        orig
    }
    #[inline]
    unsafe fn set_dword(&mut self, idx: usize, val: u32) -> u32{
        let ptr = self.as_mut().as_mut_ptr().add(idx) as *mut u32;
        let orig = *ptr;
        *ptr = val;
        orig
    }
    #[inline]
    unsafe fn flip_bit(&mut self, bit_idx: usize) -> u8 {
        let val = self.as_mut().get_unchecked_mut(bit_idx >> 3);
        let orig = *val;
        *val ^= 128 >> (bit_idx & 7);
        orig
    }
    #[inline]
    unsafe fn flip_byte(&mut self, idx: usize) -> u8 {
        let val = self.as_mut().get_unchecked_mut(idx);
        let orig = *val;
        *val ^= 0xFF;
        orig
    }
    #[inline]
    unsafe fn flip_word(&mut self, idx: usize) -> u16 {
        let ptr = self.as_mut().as_mut_ptr().add(idx) as *mut u16;
        let orig = *ptr;
        *ptr ^= 0xFFFF;
        orig
    }
    #[inline]
    unsafe fn flip_dword(&mut self, idx: usize) -> u32 {
        let ptr = self.as_mut().as_mut_ptr().add(idx) as *mut u32;
        let orig = *ptr;
        *ptr ^= 0xFFFFFFFF;
        orig
    }#[inline]
    unsafe fn add_byte(&mut self, idx: usize, val: u8) -> u8 {
        let ptr = self.as_mut().get_unchecked_mut(idx);
        let orig = *ptr;
        *ptr = ptr.overflowing_add(val).0;
        orig
    }
    #[inline]
    unsafe fn sub_byte(&mut self, idx: usize, val: u8) -> u8{
        let ptr = self.as_mut().get_unchecked_mut(idx);
        let orig = *ptr;
        *ptr = ptr.overflowing_sub(val).0;
        orig
    }
    #[inline]
    unsafe fn add_word(&mut self, idx: usize, val: u16) -> u16{
        let ptr = &mut *(self.as_mut().as_mut_ptr().add(idx) as *mut u16);
        let orig = *ptr;
        *ptr = ptr.overflowing_add(val).0;
        orig
    }
    #[inline]
    unsafe fn sub_word(&mut self, idx: usize, val: u16) -> u16{
        let ptr = &mut *(self.as_mut().as_mut_ptr().add(idx) as *mut u16);
        let orig = *ptr;
        *ptr = ptr.overflowing_sub(val).0;
        orig
    }
    #[inline]
    unsafe fn add_dword(&mut self, idx: usize, val: u32) -> u32{
        let ptr = &mut *(self.as_mut().as_mut_ptr().add(idx) as *mut u32);
        let orig = *ptr;
        *ptr = ptr.overflowing_add(val).0;
        orig
    }
    #[inline]
    unsafe fn sub_dword(&mut self, idx: usize, val: u32) -> u32{
        let ptr = &mut *(self.as_mut().as_mut_ptr().add(idx) as *mut u32);
        let orig = *ptr;
        *ptr = ptr.overflowing_sub(val).0;
        orig
    }
}