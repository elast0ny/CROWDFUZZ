use simple_parse::{SpRead, SpWrite};

use crate::*;

pub enum NewStat<'a> {
    Num(u64),
    Bytes { max_size: usize, init_val: &'a [u8] },
    Str { max_size: usize, init_val: &'a str },
}

#[derive(SpRead, SpWrite, Debug)]
#[sp(id_type = "u8")]
pub enum CoreState {
    #[sp(id = "0")]
    Initializing,
    #[sp(id = "1")]
    Fuzzing,
    #[sp(id = "2")]
    Exiting,
}

#[derive(SpRead, SpWrite, Debug)]
pub struct StatHeader<'a> {
    pid: u32,
    state: CoreState,
    num_plugins: u16,
    plugins: &'a [PluginStats<'a>],
}

#[derive(SpRead, SpWrite, Debug)]
pub struct PluginStats<'a> {
    name: &'a str,
    num_stats: u32,
    stats: &'a [PluginStats<'a>],
}

#[derive(SpRead, SpWrite, Debug)]
#[sp(id_type = "u8")]
pub enum Stat<'a> {
    #[sp(id = "0")]
    PluginHeader(&'a str),
    #[sp(id = "1")]
    Num(StatNum<'a>),
    #[sp(id = "2")]
    Bytes(StatBytes<'a>),
    #[sp(id = "3")]
    Str(StatStr<'a>),
}

#[derive(SpRead, SpWrite, Debug)]
pub struct StatNum<'a> {
    val: &'a u64,
}
impl StatNum<'_> {
    pub fn set(&'_ mut self, new_val: u64) {
        #[allow(clippy::cast_ref_to_mut)]
        unsafe {
            *(self.val as *const u64 as *mut u64) = new_val
        }
    }
    pub fn get(&self) -> &u64 {
        self.val
    }
}

#[derive(SpRead, SpWrite, Debug)]
pub struct StatBytes<'a> {
    lock: &'a u8,
    buf: GenericBuf<'a>,
}
impl<'b> StatBytes<'b> {
    pub fn set(&mut self, new_val: &[u8]) {
        acquire(self.lock);
        self.buf.set(new_val);
        release(self.lock);
    }
    pub fn get(&'b self) -> LockGuard<'b, &'b [u8]> {
        acquire(self.lock);
        LockGuard::new(self.buf.get(), self.lock)
    }
    #[allow(clippy::should_implement_trait)]
    pub fn clone(&self) -> Vec<u8> {
        let s = self.get();
        s.to_vec()
    }
}

#[derive(SpRead, SpWrite, Debug)]
pub struct StatStr<'a> {
    lock: &'a u8,
    buf: GenericBuf<'a>,
}
impl StatStr<'_> {
    pub fn set(&mut self, new_val: &str) {
        acquire(self.lock);
        self.buf.set(new_val.as_bytes());
        release(self.lock);
    }
    pub fn get(&self) -> LockGuard<'_, &str> {
        acquire(self.lock);
        let bytes = self.buf.get();
        let s = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => "<INVALID UTF8>",
        };
        LockGuard::new(s, self.lock)
    }
    #[allow(clippy::should_implement_trait)]
    pub fn clone(&self) -> String {
        let s = self.get();
        s.to_string()
    }
}

