use simple_parse::*;
use std::sync::atomic::AtomicU8;

use crate::*;

pub struct NewStat<'a> {
    pub tag: &'a str,
    pub val: NewStatVal<'a>,
}

pub enum NewStatVal<'a> {
    Num(u64),
    Bytes { max_size: usize, init_val: &'a [u8] },
    Str { max_size: usize, init_val: &'a str },
}

#[derive(SpRead, Debug)]
#[sp(id_type = "u8")]
pub enum CoreState {
    #[sp(id = "0")]
    Initializing,
    #[sp(id = "1")]
    Fuzzing,
    #[sp(id = "2")]
    Exiting,
}

#[derive(SpRead, Debug)]
pub struct StatHeader<'a> {
    pid: u32,
    state: CoreState,
    num_plugins: u16,
    #[sp(count = "num_plugins")]
    plugins: Vec<PluginStats<'a>>,
}

#[derive(SpRead, Debug)]
pub struct PluginStats<'a> {
    name: String,
    num_stats: u32,
    #[sp(count = "num_stats")]
    stats: Vec<Stat<'a>>,
}

#[derive(SpRead, Debug)]
pub struct Stat<'a> {
    tag: String,
    val: StatVal<'a>,
}

#[derive(SpRead, Debug)]
#[sp(id_type = "u8")]
pub enum StatVal<'a> {
    #[sp(id = "0")]
    Num(StatNum<'a>),
    #[sp(id = "1")]
    Bytes(StatBytes<'a>),
    #[sp(id = "2")]
    Str(StatStr<'a>),
}

#[derive(Debug)]
pub struct StatNum<'a> {
    pub(crate) val: &'a mut u64,
}
impl<'a> StatNum<'a> {
    pub fn set(&mut self, new_val: u64) {
        *self.val = new_val
    }
    pub fn get(&self) -> &u64 {
        self.val
    }
}

#[derive(Debug)]
pub struct StatStr<'a> {
    pub(crate) lock: &'a mut AtomicU8,
    pub(crate) val: GenericBuf<'a>,
}
impl<'a> StatStr<'a> {
    pub fn set(&mut self, new_val: &str) {
        acquire(self.lock);
        self.val.set(new_val.as_bytes());
        release(self.lock);
    }
    pub fn get(&'a mut self) -> LockGuard<'a, &'a str> {
        acquire(self.lock);
        
        // Convert current buf to a utf8 str
        let s = match std::str::from_utf8(self.val.get()) {
            Ok(s) => s,
            Err(_) => "<INVALID UTF8>",
        };
        
        LockGuard::new(self.lock, s)
    }
}

#[derive(Debug)]
pub struct StatBytes<'a> {
    pub(crate) lock: &'a mut AtomicU8,
    pub(crate) val: GenericBuf<'a>,
}

impl<'a> StatBytes<'a> {
    pub fn set(&mut self, new_val: &[u8]) {
        acquire(self.lock);
        self.val.set(new_val);
        release(self.lock);
    }
    pub fn get(&'a mut self) -> LockGuard<'a, &'a [u8]> {
        acquire(self.lock);
        LockGuard::new(self.lock, self.val.get())
    }
}


pub const TAG_PREFIX_TOTAL : &str = "total_";
pub const TAG_PREFIX_AVG : &str = "avg_";
pub const TAG_POSTFIX_HEX : &str = "_hex";
pub const TAG_POSTFIX_STR_DIR : &str = "_dir";
pub const TAG_POSTFIX_EPOCHS : &str = "_epoch_s";
pub const TAG_POSTFIX_US : &str = "_us";
pub const TAG_POSTFIX_MS : &str = "_ms";
pub const TAG_POSTFIX_SEC : &str = "_s";
pub const TAG_POSTFIX_MIN : &str = "_m";
pub const TAG_POSTFIX_HOUR : &str = "_h";

pub const STAT_TARGET_EXEC_TIME : &str = concat!("avg_target_exec_time_us");