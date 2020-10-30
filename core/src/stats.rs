use std::mem::size_of;
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::AtomicU8;

use ::cflib::*;
use ::log::*;
use ::simple_parse::{SpRead, SpWrite};

use crate::core::CfCore;
use crate::Result;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CoreStats {
    /// EPOCHS on startup
    pub start_time: cflib::StatNum,
    /// Number of executions since startup
    pub num_execs: cflib::StatNum,
    /// Time it takes for a single execution
    pub total_exec_time: cflib::StatNum,
    /// Time spent in the fuzzer core
    pub exec_time: cflib::StatNum,
    pub cwd: cflib::StatStr,
    pub cmd_line: cflib::StatStr,
    pub target_hash: cflib::StatBytes,
}
impl Default for CoreStats {
    fn default() -> Self {
        // This gets initialized properly before being used in init_stats()
        #[allow(invalid_value)]
        unsafe {
            Self {
                start_time: MaybeUninit::zeroed().assume_init(),
                num_execs: MaybeUninit::zeroed().assume_init(),
                total_exec_time: MaybeUninit::zeroed().assume_init(),
                exec_time: MaybeUninit::zeroed().assume_init(),
                cwd: MaybeUninit::zeroed().assume_init(),
                cmd_line: MaybeUninit::zeroed().assume_init(),
                target_hash: MaybeUninit::zeroed().assume_init(),
            }
        }
    }
}

impl<'a> CfCore<'a> {
    pub fn init_stats(&mut self) -> Result<()> {
        use std::fmt::Write;

        // Add a plugin for the core stats
        self.ctx.stats.new_plugin(&self.config.prefix)?;

        let mut tag = format!(
            "{}exec_time{}",
            cflib::TAG_PREFIX_AVG,
            cflib::TAG_POSTFIX_NS
        );
        self.stats.exec_time = match self.ctx.stats.new_stat(&tag, NewStat::Num(0)) {
            Ok(StatVal::Num(v)) => v,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to create core stat {} : {}",
                    tag, e
                )))
            }
            _ => panic!("Returned ok with invalid stat type"),
        };

        tag.clear();
        let _ = write!(
            &mut tag,
            "{}uptime{}",
            cflib::TAG_PREFIX_TOTAL,
            cflib::TAG_POSTFIX_EPOCHS
        );
        self.stats.start_time = match self.ctx.stats.new_stat(
            &tag,
            NewStat::Num(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
        ) {
            Ok(StatVal::Num(v)) => v,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to create core stat {} : {}",
                    tag, e
                )))
            }
            _ => panic!("Returned ok with invalid stat type"),
        };

        tag.clear();
        let _ = write!(&mut tag, "{}num_execs", cflib::TAG_PREFIX_TOTAL);
        self.stats.num_execs = match self.ctx.stats.new_stat(&tag, NewStat::Num(0)) {
            Ok(StatVal::Num(v)) => v,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to create core stat {} : {}",
                    tag, e
                )))
            }
            _ => panic!("Returned ok with invalid stat type"),
        };

        tag.clear();
        let _ = write!(
            &mut tag,
            "{}iteration_time{}",
            cflib::TAG_PREFIX_AVG,
            cflib::TAG_POSTFIX_NS
        );
        self.stats.total_exec_time = match self.ctx.stats.new_stat(&tag, NewStat::Num(0)) {
            Ok(StatVal::Num(v)) => v,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to create core stat {} : {}",
                    tag, e
                )))
            }
            _ => panic!("Returned ok with invalid stat type"),
        };

        tag.clear();
        let _ = write!(&mut tag, "working_dir{}", cflib::TAG_POSTFIX_PATH);
        self.stats.cwd = match self.ctx.stats.new_stat(
            &tag,
            NewStat::Str {
                max_size: self.config.cwd.len(),
                init_val: &self.config.cwd,
            },
        ) {
            Ok(StatVal::Str(v)) => v,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to create core stat {} : {}",
                    tag, e
                )))
            }
            _ => panic!("Returned ok with invalid stat type"),
        };

        tag.clear();
        let _ = write!(&mut tag, "cmd_line");
        let mut cmd_line: String = String::with_capacity(256);
        let fpath = Path::new(&*self.config.target);
        cmd_line.push_str(fpath.file_name().unwrap().to_str().unwrap());
        for arg in &self.config.target_args {
            cmd_line.push(' ');
            cmd_line.push_str(&arg);
        }
        self.stats.cmd_line = match self.ctx.stats.new_stat(
            &tag,
            NewStat::Str {
                max_size: cmd_line.len(),
                init_val: &cmd_line,
            },
        ) {
            Ok(StatVal::Str(v)) => v,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to create core stat {} : {}",
                    tag, e
                )))
            }
            _ => panic!("Returned ok with invalid stat type"),
        };

        tag.clear();
        let _ = write!(&mut tag, "target_crc{}", cflib::TAG_POSTFIX_HEX);
        self.stats.target_hash = match self.ctx.stats.new_stat(
            &tag,
            NewStat::Bytes {
                max_size: 4,
                init_val: &crc::crc32::checksum_ieee(&std::fs::read(&*self.config.target).unwrap())
                    .to_le_bytes(),
            },
        ) {
            Ok(StatVal::Bytes(v)) => v,
            Err(e) => {
                return Err(From::from(format!(
                    "Failed to create core stat {} : {}",
                    tag, e
                )))
            }
            _ => panic!("Returned ok with invalid stat type"),
        };

        Ok(())
    }
}

/// Struct used to request stat memory for specific stat types
pub enum NewStat<'a> {
    Num(u64),
    Bytes { max_size: usize, init_val: &'a [u8] },
    Str { max_size: usize, init_val: &'a str },
}

pub struct Stats<'a> {
    pub buf: &'a mut [u8],
    end_idx: usize,
    num_plugin_idx: usize,
    num_stats_idx: usize,
}

impl<'a> Stats<'a> {
    pub fn new(buf: &'a mut [u8]) -> Result<Self>
    where
        Self: 'a,
    {
        let mut res = Self {
            buf,
            end_idx: 0,
            num_plugin_idx: 0,
            num_stats_idx: 0,
        };

        let cur = res.buf.as_mut_ptr();

        // Init the cflib::CfStats
        unsafe {
            //CfStats.state
            let magic: *mut u32 = cur as _;
            let state: *mut CoreState = magic.add(1) as _;
            let pid: *mut u32 = state.add(1) as _;
            let num_plugins: *mut u16 = pid.add(1) as _;

            *magic = STAT_MAGIC;
            *state = ::cflib::CoreState::Initializing;
            *pid = std::process::id();
            *num_plugins = 0;

            res.num_plugin_idx = num_plugins as usize - cur as usize;
            res.end_idx = num_plugins.add(1) as usize - cur as usize;
        }

        Ok(res)
    }

    pub fn new_plugin(&mut self, name: &str) -> Result<()> {
        match self.get_state() {
            CoreState::Initializing => {}
            _ => {
                warn!("new_plugin called outside of initialization...");
                return Err(From::from("Cannot add stats after init".to_string()));
            }
        };

        let buf = self.buf.as_mut_ptr();
        let mut tmp: Vec<u8> = Vec::with_capacity(name.len());

        let num_plugins = unsafe { &mut *(buf.add(self.num_plugin_idx) as *mut u16) };

        let plugin_start_idx = self.end_idx;
        let _ = name.to_bytes(&mut tmp);
        if self.buf.len() < self.end_idx + tmp.len() {
            return Err(From::from("Stats memory is too small".to_string()));
        }

        //PluginStats.name
        unsafe {
            copy_nonoverlapping(tmp.as_ptr(), buf.add(self.end_idx), tmp.len());
            self.end_idx += tmp.len();
        }

        if self.buf.len() < self.end_idx + size_of::<u32>() {
            return Err(From::from("Stats memory is too small".to_string()));
        }
        //PluginStats.num_stats
        self.num_stats_idx = self.end_idx;
        unsafe {
            *(buf.add(self.num_stats_idx) as *mut u32) = 0;
        }
        self.end_idx += size_of::<u32>();

        *num_plugins += 1;

        let dbg = cflib::PluginStats::from_bytes(&self.buf[plugin_start_idx..self.end_idx])?.1;
        trace!("\tshm[{}] = {:?}", plugin_start_idx, dbg);
        Ok(())
    }

    pub fn new_stat(&mut self, tag: &str, stat: NewStat) -> Result<StatVal> {
        match self.get_state() {
            CoreState::Initializing => {}
            _ => {
                warn!("new_stat called outside of initialization...");
                return Err(From::from("Cannot add stats after init".to_string()));
            }
        };

        let buf = self.buf.as_mut_ptr();
        let mut tmp: Vec<u8> = Vec::with_capacity(tag.len());
        let num_plugins = unsafe { &mut *(buf.add(self.num_plugin_idx) as *mut u16) };
        let num_stats = unsafe { &mut *(buf.add(self.num_stats_idx) as *mut u32) };

        // Update the number of stats for the previous plugin
        if *num_plugins == 0 {
            return Err(From::from("new_stat called before new_plugin".to_string()));
        }

        let tag_len = match tag.to_bytes(&mut tmp) {
            Ok(l) => l,
            Err(_) => unreachable!(),
        };

        if self.buf.len() < self.end_idx + tag_len {
            return Err(From::from("Stats memory is too small".to_string()));
        }

        let stat_idx = self.end_idx;
        //Stat.tag
        unsafe {
            copy_nonoverlapping(tmp.as_ptr(), buf.add(self.end_idx), tag_len);
            self.end_idx += tag_len;
        }

        // Save where the stat's start is
        let stat_val_idx = self.end_idx;
        if let NewStat::Num(val) = stat {
            if self.buf.len() < self.end_idx + size_of::<u8>() + size_of::<u64>() {
                return Err(From::from("Stats memory is too small".to_string()));
            }
            unsafe {
                // id
                *(buf.add(self.end_idx) as *mut u8) = 0;
                self.end_idx += size_of::<u8>();
                //StatNum::num
                *(buf.add(self.end_idx) as *mut u64) = val;
                self.end_idx += size_of::<u64>();
            }
        } else {
            let (id, mut max_size, init_val) = match stat {
                NewStat::Bytes { max_size, init_val } => (1, max_size, init_val),
                NewStat::Str { max_size, init_val } => (2, max_size, init_val.as_bytes()),
                NewStat::Num(_) => unreachable!(),
            };
            // Make sure max_size makes sense
            if init_val.len() > max_size {
                max_size = init_val.len();
            }
            // Make sure this can fit
            if self.buf.len()
                < self.end_idx
                    + size_of::<u8>() // id
                    + size_of::<AtomicU8>() // Lock
                    + size_of::<u64>() // Capacity
                    + size_of::<u64>() // Len
                    + max_size
            // buf[]
            {
                return Err(From::from("Stats memory is too small".to_string()));
            }

            unsafe {
                // id
                *(buf.add(self.end_idx) as *mut u8) = id;
                self.end_idx += size_of::<u8>();
                // lock
                *(buf.add(self.end_idx) as *mut u8) = 0;
                self.end_idx += size_of::<AtomicU8>();
                // capacity
                *(buf.add(self.end_idx) as *mut u64) = max_size as u64;
                self.end_idx += size_of::<u64>();
                // len
                *(buf.add(self.end_idx) as *mut u64) = init_val.len() as u64;
                self.end_idx += size_of::<u64>();
                // buf
                copy_nonoverlapping(init_val.as_ptr(), buf.add(self.end_idx), init_val.len());
                self.end_idx += max_size;
            }
        }

        // we should be able to parse the stat successfully
        let stat_val = StatVal::from_bytes(&self.buf[stat_val_idx..self.end_idx])?.1;

        let dbg = Stat::from_bytes(&self.buf[stat_idx..self.end_idx])?.1;
        trace!("\tshm[{}] = {:?}", stat_val_idx, dbg);

        *num_stats += 1;
        Ok(stat_val)
    }

    pub fn set_state(&mut self, new_state: CoreState) {
        unsafe {
            *(self.buf.as_mut_ptr().add(size_of::<u32>()) as *mut CoreState) = new_state;
        };
    }

    pub fn get_state(&self) -> &CoreState {
        unsafe { &*(self.buf.as_ptr().add(size_of::<u32>()) as *mut CoreState) }
    }
}
