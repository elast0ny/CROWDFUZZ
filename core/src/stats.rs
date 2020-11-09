use std::convert::TryInto;
use std::io::Cursor;
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr::{read_volatile, write_volatile};

use ::cflib::*;
use ::log::*;
use ::simple_parse::{SpReadRawMut, SpWrite};

use crate::core::CfCore;
use crate::Result;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CoreStats<'b> {
    pub header: OwnedCfStatsHeader<'b>,
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
impl<'b> Default for CoreStats<'b> {
    fn default() -> Self {
        // This gets initialized properly before being used in init_stats()
        #[allow(invalid_value)]
        unsafe {
            Self {
                header: MaybeUninit::zeroed().assume_init(),
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

impl<'b> CfCore<'b> {
    pub fn init_stats(&mut self) -> Result<()> {
        use std::fmt::Write;

        // Add core plugin to stats
        if let Err(e) = self.ctx.stats.new_plugin(&self.config.prefix) {
            error!("Failed to created core plugin entry in stats memory : {}", e);
            return Err(e);
        }

        let mut tag = format!(
            "{}exec_time{}",
            cflib::TAG_PREFIX_AVG,
            cflib::TAG_POSTFIX_NS
        );
        self.stats.exec_time = match self.ctx.stats.new_stat(&tag, NewStat::Num(0)) {
            Ok(StatVal::Num(v)) => v,
            Err(e) => {
                error!("Failed to created core stat : {}", e);
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

pub struct Stats<'b> {
    pub cursor: Cursor<&'b mut [u8]>,
    pub header: OwnedCfStatsHeader<'b>,
    num_plugins: &'b mut u64,
    num_stats: &'b mut u64,
}

impl<'b> Stats<'b> {
    pub fn new(buf: &'b mut [u8]) -> Result<Self>
    where
        Self: 'b,
    {
        let mut cursor = Cursor::new(buf);
        let header = OwnedCfStatsHeader::init(&mut cursor)?;

        let num_plugins = <&mut u64>::from_mut_slice(&mut cursor)?;
        *num_plugins = 0;

        #[allow(invalid_value)]
        let res = Self {
            cursor,
            header,
            num_plugins,
            num_stats: unsafe { MaybeUninit::zeroed().assume_init() },
        };

        Ok(res)
    }

    pub fn new_plugin(&mut self, name: &str) -> Result<()> {
        if self.is_init() {
            warn!("new_plugin called outside of initialization...");
            return Err(From::from("Cannot add stats after init".to_string()));
        };

        let plugin_start_idx = self.cursor.position() as usize;

        //Write the name
        name.to_writer(&mut self.cursor)?;
        // Save index of the number of stats field
        self.num_stats = <&mut u64>::from_mut_slice(&mut self.cursor)?;

        *self.num_stats = 0;
        *self.num_plugins += 1;

        let dbg = cflib::PluginStats::from_mut_slice(&mut Cursor::new(
            &mut self.cursor.get_mut()[plugin_start_idx..],
        ))?;
        trace!("\tshm[{}] = {:?}", plugin_start_idx, dbg);
        Ok(())
    }

    pub fn new_stat(&mut self, tag: &str, stat: NewStat) -> Result<StatVal> {
        if self.is_init() {
            warn!("new_stat called outside of initialization...");
            return Err(From::from("Cannot add stats after init".to_string()));
        }

        // Update the number of stats for the previous plugin
        if *self.num_plugins == 0 {
            return Err(From::from("new_stat called before new_plugin".to_string()));
        }

        let stat_start_idx = self.cursor.position() as usize;

        // Write tag
        tag.to_writer(&mut self.cursor)?;

        #[allow(clippy::never_loop)]
        loop {
            let mut capacity: u32;
            let mut len: u32;
            let buf;
            match stat {
                NewStat::Num(v) => {
                    (0u8).to_writer(&mut self.cursor)?;
                    v.to_writer(&mut self.cursor)?;
                    break;
                }
                NewStat::Bytes { max_size, init_val } => {
                    (1u8).to_writer(&mut self.cursor)?;
                    capacity = max_size.try_into()?;
                    len = init_val.len().try_into()?;
                    buf = init_val;
                }
                NewStat::Str { max_size, init_val } => {
                    (2u8).to_writer(&mut self.cursor)?;
                    capacity = max_size.try_into()?;
                    len = init_val.len().try_into()?;
                    buf = init_val.as_bytes();
                }
            };
            // Make sure capacity is >= len
            if len > capacity {
                capacity = len;
            }
            
            std::sync::atomic::AtomicU8::new(0).to_writer(&mut self.cursor)?;
            capacity.to_writer(&mut self.cursor)?;
            len.to_writer(&mut self.cursor)?;
            buf.inner_to_writer(true, false, &mut self.cursor)?;
            // Pad with 0
            while len < capacity {
                (0u8).to_writer(&mut self.cursor)?;
                len += 1;
            }

            break;
        }

        // Leak the lifetime of this stat to be 'static
        let static_buf = unsafe {
            let buf = self.cursor.get_mut();
            std::slice::from_raw_parts_mut(buf.as_mut_ptr(), buf.len())
        };

        // we should be able to parse the stat successfully
        let stat =
            cflib::Stat::from_mut_slice(&mut Cursor::new(&mut static_buf[stat_start_idx..]))?;

        trace!("\tshm[{}] = {:?}", stat_start_idx, stat);

        *self.num_stats += 1;
        Ok(stat.val)
    }

    pub fn set_initialized(&mut self, is_init: bool) {
        unsafe {
            if is_init {
                write_volatile(self.header.initialized, 1)
            } else {
                write_volatile(self.header.initialized, 0)
            }
        };
    }

    pub fn is_init(&self) -> bool {
        unsafe { read_volatile(self.header.initialized) != 0 }
    }
}
