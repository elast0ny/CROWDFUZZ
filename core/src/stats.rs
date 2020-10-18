use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};
use std::path::Path;
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::atomic::AtomicU8;

use ::cflib::*;
use ::log::*;
use ::shared_memory::Shmem;
use ::simple_parse::{SpRead, SpWrite};

use crate::core::Core;
use crate::plugin::*;
use crate::Result;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CoreStats<'a> {
    buf: &'a mut [u8],
    end_idx: usize,
    num_plugin_idx: usize,
    // Points to the current plugin's num_stats field
    num_stats_idx: usize,
    // The number of stats the current plugin has
    cur_num_stats: u32,
    start_time: cflib::StatNum,
    cwd: cflib::StatStr,
    total_exec_time: cflib::StatNum,
    core_exec_time: cflib::StatNum,
    num_execs: cflib::StatNum,
    cmd_line: cflib::StatStr,
    target_hash: cflib::StatStr,
}

impl<'a> CoreStats<'a> {
    pub fn new(buf: &'a mut [u8]) -> Result<Self>
    where
        Self: 'a,
    {
        let mut res = unsafe {
            Self {
                buf,
                end_idx: 0,
                num_plugin_idx: 0,
                num_stats_idx: 0,
                cur_num_stats: 0,
                start_time: MaybeUninit::zeroed().assume_init(),
                cwd: MaybeUninit::zeroed().assume_init(),
                total_exec_time: MaybeUninit::zeroed().assume_init(),
                core_exec_time: MaybeUninit::zeroed().assume_init(),
                num_execs: MaybeUninit::zeroed().assume_init(),
                cmd_line: MaybeUninit::zeroed().assume_init(),
                target_hash: MaybeUninit::zeroed().assume_init(),
            }
        };

        let cur = res.buf.as_mut_ptr();

        // Init the cflib::StatHeader
        unsafe {
            //StatHeader.pid
            *(cur.add(res.end_idx) as *mut u32) = std::process::id();
            res.end_idx += size_of::<u32>();

            //StatHeader.state
            *(cur.add(res.end_idx) as *mut cflib::CoreState) = cflib::CoreState::Initializing;
            res.end_idx += size_of::<cflib::CoreState>();
            //StatHeader.num_plugins
            res.num_plugin_idx = res.end_idx;
            *(cur.add(res.num_plugin_idx) as *mut u16) = 0;
            res.end_idx += size_of::<u16>();
        }

        Ok(res)
    }

    pub fn new_plugin(&mut self, name: &str) -> Result<()> {
        let buf = self.buf.as_mut_ptr();
        let mut tmp: Vec<u8> = Vec::with_capacity(name.len());

        let num_plugins = unsafe { &mut *(buf.add(self.num_plugin_idx) as *mut u16) };

        // Update the number of stats for the previous plugin
        if *num_plugins != 0 {
            let num_stats = unsafe { &mut *(buf.add(self.num_stats_idx) as *mut u32) };
            *num_stats = self.cur_num_stats;
        }

        *num_plugins += 1;

        let name_len = match name.to_bytes(&mut tmp) {
            Ok(l) => l,
            Err(_) => unreachable!(),
        };

        if self.buf.len() < self.end_idx + name_len {
            return Err(From::from("Stats memory is too small".to_string()));
        }

        //PluginStats.name
        unsafe {
            copy_nonoverlapping(tmp.as_ptr(), buf.add(self.end_idx), name_len);
            self.end_idx += name_len;
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

        Ok(())
    }

    pub fn new_stat(&mut self, stat: NewStat) -> Result<StatVal> {
        let buf = self.buf.as_mut_ptr();
        let mut tmp: Vec<u8> = Vec::with_capacity(stat.tag.len());
        let num_plugins = unsafe { &mut *(buf.add(self.num_plugin_idx) as *mut u16) };
        let num_stats = unsafe { &mut *(buf.add(self.num_stats_idx) as *mut u32) };

        // Update the number of stats for the previous plugin
        if *num_plugins == 0 {
            return Err(From::from("new_stat called before new_plugin".to_string()));
        }

        let tag_len = match stat.tag.to_bytes(&mut tmp) {
            Ok(l) => l,
            Err(_) => unreachable!(),
        };

        if self.buf.len() < self.end_idx + tag_len {
            return Err(From::from("Stats memory is too small".to_string()));
        }

        //Stat.tag
        unsafe {
            copy_nonoverlapping(tmp.as_ptr(), buf.add(self.end_idx), tag_len);
            self.end_idx += tag_len;
        }
        debug!("stats[{}..{}] = {}", self.end_idx - tag_len, self.end_idx, stat.tag);
        let stat_val_idx = self.end_idx;
        let mut max_sz;
        //Stat.val
        match stat.val {
            NewStatVal::Num(val) => {
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
                debug!("stats[{}..{}] = 0x{:X}", self.end_idx - (size_of::<u8>() + size_of::<u64>()), self.end_idx, val);
            }
            NewStatVal::Bytes { max_size, init_val } => {
                max_sz = max_size;
                if init_val.len() > max_sz {
                    max_sz = init_val.len();
                }
                if self.buf.len()
                    < self.end_idx
                        + size_of::<u8>()
                        + size_of::<AtomicU8>()
                        + size_of::<u64>()
                        + size_of::<u64>()
                        + max_size
                {
                    return Err(From::from("Stats memory is too small".to_string()));
                }
                unsafe {
                    // id
                    *(buf.add(self.end_idx) as *mut u8) = 1;
                    self.end_idx += size_of::<u8>();
                    // lock
                    *(buf.add(self.end_idx) as *mut u8) = 0;
                    self.end_idx += size_of::<u8>();

                    // capacity
                    *(buf.add(self.end_idx) as *mut u64) = max_size as u64;
                    self.end_idx += size_of::<u64>();
                    // len
                    *(buf.add(self.end_idx) as *mut u64) = init_val.len() as u64;
                    self.end_idx += size_of::<u64>();
                    // buf
                    copy_nonoverlapping(init_val.as_ptr(), buf.add(self.end_idx), init_val.len());
                    self.end_idx += init_val.len();
                }

                debug!("stats[{}..{}] = {:X?}", stat_val_idx - self.end_idx, self.end_idx, init_val);
            }
            NewStatVal::Str { max_size, init_val } => {
                max_sz = max_size;
                if init_val.len() > max_sz {
                    max_sz = init_val.len();
                }
                if self.buf.len()
                    < self.end_idx
                        + size_of::<u8>()
                        + size_of::<AtomicU8>()
                        + size_of::<u64>()
                        + size_of::<u64>()
                        + max_size
                {
                    return Err(From::from("Stats memory is too small".to_string()));
                }
                unsafe {
                    // id
                    *(buf.add(self.end_idx) as *mut u8) = 2;
                    self.end_idx += size_of::<u8>();
                    // lock
                    *(buf.add(self.end_idx) as *mut u8) = 0;
                    self.end_idx += size_of::<u8>();
                    // capacity
                    *(buf.add(self.end_idx) as *mut u64) = max_size as u64;
                    self.end_idx += size_of::<u64>();
                    // len
                    *(buf.add(self.end_idx) as *mut u64) = init_val.len() as u64;
                    self.end_idx += size_of::<u64>();
                    // str
                    copy_nonoverlapping(init_val.as_ptr(), buf.add(self.end_idx), init_val.len());
                    self.end_idx += init_val.len();
                }
                debug!("stats[{}..{}] = {}", stat_val_idx - self.end_idx, self.end_idx, init_val);
            }
        }

        debug!("stats[{}..{}] = {:X?}", stat_val_idx, self.end_idx, &self.buf[stat_val_idx..self.end_idx]);
        let stat_val = StatVal::from_bytes(&self.buf[stat_val_idx..self.end_idx])?.1;

        *num_stats += 1;
        Ok(stat_val)
    }
}

impl<'a> Core<'a> {
    pub fn init_stats(&mut self) -> Result<()> {
        use std::fmt::Write;

        // Add a plugin for the core stats
        self.stats.new_plugin(&self.config.prefix)?;

        let mut tag = format!(
            "{}uptime{}",
            cflib::TAG_PREFIX_TOTAL,
            cflib::TAG_POSTFIX_EPOCHS
        );


        self.stats.start_time = match self.stats.new_stat(NewStat {
            tag: &tag,
            val: NewStatVal::Num(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs())
        }) {
            Ok(StatVal::Num(v)) => v,
            Err(e) => return Err(From::from(format!("Failed to create core stat {} : {}", tag, e))),
            _ => panic!("Rested Stat::num but got different"),
            
        };

        /*
        use std::fmt::Write;
        self.stats.init(&self.config.prefix)?;
        let mut tag = format!(
            "{}uptime{}",
            cflib::TAG_PREFIX_TOTAL_STR,
            cflib::NUM_POSTFIX_EPOCHS_STR
        );

        // Iteration time
        self.stats.start_time =
            unsafe { &mut *(self.stats.add(&tag, cflib::NewStat::Number)? as *mut _) };
        *self.stats.start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Iteration time
        tag.clear();
        let _ = write!(
            &mut tag,
            "{}iteration_time{}",
            cflib::TAG_PREFIX_AVERAGE_STR,
            cflib::NUM_POSTFIX_US_STR
        );
        self.stats.total_exec_time =
            unsafe { &mut *(self.stats.add(&tag, cflib::NewStat::Number)? as *mut _) };
        *self.stats.total_exec_time = 0;

        // Total execs
        tag.clear();
        let _ = write!(&mut tag, "{}execs", cflib::TAG_PREFIX_TOTAL_STR);
        self.stats.num_execs =
            unsafe { &mut *(self.stats.add(&tag, cflib::NewStat::Number)? as *mut _) };
        *self.stats.num_execs = 0;

        // Working dir
        self.stats.cwd = unsafe {
            &mut *(self.stats.add(
                "working_dir",
                cflib::NewStat::Str(self.config.cwd.len() as u16),
            )? as *mut _)
        };
        unsafe {
            cflib::update_dyn_stat(self.stats.cwd as *mut _, &self.config.cwd);
        }
        // Fuzz cmdline
        let mut cmd_line: String = String::with_capacity(256);
        let fpath = Path::new(&self.config.target);
        cmd_line.push_str(fpath.file_name().unwrap().to_str().unwrap());
        for arg in &self.config.target_args {
            cmd_line.push(' ');
            cmd_line.push_str(&arg);
        }
        self.stats.cmd_line = self
            .stats
            .add("cmd_line", cflib::NewStat::Str(cmd_line.len() as u16))?;
        unsafe {
            cflib::update_dyn_stat(self.stats.cmd_line as *mut _, &cmd_line);
        }

        //Target binary hash
        tag.clear();
        let _ = write!(&mut tag, "bin_bash{}", cflib::BYTES_POSTFIX_HEX_STR);
        self.stats.target_hash = self.stats.add("bin_hash_hex", cflib::NewStat::Bytes(4))?;
        unsafe {
            cflib::update_dyn_stat(
                self.stats.target_hash as *mut _,
                &crc::crc32::checksum_ieee(&std::fs::read(&self.config.target).unwrap())
                    .to_le_bytes(),
            );
        }
        */
        Ok(())
    }
}
/*
pub struct CoreStats {
    prefix: String,
    pub stats_memory: Shmem,
    pub header: &'static mut cflib::StatFileHeader,
    pub start_time: &'static mut u64,
    pub cwd: *mut c_void,
    pub total_exec_time: &'static mut u64,
    pub core_exec_time: &'static mut u64,
    pub num_execs: &'static mut u64,
    pub cmd_line: *mut c_void,
    pub target_hash: *mut c_void,
}

impl CoreStats {
    pub fn new(shmem: Shmem) -> CoreStats {
        unsafe {
            CoreStats {
                prefix: String::new(),
                stats_memory: shmem,
                header: &mut *null_mut(),
                start_time: &mut *null_mut(),
                cwd: null_mut(),
                total_exec_time: &mut *null_mut(),
                core_exec_time: &mut *null_mut(),
                num_execs: &mut *null_mut(),
                cmd_line: null_mut(),
                target_hash: &mut *null_mut(),
            }
        }
    }

    pub fn init(&mut self, core_name: &str) -> Result<()> {
        self.prefix = core_name.to_string();
        let shmem_base: *mut u8 = self.stats_memory.as_ptr();
        // Init the stats header
        self.header = unsafe { &mut *(shmem_base as *mut _) };
        self.header.stat_len = 0;
        self.header.pid = std::process::id();
        self.header.state = cflib::CORE_INITIALIZING as _;
        self.header.stat_len += size_of::<cflib::StatFileHeader>() as u32;

        // Add the stats for the "core" component
        self.add_component(None)?;
        Ok(())
    }

    pub fn add_component(&mut self, plugin: Option<&mut Plugin>) -> Result<()> {
        let shmem_base: *mut u8 = self.stats_memory.as_ptr();

        let plugin_name: &str = match plugin {
            None => &self.prefix,
            Some(ref plugin) => plugin.name(),
        };

        if self.header.stat_len as usize + size_of::<cflib::StatHeader>() + plugin_name.len()
            >= self.stats_memory.len()
        {
            return Err(From::from(format!("No more space to allocate stats... you can increase this value through the 'shmem_size' config. (Current value {} bytes)", self.stats_memory.len())));
        }

        let comp_header: &mut cflib::StatHeader =
            unsafe { &mut *(shmem_base.add(self.header.stat_len as _) as *mut _) };
        self.header.stat_len += size_of::<cflib::StatHeader>() as u32;
        let tag_ptr: *mut u8 = unsafe { shmem_base.add(self.header.stat_len as _) as *mut _ };
        // Write the header values
        comp_header.stat_type = cflib::STAT_NEWCOMPONENT as _;
        comp_header.tag_len = plugin_name.len() as u16;
        //Write the component name
        unsafe {
            std::ptr::copy(plugin_name.as_ptr(), tag_ptr, comp_header.tag_len as usize);
        }
        self.header.stat_len += plugin_name.len() as u32;

        //Every component gets an exec time stat
        let mut tag = String::from(cflib::TAG_PREFIX_AVERAGE_STR);
        tag.push_str("exec_time");
        tag.push_str(cflib::NUM_POSTFIX_US_STR);
        let exec_time_ptr: *mut u64 =
            unsafe { &mut *(self.add(&tag, cflib::NewStat::Number)? as *mut _) };
        match plugin {
            None => {
                self.core_exec_time = unsafe { &mut *exec_time_ptr };
                *self.core_exec_time = 0;
            }
            Some(cur_plugin) => {
                cur_plugin.exec_time = unsafe { &mut *exec_time_ptr };
                *cur_plugin.exec_time = 0;
            }
        };

        Ok(())
    }

    pub fn add(&mut self, tag: &str, new_stat: cflib::NewStat) -> Result<*mut c_void> {
        if self.header.state != cflib::CORE_INITIALIZING as cflib::CoreState {
            return Err(From::from(
                "Plugins cannot reserve stat space after initialization".to_owned(),
            ));
        }

        let header_len = new_stat.header_len();
        let mut max_data_len = new_stat.max_len() as usize;
        if header_len != size_of::<cflib::StatHeader>() {
            // prepend a cur_data_len field to dynamic fields
            max_data_len += size_of::<u16>();
        }

        if header_len + tag.len() + max_data_len >= self.stats_memory.len() {
            return Err(
                From::from(
                    format!(
                        "No more space to allocate stat {:?}... you can increase this value through the 'shmem_size' config. (Current value {} bytes)", new_stat, self.stats_memory.len()
                    )
                )
            );
        }

        let shmem_base: *mut u8 = self.stats_memory.as_ptr();
        let header_ptr: *mut u8 =
            unsafe { &mut *(shmem_base.add(self.header.stat_len as _) as *mut _) };
        self.header.stat_len += header_len as u32;

        //init the header
        let stat_header = if header_len == size_of::<cflib::StatHeader>() {
            unsafe { &mut *(header_ptr as *mut _) }
        } else {
            let dyn_header: &mut cflib::StatHeaderDyn = unsafe { &mut *(header_ptr as *mut _) };
            dyn_header.data_len = max_data_len as u16;
            &mut dyn_header.header
        };
        stat_header.stat_type = new_stat.to_id();
        stat_header.tag_len = tag.len() as u16;

        // Write the tag
        let tag_ptr: *mut u8 =
            unsafe { &mut *(shmem_base.add(self.header.stat_len as _) as *mut _) };
        unsafe {
            std::ptr::copy(tag.as_ptr(), tag_ptr, tag.len());
        }
        self.header.stat_len += tag.len() as u32;

        //Return pointer to data
        let data_ptr: *mut c_void = unsafe { shmem_base.add(self.header.stat_len as _) as *mut _ };
        self.header.stat_len += max_data_len as u32;

        trace!(
            "(\"{}\") : Header {:p} Tag {:p}[{}] Data {:p} {:?}",
            tag,
            header_ptr,
            tag_ptr,
            tag.len(),
            data_ptr,
            new_stat
        );

        Ok(data_ptr)
    }
}
*/
