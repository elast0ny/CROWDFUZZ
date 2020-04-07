use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use std::ptr::null_mut;

use ::log::*;
use ::shared_memory::SharedMem;

use crate::core::Core;
use crate::plugin::*;
use crate::Result;
use std::time::{SystemTime, UNIX_EPOCH};

impl Core {
    pub fn init_stats(&mut self) -> Result<()> {
        self.stats.init(&self.config.prefix)?;

        // Iteration time
        self.stats.start_time =
            unsafe { &mut *(self.stats.add("uptime_epochs", cflib::NewStat::U64)? as *mut _) };
        *self.stats.start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Iteration time
        self.stats.total_exec_time =
            unsafe { &mut *(self.stats.add("total_exec_time_us", cflib::NewStat::U64)? as *mut _) };
        *self.stats.total_exec_time = 0;
        // Total execs
        self.stats.num_execs =
            unsafe { &mut *(self.stats.add("total_execs", cflib::NewStat::U64)? as *mut _) };
        *self.stats.num_execs = 0;
        // Working dir
        self.stats.cwd = unsafe {
            &mut *(self.stats.add(
                "working_dir",
                cflib::NewStat::Str(self.config.cwd.len() as u16),
            )? as *mut _)
        };
        cflib::update_dyn_stat(self.stats.cwd as *mut _, &self.config.cwd);
        // Fuzz cmdline
        let mut cmd_line: String = String::with_capacity(256);
        let fpath = Path::new(&self.config.target);
        cmd_line.push_str(fpath.file_name().unwrap().to_str().unwrap());
        for arg in &self.config.target_args {
            cmd_line.push(' ');
            cmd_line.push_str(&arg);
        }
        self.stats.cmd_line = unsafe {
            &mut *(self
                .stats
                .add("cmd_line", cflib::NewStat::Str(cmd_line.len() as u16))?
                as *mut _)
        };
        cflib::update_dyn_stat(self.stats.cmd_line as *mut _, &cmd_line);
        //Target binary hash
        self.stats.target_hash =
            unsafe { &mut *(self.stats.add("bin_hash", cflib::NewStat::U32)? as *mut _) };
        *self.stats.target_hash =
            crc::crc32::checksum_ieee(&std::fs::read(&self.config.target).unwrap());

        Ok(())
    }
}

pub struct CoreStats {
    prefix: String,
    pub stats_memory: SharedMem,
    pub header: &'static mut cflib::StatFileHeader,
    pub start_time: &'static mut u64, 
    pub cwd: *mut c_void,
    pub total_exec_time: &'static mut u64,
    pub core_exec_time: &'static mut u64,
    pub num_execs: &'static mut u64,
    pub cmd_line: *mut c_void,
    pub target_hash: &'static mut u32,
}
impl CoreStats {
    pub fn new(shmem: SharedMem) -> CoreStats {
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
        let shmem_base: *mut u8 = self.stats_memory.get_ptr() as *mut _;
        // Init the stats header
        self.header = unsafe { &mut *(shmem_base as *mut _) };
        self.header.stat_len = 0;
        self.header.pid = std::process::id();
        self.header.state = cflib::CORE_INITIALIZING;

        self.header.stat_len += size_of::<cflib::StatFileHeader>() as u32;

        // Add the stats for the "core" component
        self.add_component(None)?;

        Ok(())
    }

    pub fn add_component(&mut self, plugin: Option<&mut Plugin>) -> Result<()> {
        let shmem_base: *mut u8 = self.stats_memory.get_ptr() as *mut _;

        let plugin_name: &str = match plugin {
            None => &self.prefix,
            Some(ref plugin) => plugin.name(),
        };

        if self.header.stat_len as usize + size_of::<cflib::StatHeader>() + plugin_name.len()
            >= self.stats_memory.get_size()
        {
            return Err(From::from(format!("No more space to allocate stats... you can increase this value through the 'shmem_size' config. (Current value {} bytes)", self.stats_memory.get_size())));
        }

        let comp_header: &mut cflib::StatHeader =
            unsafe { &mut *(shmem_base.add(self.header.stat_len as _) as *mut _) };
        self.header.stat_len += size_of::<cflib::StatHeader>() as u32;
        let tag_ptr: *mut u8 = unsafe { shmem_base.add(self.header.stat_len as _) as *mut _ };
        // Write the header values
        comp_header.stat_type = cflib::STAT_NEWCOMPONENT;
        comp_header.tag_len = plugin_name.len() as u16;
        //Write the component name
        unsafe {
            std::ptr::copy(plugin_name.as_ptr(), tag_ptr, comp_header.tag_len as usize);
        }
        self.header.stat_len += plugin_name.len() as u32;

        //Every component gets an exec time stat
        match plugin {
            None => {
                let exec_time_ptr: *mut u64 =
                    unsafe { &mut *(self.add("core_exec_time_us", cflib::NewStat::U64)? as *mut _) };
                self.core_exec_time = unsafe { &mut *exec_time_ptr };
                *self.core_exec_time = 0;
            }
            Some(cur_plugin) => {
                let exec_time_ptr: *mut u64 =
                    unsafe { &mut *(self.add("exec_time_us", cflib::NewStat::U64)? as *mut _) };
                cur_plugin.exec_time = unsafe { &mut *exec_time_ptr };
                *cur_plugin.exec_time = 0;
            }
        };

        Ok(())
    }

    pub fn add(&mut self, tag: &str, new_stat: cflib::NewStat) -> Result<*mut c_void> {
        if self.header.state != cflib::CORE_INITIALIZING {
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

        if header_len + tag.len() + max_data_len >= self.stats_memory.get_size() {
            return Err(
                From::from(
                    format!(
                        "No more space to allocate stat {:?}... you can increase this value through the 'shmem_size' config. (Current value {} bytes)", new_stat, self.stats_memory.get_size()
                    )
                )
            );
        }

        let shmem_base: *mut u8 = self.stats_memory.get_ptr() as *mut _;
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
