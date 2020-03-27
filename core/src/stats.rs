use std::ffi::c_void;
use std::mem::{size_of, size_of_val};
use std::ptr::null_mut;

use ::log::*;
use ::shared_memory::SharedMem;

use crate::config::*;
use crate::plugin::*;

pub struct CoreStats {
    pub reserved_stats: usize,
    pub stats_memory: SharedMem,

    pub state: &'static mut cflib::CoreState,
    pub pid: &'static mut u32,
    pub cwd: *mut c_void,
    pub exec_time: &'static mut u64,
    pub num_execs: &'static mut u64,
    pub cmd_line: *mut c_void,
    pub target_hash: &'static mut u32,
}
impl CoreStats {
    pub fn new(shmem: SharedMem) -> CoreStats {
        unsafe {
            CoreStats {
                reserved_stats: 0,
                stats_memory: shmem,
                state: &mut *null_mut(),

                pid: &mut *null_mut(),
                cwd: null_mut(),
                exec_time: &mut *null_mut(),
                num_execs: &mut *null_mut(),
                cmd_line: null_mut(),
                target_hash: &mut *null_mut(),
            }
        }
    }

    pub fn init(&mut self, config: &Config) {
        self.state = unsafe { &mut *(self.stats_memory.get_ptr() as *mut _) };
        self.reserved_stats += size_of_val(self.state);
        *self.state = cflib::CORE_INITIALIZING;

        // Add the headers for the "core" component
        self.add_component(None);

        // Fuzzer pid
        self.pid =
            unsafe { &mut *(self.add(cflib::STAT_U32, "pid", size_of_val(self.pid) as u16) as *mut _) };
        *self.pid = std::process::id();

        // Current Working directory
        /*
        self.cwd = self.add(CFSTAT_STR, "cwd", config.cwd.to_bytes_with_nul().len() as u16);
        Stat::write_cstr(self.cwd, &config.cwd);
        */
        self.num_execs = unsafe {
            &mut *(self.add(cflib::STAT_U64, "num_execs", size_of_val(self.num_execs) as u16) as *mut _)
        };
        *self.num_execs = 0;

        //Fuzz command line
        /*
        let mut cmd_line: String = String::with_capacity(256);
        cmd_line.push_str(Path::new(config.target.to_str().unwrap()).file_name().unwrap().to_str().unwrap());
        for arg in &config.target_args {
            cmd_line.push(' ');
            cmd_line.push_str(arg.to_str().unwrap());
        }
        let cmd_line: CString = CString::new(cmd_line).unwrap();
        self.cmd_line = self.add(CFSTAT_STR, "cmd_line", cmd_line.to_bytes_with_nul().len() as _);
        Stat::write_cstr(self.cmd_line, cmd_line);
        */

        //Target binary hash
        self.target_hash = unsafe {
            &mut *(self.add(
                cflib::STAT_U32,
                "target_id",
                size_of_val(self.target_hash) as u16,
            ) as *mut _)
        };
        *self.target_hash = crc::crc32::checksum_ieee(&std::fs::read(&config.target).unwrap());
    }

    pub fn add_component(&mut self, plugin: Option<&mut Plugin>) {
        let shmem_base: *mut u8 = self.stats_memory.get_ptr() as *mut _;

        let plugin_name: &str = match plugin {
            None => "core",
            Some(ref plugin) => plugin.name(),
        };

        if self.reserved_stats + size_of::<cflib::StatHeader>() + plugin_name.len()
            >= self.stats_memory.get_size()
        {
            panic!("No more space to allocate stats... you can increase this value through the 'shmem_size' config. (Current value {} bytes)", self.stats_memory.get_size());
        }

        let comp_header: &mut cflib::StatHeader =
            unsafe { &mut *(shmem_base.add(self.reserved_stats) as *mut _) };
        self.reserved_stats += size_of::<cflib::StatHeader>();
        let tag_ptr: *mut u8 = unsafe { shmem_base.add(self.reserved_stats) as *mut _ };
        // Write the header values
        comp_header.stat_type = cflib::STAT_NEWCOMPONENT;
        comp_header.tag_len = plugin_name.len() as u16;
        //Write the component name
        unsafe {
            std::ptr::copy(plugin_name.as_ptr(), tag_ptr, comp_header.tag_len as usize);
        }
        trace!(
            "{:?}(\"{}\") : Header {:p} Tag {:p}[{}]",
            comp_header.stat_type,
            plugin_name,
            comp_header,
            tag_ptr,
            comp_header.tag_len
        );
        self.reserved_stats += plugin_name.len();

        //Every component gets an exec time stat
        let exec_time_ptr: *mut u64 =
            unsafe { &mut *(self.add(cflib::STAT_U64, "exec_time", size_of::<u64>() as u16) as *mut _) };

        match plugin {
            None => {
                self.exec_time = unsafe { &mut *exec_time_ptr };
                *self.exec_time = 0;
            }
            Some(cur_plugin) => {
                cur_plugin.exec_time = unsafe { &mut *exec_time_ptr };
                *cur_plugin.exec_time = 0;
            }
        };
    }

    pub fn add<I: AsRef<str>>(
        &mut self,
        stat_type: cflib::StatType,
        tag: I,
        requested_sz: u16,
    ) -> *mut c_void {
        if *self.state != cflib::CORE_INITIALIZING {
            panic!("Plugins cannot reserve stat space after initialization");
        }

        // Get the actual data size & data type
        let mut data_type: cflib::StatType = stat_type;
        let data_sz: u16 = match stat_type {
            cflib::STAT_NEWCOMPONENT => panic!("Plugins cannot use StatId::NewComponent"),
            cflib::STAT_BYTES => requested_sz,
            cflib::STAT_STR => requested_sz,
            _ => {
                let expected_sz = cflib::stat_data_len(stat_type).unwrap();
                if expected_sz != requested_sz {
                    warn!(
                        "Plugin requested bad size ({}) for stat {:?}",
                        requested_sz, stat_type
                    );
                    data_type = cflib::STAT_BYTES;
                    requested_sz
                } else {
                    expected_sz
                }
            }
        };
        let header_sz: u16 = cflib::stat_header_len(data_type);

        if self.reserved_stats + header_sz as usize + tag.as_ref().len() + data_sz as usize
            >= self.stats_memory.get_size()
        {
            panic!("No more space to allocate stats... you can increase this value through the 'shmem_size' config. (Current value {} bytes)", self.stats_memory.get_size());
        }

        let shmem_base: *mut u8 = self.stats_memory.get_ptr() as *mut _;
        let header_ptr: *mut u8 = unsafe { &mut *(shmem_base.add(self.reserved_stats) as *mut _) };
        self.reserved_stats += header_sz as usize;

        //init the header
        let comp_header: &mut cflib::StatHeader = match data_type {
            cflib::STAT_BYTES | cflib::STAT_STR => unsafe { &mut *(header_ptr as *mut _) },
            _ => {
                let dyn_header: &mut cflib::StatHeaderDyn = unsafe { &mut *(header_ptr as *mut _) };
                &mut dyn_header.header
            }
        };
        comp_header.stat_type = data_type;
        comp_header.tag_len = tag.as_ref().len() as u16;

        // Write the tag
        let tag_ptr: *mut u8 = unsafe { &mut *(shmem_base.add(self.reserved_stats) as *mut _) };
        unsafe {
            std::ptr::copy(tag.as_ref().as_ptr(), tag_ptr, tag.as_ref().len());
        }
        if data_sz as usize + self.reserved_stats > self.stats_memory.get_size() {
            panic!("Plugin has requested ")
        }
        self.reserved_stats += tag.as_ref().len();

        //Return pointer to data
        let data_ptr: *mut c_void =
            unsafe { &mut *(shmem_base.add(self.reserved_stats) as *mut _) };
        self.reserved_stats += data_sz as usize;

        trace!(
            "{:?}(\"{}\") : Header {:p} Tag {:p}[{}] Data {:p}[{}]",
            data_type,
            tag.as_ref(),
            header_ptr,
            tag_ptr,
            tag.as_ref().len(),
            data_ptr,
            data_sz
        );

        data_ptr
    }
}
