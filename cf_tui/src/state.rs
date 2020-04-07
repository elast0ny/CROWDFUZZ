use std::{collections::HashSet, error::Error, mem::size_of_val};

use ::shared_memory::SharedMem;
use ::sysinfo::{ProcessExt, System, SystemExt};

pub struct CachedStat {
    pub stat_ref: cflib::StatRef,
    pub cache: cflib::StatVal,
    pub str_repr: String,
}

impl CachedStat {
    /// Return the stat tag
    pub fn get_tag(&self) -> &str {
        self.stat_ref.get_tag()
    }

    /// Returns the current string representation of the stat data
    pub fn as_str(&self) -> &str {
        self.str_repr.as_str()
    }

    /// Updates itself to represent the current value in the stats memory
    pub fn update(&mut self) {
        if !self.cache.is_equal(&self.stat_ref) {
            self.cache.update(&self.stat_ref);
            self.cache.write_str(&mut self.str_repr);
        }
    }
}

pub struct Plugin {
    pub name: String,
    // Name with some details
    pub stats: Vec<CachedStat>,
    pub max_tag_len: u16,
    pub max_val_len: u16,
}
impl Plugin {
    pub fn refresh_stat_vals(&mut self) {
        self.max_val_len = 0;
        let stats_iter = self.stats.iter_mut().skip(1);
        for stat in stats_iter {
            stat.update();
            // Update the longest name value
            if stat.str_repr.len() as u16 > self.max_val_len {
                self.max_val_len = stat.str_repr.len() as u16;
            }
        }
    }
}
pub struct Fuzzer {
    #[allow(unused)]
    shmem: SharedMem,
    pub cur_plugin_idx: usize,
    pub pid: u32,
    pub core: Plugin,
    pub max_plugin_name_len: u16,
    pub plugins: Vec<Plugin>,
}

impl Fuzzer {
    pub fn is_alive(pid: u32, sys_info: &mut System) -> bool {
        match sys_info.get_process(pid as _) {
            None => false,
            Some(p) => p.name().starts_with("crowdfuzz"),
        }
    }

    pub fn new(shmem: SharedMem, sys_info: &mut System) -> Result<Self, Box<dyn Error>> {
        let shmem_base: *mut u8 = shmem.get_ptr() as *mut _;
        let header: &'static cflib::StatFileHeader = unsafe { &mut *(shmem_base as *mut _) };
        let mut shmem_idx = size_of_val(header);
        //println!("{:p} : {} {} {}", shmem_base, header.stat_len, header.pid, header.state);

        // Can safely read header
        if header.stat_len <= size_of_val(header) as u32 {
            return Err(From::from(format!("Fuzzer not initialized yet")));
        // Core is initialized
        } else if header.state != cflib::CORE_FUZZING {
            return Err(From::from(format!("Fuzzer not initialized yet")));
        } else if !Fuzzer::is_alive(header.pid, sys_info) {
            // Trigger a refresh to make sure it didnt spawn recently
            sys_info.refresh_processes();
            if !Fuzzer::is_alive(header.pid, sys_info) {
                return Err(From::from(format!(
                    "Fuzzer with pid {} not alive anymore...",
                    header.pid
                )));
            }
        }

        // First stat should be the fuzzer core
        let core_name: String;
        let cur_stat = cflib::StatRef::from_base_ptr(
            unsafe { shmem_base.add(shmem_idx) },
            header.stat_len as usize - shmem_idx,
        )?;
        let cur_val = cur_stat.to_owned();
        match cur_val {
            cflib::StatVal::Component(name) => {
                core_name = name;
            }
            _ => {
                return Err(From::from(
                    "Fuzzer stats does not start with a Component stat".to_owned(),
                ))
            }
        };
        shmem_idx += cur_stat.mem_len();

        let mut cur_fuzzer = Fuzzer {
            shmem,
            pid: header.pid,
            core: Plugin {
                max_tag_len: core_name.len() as u16,
                name: core_name,
                stats: Vec::new(),
                max_val_len: 0,
            },
            max_plugin_name_len: 0,
            cur_plugin_idx: 0,
            plugins: Vec::new(),
        };

        let mut cur_plugin: &mut Plugin = &mut cur_fuzzer.core;
        loop {
            if shmem_idx >= header.stat_len as usize {
                break;
            }
            let cur_stat = cflib::StatRef::from_base_ptr(
                unsafe { shmem_base.add(shmem_idx) },
                header.stat_len as usize - shmem_idx,
            )?;
            shmem_idx += cur_stat.mem_len();

            let cur_tag = cur_stat.get_tag();
            if cur_tag.len() as u16 > cur_plugin.max_tag_len {
                cur_plugin.max_tag_len = cur_tag.len() as u16;
            }

            //println!("{} {:?}", cur_stat.get_tag(), cur_stat.get_data());
            let cur_val = cur_stat.to_owned();
            let mut str_repr = String::new();
            cur_val.write_str(&mut str_repr);
            match cur_val {
                cflib::StatVal::Component(name) => {
                    if name.len() as u16 > cur_fuzzer.max_plugin_name_len {
                        cur_fuzzer.max_plugin_name_len = name.len() as u16;
                    }
                    cur_plugin.refresh_stat_vals();
                    cur_fuzzer.plugins.push(Plugin {
                        max_tag_len: name.len() as u16,
                        name,
                        stats: Vec::new(),
                        max_val_len: 0,
                    });
                    cur_plugin = cur_fuzzer.plugins.last_mut().unwrap();
                }
                _ => {
                    cur_plugin.stats.push(CachedStat {
                        stat_ref: cur_stat,
                        cache: cur_val,
                        str_repr,
                    });
                }
            }
        }
        Ok(cur_fuzzer)
    }
}

pub struct State {
    pub unique_fuzzers: HashSet<String>,
    pub fuzzers: Vec<Fuzzer>,
    pub fuzzer_prefix: String,
    pub stat_file_prefix: String,
    pub monitored_dirs: Vec<String>,
    pub sys_info: System,
    pub changed: bool,
    pub tab_titles: Vec<String>,
}

impl State {
    /// Removes any dead fuzzer and scans the directories for new fuzzers
    pub fn update_fuzzers(&mut self) {
        self.sys_info.refresh_processes();
        let mut to_del: Vec<usize> = Vec::new();
        for (idx, fuzzer) in self.fuzzers.iter().enumerate() {
            if !Fuzzer::is_alive(fuzzer.pid, &mut self.sys_info) {
                to_del.push(idx);
            }
        }
        if to_del.len() > 0 {
            self.remove_fuzzers(&to_del);
        }

        let mut found_files = Vec::new();
        for dir in &self.monitored_dirs {
            if let Ok(mut dir_list) = std::fs::read_dir(dir) {
                while let Some(Ok(entry)) = dir_list.next() {
                    let metadata = match entry.metadata() {
                        Ok(v) => v,
                        _ => continue,
                    };
                    if !metadata.is_file() {
                        continue;
                    }

                    let file_path = entry.path();
                    if file_path
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .starts_with(&self.stat_file_prefix)
                    {
                        found_files.push(file_path);
                    }
                }
            }
        }

        // Try to load all the files
        for fpath in found_files.iter() {
            let shmem = match SharedMem::open_linked(&fpath) {
                Ok(m) => {
                    // we already are tracking this fuzzer
                    if self.unique_fuzzers.contains(m.get_os_path()) {
                        continue;
                    }
                    m
                }
                Err(_e) => {
                    //println!("Failed to open {} : {:?}", fpath.to_string_lossy(), e);
                    continue;
                }
            };

            let new_fuzzer = match Fuzzer::new(shmem, &mut self.sys_info) {
                Ok(f) => f,
                Err(_e) => {
                    //println!("Failed to parse '{}' : {:?}", fpath.to_string_lossy(), e);
                    continue;
                }
            };
            self.add_fuzzer(new_fuzzer);
        }
    }

    fn add_fuzzer(&mut self, fuzzer: Fuzzer) {
        self.changed = true;
        self.unique_fuzzers
            .insert(fuzzer.shmem.get_os_path().to_string());
        self.fuzzers.push(fuzzer);
    }

    fn remove_fuzzers(&mut self, idx_list: &[usize]) {
        self.changed = true;
        for idx in idx_list.iter().rev() {
            let fuzzer = self.fuzzers.remove(*idx);
            self.unique_fuzzers.remove(fuzzer.shmem.get_os_path());
        }        
    }
}
