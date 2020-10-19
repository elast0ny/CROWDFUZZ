use std::path::{Path, PathBuf};
use std::collections::HashSet;

use ::log::*;
use ::cflib::CfStats;
use ::shared_memory::{Shmem, ShmemConf};
use ::simple_parse::SpRead;
use ::sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

use crate::*;

pub struct State {
    watch_dir: PathBuf,
    stats_file_prefix: String,
    fuzzers: Vec<Fuzzer>,
    sys_info: System,
}
impl State {
    pub fn new(args: &mut clap::ArgMatches) -> Self {

        let mut r = Self {
            watch_dir: PathBuf::from(args.value_of("project_state").unwrap()),
            stats_file_prefix: String::from(args.value_of("stats_prefix").unwrap()),
            fuzzers: Vec::new(),
            sys_info: System::new_with_specifics(
                RefreshKind::new().with_processes().with_cpu().with_memory(),
            ),
        };

        r.sys_info.refresh_cpu();
        r.sys_info.refresh_memory();

        r
    }
    pub fn update_fuzzer_list(&mut self) {
        self.sys_info.refresh_processes();

        // Delete dead fuzzers
        let mut to_del = Vec::new();
        for (idx, fuzzer) in self.fuzzers.iter().enumerate() {
            if !fuzzer.is_alive(&mut self.sys_info) {
                to_del.push(idx);
            }
        }
        for idx in to_del.iter().rev() {
            self.fuzzers.remove(*idx);
        }

        let mut found_files = Vec::new();
        // Scan for new
        if let Ok(mut dir_list) = std::fs::read_dir(&self.watch_dir) {
            while let Some(Ok(item)) = dir_list.next() {

                // Ignore files without the stats prefix
                if !item.file_name().to_str().unwrap().starts_with(&self.stats_file_prefix) {
                    continue;
                }

                // Ignore directories
                match item.metadata() {
                    Ok(m) if m.is_file() => {},
                    _ => continue,
                };

                found_files.push(item.path())
            }
        }

        for fpath in &found_files {
            let shmem = match ShmemConf::new().flink(&fpath).open() {
                Ok(m) => m,
                Err(_e) => {
                    //warn!("Found invalid fuzzer stat file : {}", fpath.to_string_lossy());
                    continue
                },
            };
        
            let cur = shmem.as_ptr();

            let state: CoreState;
            let pid: u32;
            
            unsafe {
                //CfStats.state
                res.set_state(cflib::CoreState::Initializing);
                res.end_idx += size_of::<cflib::CoreState>();
                //CfStats.pid
                *(cur.add(res.end_idx) as *mut u32) = std::process::id();
                res.end_idx += size_of::<u32>();
            }
        }



    }
}

pub struct Fuzzer {
    shmem: Shmem,
    stats: CfStats,
}

impl Fuzzer {
    pub fn from_path(path: &Path) -> Result<Self> {

        Err(From::from("Not implemented yet"))
    }

    pub fn is_alive(&self, sys_info: &mut System) -> bool {
        // Check if our PID is alive and is a crowdfuzz process
        match sys_info.get_process(self.stats.pid as usize) {
            None => false,
            Some(p) => p.name().starts_with("crowdfuzz"),
        }
    }
}