use std::fmt::Write;
use std::path::PathBuf;

use ::cflib::CfStats;
use ::shared_memory::{Shmem, ShmemConf};
use ::simple_parse::SpReadRawMut;
use ::sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

use crate::*;

pub struct State {
    watch_dir: PathBuf,
    stats_file_prefix: String,
    pub sys_info: System,
    pub fuzzers: Vec<Fuzzer>,
    pub ui: UiState,
}
impl State {
    pub fn new(args: &clap::ArgMatches) -> Self {
        let mut r = Self {
            watch_dir: PathBuf::from(args.value_of("project_state").unwrap()),
            stats_file_prefix: String::from(args.value_of("stats_prefix").unwrap()),
            fuzzers: Vec::new(),
            sys_info: System::new_with_specifics(
                RefreshKind::new().with_processes().with_cpu().with_memory(),
            ),
            ui: UiState::default(),
        };

        r.sys_info.refresh_cpu();
        r.sys_info.refresh_memory();

        r
    }

    /// Deletes any dead fuzzer and checks for new fuzzers.
    /// Returns true if the fuzzer list changed
    pub fn update_fuzzer_list(&mut self) -> bool {
        let mut changed = false;
        let init_fuzzer_num = self.fuzzers.len();

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
            // Deleting to the left of the cursor
            if *idx < self.ui.selected_tab {
                decrement_selected(&mut self.ui.selected_tab, 0, false);
            }
            changed = true;
        }

        let mut found_files = Vec::new();
        // Scan for new
        if let Ok(mut dir_list) = std::fs::read_dir(&self.watch_dir) {
            while let Some(Ok(item)) = dir_list.next() {
                // Ignore files without the stats prefix
                if !item
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with(&self.stats_file_prefix)
                {
                    continue;
                }

                // Ignore directories
                match item.metadata() {
                    Ok(m) if m.is_file() => {}
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
                    continue;
                }
            };

            let buf = unsafe {
                std::slice::from_raw_parts_mut(
                    shmem.as_ptr(),
                    shmem.len(),
                )
            };

            let fuzzer_pid;
            match cflib::get_fuzzer_pid(buf) {
                Ok(Some(p)) => fuzzer_pid = p,
                Err(e) => {
                    let _ = destroy_ui();
                    panic!("Failed to get pid : {}", e);
                }
                Ok(None) => {
                    let _ = destroy_ui();
                    panic!("fuzzer never initialized in time...");
                    //continue
                },
            };

            let compare_pid_fn = |f: &Fuzzer| *f.stats.header.pid == fuzzer_pid;

            // If we are already tracking this pid
            if self.fuzzers.iter().any(compare_pid_fn) {
                continue;
            }

            // Parse the fuzzer stats
            let stats = match CfStats::from_mut_slice(&mut std::io::Cursor::new(buf)) {
                Ok(s) => s,
                Err(e) => {
                    let _ = destroy_ui();
                    panic!("Failed to parse stat memory : {}", e);
                },
            };

            let fuzzer = Fuzzer {
                shmem,
                stats
            };
            if !fuzzer.is_alive(&mut self.sys_info) {
                continue;
            }
            changed = true;

            // New fuzzer
            self.fuzzers.push(fuzzer);
        }

        if changed {
            if init_fuzzer_num != self.fuzzers.len() {
                self.ui.tab_title.clear();
                let _ = write!(&mut self.ui.tab_title, "Fuzzers ({})", self.fuzzers.len());
            }

            if self.fuzzers.is_empty() {
                self.ui.clear_all();
            } else if self.ui.plugin_list.selected().is_none() {
                self.ui.plugin_list.select(Some(self.ui.selected_plugin));
            }
        }

        changed
    }
}

pub struct Fuzzer {
    #[allow(dead_code)]
    shmem: Shmem,
    pub stats: CfStats<'static>,
}

impl Fuzzer {
    pub fn is_alive(&self, sys_info: &mut System) -> bool {
        // Check if our PID is alive and is a crowdfuzz process
        match sys_info.get_process(*self.stats.header.pid as _) {
            None => false,
            Some(p) => p.name().starts_with("crowdfuzz"),
        }
    }
}
