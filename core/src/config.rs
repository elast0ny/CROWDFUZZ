use std::path::{Path, PathBuf};
use std::{
    collections::HashMap,
    fs::{create_dir_all, File},
};

use ::cflib::*;

use ::log::*;
use ::serde_derive::{Deserialize};
use ::shared_memory::{ShmemConf, Shmem};
use ::sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

use crate::Result;

#[derive(Deserialize)]
pub struct Config {
    /// Path to directory holding starting testcases
    pub input: String,
    /// Path to the directory that will hold state data
    pub state: String,
    /// Path where results will be stored
    pub results: String,
    /// Path to the target binary
    pub target: String,
    /// Arguments for the target binary
    pub target_args: Vec<String>,
    /// List of plugins for the fuzz loop
    pub fuzz_loop: Vec<PathBuf>,

    /// Additional confif values for the plugins
    #[serde(default = "HashMap::new")]
    pub plugin_conf: HashMap<String, String>,

    /// Plugins to be run before the fuzzing begins
    #[serde(default = "Vec::new")]
    pub pre_fuzz_loop: Vec<PathBuf>,
    /// Working directory for the project
    #[serde(default = "String::new")]
    pub cwd: String,
    /// Size of the memory used for statistics for UIs
    #[serde(default = "default_shmem_size")]
    pub shmem_size: usize,
    /// Path of the statistic file
    #[serde(default = "default_stats_path")]
    pub stats_file: String,

    #[serde(skip_deserializing)]
    #[serde(default = "String::new")]
    pub prefix: String,
    #[serde(skip_deserializing)]
    pub instance_id: usize,
    
    #[serde(skip_deserializing)]
    pub shmem: Option<Shmem>,

    #[serde(skip_deserializing)]
    #[serde(default = "PathBuf::new")]
    pub invoke_dir: PathBuf,
}

fn default_shmem_size() -> usize {
    4096 // 1 page is the lowest the OS gives anyway
}
fn default_stats_path() -> String {
    String::from("fuzzer_stats")
}

/// Attempts to delete a dead fuzzer's stat file. Returns true if the file is succesfully deleted.
fn is_fuzzer_alive(stats_file: &Path) -> bool {
    debug!("Openning shmem link");
    let shmem = match ShmemConf::new().flink(stats_file).open() {
        Ok(m) => m,
        Err(_e) => {
            warn!("Stat memory is invalid for '{}'", stats_file.to_string_lossy());
            warn!("Deleting stats file...");
            return std::fs::remove_file(stats_file).is_err();
        }
    };

    let mut num_attempts = 5;
    let mut pid = 0;
    while num_attempts != 0 {
        match unsafe{cflib::get_fuzzer_pid(shmem.as_ptr())} {
            Err(_) => {
                warn!("Stat memory is invalid for '{}'", stats_file.to_string_lossy());
                warn!("Deleting stats file...");
                return std::fs::remove_file(stats_file).is_err()
            },
            Ok(Some(p)) => pid = p,
            Ok(None) => {},
        }
        num_attempts -= 1;
    }
    if pid == 0 {
        warn!("Fuzzer never initialized its pid after >5s in '{}'", stats_file.to_string_lossy());
        warn!("Deleting stats file...");
        return std::fs::remove_file(stats_file).is_err();
    }
    
    debug!("Checking if pid {} is {}", pid, FUZZER_PROCESS_NAME);
    let mut sys_info = System::new_with_specifics(RefreshKind::new().with_processes());
    sys_info.refresh_processes();
    let fuzzer_alive = match sys_info.get_process(pid as _) {
        None => false,
        Some(p) => p.name().starts_with(FUZZER_PROCESS_NAME),
    };

    if !fuzzer_alive {
        debug!("Deleting stats file...");
        return std::fs::remove_file(stats_file).is_err();
    }

    // Nothing was deleted
    fuzzer_alive
}

impl Config {
    /// Validates mandatory config values like the target bin path, input dir, etc...
    fn validate(&mut self) -> Result<()> {
        debug!("Validating path : '{}'", self.input);
        let tmp_path = Path::new(&self.input);
        if !tmp_path.is_dir() {
            return Err(From::from(format!(
                "Folder does no exist : '{}'",
                self.input
            )));
        }

        // state directory
        debug!("Validating path : '{}'", self.state);
        let tmp_path = Path::new(&self.state);
        if !tmp_path.is_dir() {
            warn!("Folder \"{}\" does not exist. Creating...", self.state);
            if let Err(e) = create_dir_all(tmp_path) {
                return Err(From::from(format!(
                    "Failed to create directory : '{}' with {}",
                    self.state, e
                )));
            }
        }

        // result directory
        debug!("Validating path : '{}'", self.results);
        if !Path::new(&self.results).is_dir() {
            warn!("Folder \"{}\" does not exist. Creating...", self.results);
            if let Err(e) = create_dir_all(&self.results) {
                return Err(From::from(format!(
                    "Failed to create directory : '{}' with {}",
                    self.results, e
                )));
            }
        }

        // Target binary
        debug!("Validating path : '{}'", self.target);
        let tmp_path = Path::new(&self.target);
        if !tmp_path.is_file() {
            return Err(From::from(format!(
                "File does no exist : '{}'",
                self.target
            )));
        }

        Ok(())
    }

    /// Picks a unique fuzzer prefix based on current state directory
    fn create_next_instance(&mut self) -> Result<()> {
        use std::fmt::Write;
        let mut tmp_path = PathBuf::from(&self.state);
        let mut tmp_name = String::with_capacity(self.prefix.len() + 4);
        let mut tmp_stat_name = String::new();
        
        let mut shmem_attempts = 0;
        self.instance_id = 0;
        loop {
            self.instance_id += 1;
            tmp_name.clear();
            tmp_stat_name.clear();
            let _ = write!(&mut tmp_name, "{}{}", self.prefix, self.instance_id);
            let _ = write!(&mut tmp_stat_name, "{}_{}", self.stats_file, tmp_name);
            
            tmp_path.push(&tmp_stat_name);
            // If the file exist and fuzzer is still alive
            if tmp_path.is_file() && is_fuzzer_alive(tmp_path.as_path()) {
                debug!("Fuzzer '{}' is currently running!", tmp_name);
                tmp_path.pop();
                continue
            }

            // Lock in the stat file asap
            self.shmem = match ShmemConf::new().flink(&tmp_path).size(self.shmem_size).create() {
                Ok(s) => {
                    unsafe{
                        *(s.as_ptr() as *mut u32) = STAT_MAGIC;
                    }
                    Some(s)
                },
                Err(_) => {
                    tmp_path.pop();

                    if shmem_attempts >= 5 {
                        return Err(From::from(format!("Failed to create unused fuzzer stats {} times...", shmem_attempts)));
                    }
                    // Maybe another fuzzer snatched it before us !
                    // Try again just to make sure the fuzzer is alive
                    shmem_attempts += 1;
                    self.instance_id -= 1;
                    continue;
                }
            };

            // Save the fuzzer name & stat_file path
            self.prefix = tmp_name;
            self.stats_file = tmp_path.to_str().unwrap().to_string();
            tmp_path.pop();

            // Create the fuzzer's state directory
            tmp_path.push(&self.prefix);
            self.state = tmp_path.to_str().unwrap().to_string();
            if !tmp_path.is_dir() {
                warn!("Folder \"{}\" does not exist. Creating...", self.state);
                if let Err(e) = create_dir_all(&tmp_path) {
                    return Err(From::from(format!(
                        "Failed to create directory : '{}' with {}",
                        self.state, e
                    )));
                }
            }
            break;
        }

        Ok(())
    }

    pub fn new<S: AsRef<str>>(prefix: S, config_fpath: S) -> Result<Config> {
        // Parse the yaml config
        let path = match PathBuf::from(config_fpath.as_ref()).canonicalize() {
            Ok(p) => p,
            Err(e) => {
                error!("Cannot find config file '{}'", config_fpath.as_ref());
                return Err(From::from(e));
            }
        };

        let fin = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                error!(
                    "Failed to open config file '{}' : {}",
                    path.to_str().unwrap(),
                    e
                );
                return Err(From::from(e));
            }
        };

        let mut config: Config = match serde_yaml::from_reader(fin) {
            Ok(c) => c,
            Err(e) => {
                error!(
                    "Failed to parse config file '{}' : {}",
                    path.to_str().unwrap(),
                    e
                );
                return Err(From::from(e));
            }
        };

        // Set the current working directory to be the config's directory
        config.invoke_dir = std::env::current_dir().unwrap();
        config.cwd = String::from(match path.parent() {
            Some(d) => {
                if config.invoke_dir != d {
                    debug!("Changing to config directory '{}'", d.to_string_lossy());
                    if let Err(e) = std::env::set_current_dir(d) {
                        return Err(From::from(format!(
                            "Error changing to directory of config file : {}",
                            e
                        )));
                    }
                }
                d.to_str().unwrap()
            }
            None => config.invoke_dir.to_str().unwrap(),
        });
        config.prefix = String::from(prefix.as_ref());

        // Validate base directories
        config.validate()?;

        // Create files for the next available instance in this project
        config.create_next_instance()?;

        Ok(config)
    }
}
