use std::path::{Path, PathBuf};
use std::{
    collections::HashMap,
    fs,
    fs::{create_dir_all, File},
};

use ::log::*;

use ::serde_derive::{Deserialize, Serialize};

use crate::Result;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
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
    #[serde(default = "Vec::new")]
    pub plugin_conf: Vec<HashMap<String, String>>,

    /// Plugins to be run before the fuzzing begins
    #[serde(default = "Vec::new")]
    pub pre_fuzz_loop: Vec<PathBuf>,
    /// Working directory for the project
    #[serde(default = "String::new")]
    pub cwd: String,
    /// Size of the memory used for statistics for UIs
    #[serde(default = "default_smem_size")]
    pub shmem_size: usize,
    /// Path of the statistic file
    #[serde(default = "default_stats_path")]
    pub stats_file: String,
    /// Name of the input file when fuzzing
    #[serde(default = "default_input_fname")]
    pub input_file_name: String,

    #[serde(skip_deserializing)]
    #[serde(default = "String::new")]
    pub prefix: String,
    #[serde(skip_deserializing)]
    #[serde(default = "PathBuf::new")]
    pub prev_wd: PathBuf,
}

fn default_smem_size() -> usize {
    4096
}
fn default_stats_path() -> String {
    String::from("fuzzer_stats")
}

fn default_input_fname() -> String {
    String::from("cur_input")
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

    fn set_prefix(&mut self) -> Result<()> {
        let mut fuzz_num = 1;
        // Check how many fuzzer stats files there are in the state directory
        if let Ok(mut dir_list) = fs::read_dir(&self.state) {
            while let Some(Ok(entry)) = dir_list.next() {
                let fname = entry.file_name();
                let file_name = fname.to_str().unwrap();

                if !file_name.starts_with(&self.stats_file) {
                    continue;
                }
                // TODO : Read the fuzzer stats file and ensure that the pid is still a live fuzzer process
                fuzz_num += 1;
            }
        }
        self.prefix.push_str(&fuzz_num.to_string());

        self.stats_file.push_str("_");
        self.stats_file.push_str(&self.prefix);

        let mut tmp_path = PathBuf::from(&self.state);

        tmp_path.push(&self.stats_file);
        self.stats_file = tmp_path.to_str().unwrap().to_string();
        tmp_path.pop();

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

        Ok(())
    }

    pub fn new<S: AsRef<str>>(prefix: S, config_fpath: S) -> Result<Config> {
        // Parse the yaml config
        let path = PathBuf::from(config_fpath.as_ref()).canonicalize()?;
        let mut config: Config = serde_yaml::from_reader(File::open(&path)?)?;

        // Set the current working directory to be the config's directory
        config.prev_wd = std::env::current_dir().unwrap();
        config.cwd = String::from(match path.parent() {
            Some(d) => {
                if config.prev_wd != d {
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
            None => config.prev_wd.to_str().unwrap(),
        });
        config.prefix = String::from(prefix.as_ref());

        // Validate base directories
        config.validate()?;

        config.set_prefix()?;

        Ok(config)
    }
}
