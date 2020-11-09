use std::boxed::Box;
use std::cmp::Ordering;
use std::process::exit;

use ::clap::{App, Arg};
use ::log::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub mod config;
pub mod core;
pub mod log;
pub mod plugin;
pub mod stats;
pub mod store;
pub mod util;

pub const ARG_VERBOSE_SHORT: &str = "-v";
pub const ARG_VERBOSE_LONG: &str = "--verbose";
pub const ARG_INSTANCES_SHORT: &str = "-n";
pub const ARG_INSTANCES_LONG: &str = "--num_instances";

use crate::config::Config;
use crate::core::CfCore;

fn main() -> Result<()> {
    let mut name = String::from(env!("CARGO_PKG_NAME"));
    name.make_ascii_uppercase();
    let total_cores = ::affinity::get_core_num();
    let args = App::new(&name)
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about("A plugin based fuzzer")
        .arg(
            Arg::with_name("config")
                .value_name("PROJECT_CONFIG")
                .help("The yaml config that describes your project")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("prefix")
                .short("p")
                .long("prefix")
                .help("Sets the fuzzer prefix")
                .default_value("fuzzer")
                .hidden(true) //This shouldnt really be needed by anyone
                .takes_value(true),
        )
        .arg(
            Arg::with_name("num_instances")
                .long(ARG_INSTANCES_LONG)
                .short(ARG_INSTANCES_SHORT)
                .allow_hyphen_values(true)
                .help(&format!(
                    "How many fuzzers to spawn [1 == 1|0 == #cores ({})|-1 == ({} - 1)]",
                    total_cores, total_cores
                ))
                .default_value("1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("single_run")
                .short("s")
                .long("single_run")
                .help("Stop after one iteration"),
        )
        .arg(
            Arg::with_name("bind_cpu")
                .long("bind_cpu")
                .takes_value(true)
                .help(&format!(
                    "Bind to a specific cpu core (-1 to disable, max {})",
                    total_cores - 1
                )),
        )
        .arg(
            Arg::with_name("verbose")
                .long(ARG_VERBOSE_LONG)
                .short(ARG_VERBOSE_SHORT)
                .long("verbose")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    // Set up the logger
    crate::log::set_log_level(&(args.occurrences_of("verbose") as usize), "info");
    env_logger::Builder::from_default_env()
        .format(crate::log::log_format)
        .init();

    info!("==== {}-{} ====", &name, env!("CARGO_PKG_VERSION"));

    // Parse the config
    info!("Loading project config");
    let config = Config::new(
        args.value_of("prefix").unwrap(),
        args.value_of("config").unwrap(),
    )?;

    // Validate --bind_cpu
    let bind_cpu_id: Option<usize> = match args.value_of("bind_cpu") {
        None => {
            // Attempt to use the instance_id
            let target_core = config.instance_id - 1;
            if target_core >= total_cores {
                warn!("There are more fuzzers running than cores available !");
                warn!("Will not bind to any core...");
                None
            } else {
                Some(target_core)
            }
        }
        Some(v) => {
            let v = v
                .parse::<isize>()
                .expect("Invalid number provided for --bind_cpu");
            if v == -1 {
                None
            } else if v >= 0 {
                let target_core = v as usize;
                if target_core < total_cores {
                    Some(target_core)
                } else {
                    return Err(From::from(format!(
                        "Tried to bind to core[{}] but only {} cores are available...",
                        target_core, total_cores
                    )));
                }
            } else {
                return Err(From::from(
                    "Invalid number provided for --bind_cpu".to_string(),
                ));
            }
        }
    };

    // Basic checks for cpu binding and such
    let cur_running_instances = util::get_num_instances()?;
    if config.instance_id < cur_running_instances {
        warn!("Detected {} fuzzers running on the machine but only {} in the current project folder...", cur_running_instances, config.instance_id);
        warn!("This could lead to multiple fuzzer binding to the same cpu core.")
    }

    // Validate -n
    let num_instances: usize = match args.value_of("num_instances").unwrap().parse::<isize>() {
        Ok(n) => match n.cmp(&0) {
            Ordering::Greater => n as usize,
            Ordering::Equal => total_cores,
            Ordering::Less => {
                if n.abs() as usize >= total_cores {
                    return Err(From::from(format!("Tried to spawn invalid number of instances '{}' but host only has {} cores...", n, total_cores)));
                } else {
                    total_cores - (n.abs() as usize)
                }
            }
        },
        Err(e) => {
            return Err(From::from(format!(
                "Invalid number provided for number of instances {} : {}",
                args.value_of("num_instances").unwrap(),
                e
            )))
        }
    };

    // Initialize the fuzzer core
    let mut core = CfCore::init(config)?;

    // Duplicate ourselves if we arent at num_instances yet
    if num_instances > core.config.instance_id {
        info!(
            "Spawning {} instances ! ({}/{} already running)",
            num_instances - core.config.instance_id,
            core.config.instance_id,
            num_instances,
        );

        for _ in core.config.instance_id..num_instances {
            let child = util::spawn_self(&core.config.invoke_dir, args.is_present("single_run"))?;
            if let Some(mut p) = child {
                if args.is_present("single_run") {
                    info!("Waiting for other instances to exit because of --single-run");
                    let _ = p.wait();
                }
            }
        }
    }

    // Bind now that we arent spawning anything else
    if let Some(core_id) = bind_cpu_id {
        info!("Bound to core #{}", util::bind_to_core(core_id)?);
    }

    //Add a ctrl-c handler
    let should_quit = core.exiting.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        // Set `exiting` to true when ctrl-c is triggerred
        should_quit.store(true, std::sync::atomic::Ordering::Relaxed);
    }) {
        error!("Failed to set CTRL-C handler : {}", e);
        exit(-1);
    }
    debug!("Handler for [ctrl+c] initialized...");

    #[allow(clippy::never_loop)]
    loop {
        //Call every plugin's init function
        if let Err(e) = core.init_plugins() {
            error!("{}", e);
            break;
        }

        info!("Core & plugins initialized succesfully");
        
        info!("Fuzzing...");
        
        //Run through once
        if let Err(e) = core.single_run() {
            warn!("{}", e);
            break;
        }

        if args.is_present("single_run") {
            info!("Exiting before fuzz loop because of --single_run");
            core.exiting
                .store(true, std::sync::atomic::Ordering::Relaxed);
            break;
        }

        //Start fuzzing
        if let Err(e) = core.fuzz_loop() {
            warn!("{}", e);
            break;
        }

        break;
    }

    //Planned stop ?
    if core.exiting() {
        info!("Tearing down");
    } else {
        error!("Tearing down");
    }

    core.destroy_plugins();

    if core.exiting() {
        info!("Done !");
    } else {
        error!("Done !");
        drop(core);
        std::process::exit(1);
    }

    Ok(())
}
