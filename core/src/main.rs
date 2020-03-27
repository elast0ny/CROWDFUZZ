use std::boxed::Box;
use std::process::exit;

use ::clap::{App, Arg};
pub use ::log::{debug, error, info, log, trace, warn};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub mod config;
pub mod core;
pub mod interface;
pub mod log;
pub mod plugin;
pub mod stats;
pub mod store;
pub mod util;

use crate::core::Core;
use crate::log::*;

fn main() -> Result<()> {
    let mut name = String::from(env!("CARGO_PKG_NAME"));
    name.make_ascii_uppercase();
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
                .takes_value(true)
        )
        .arg(
            Arg::with_name("instances")
                .allow_hyphen_values(true)
                .long("instances")
                .help("How many fuzzers to spawn (1 == 1, 0 == #cores, -1 == (#cores - 1))")
                .default_value("1")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("single_run")
                .short("s")
                .long("single_run")
                .help("Stop after one iteration")
        )
        .arg(
            Arg::with_name("bind_cpu")
                .long("bind_cpu")
                .takes_value(true)
                .help("Bind to a specific cpu core (-1 to disable)")
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Sets the level of verbosity")
        )
        .get_matches();

    // Set up the logger
    set_log_level(&(args.occurrences_of("verbose") as usize), "info");
    env_logger::Builder::from_default_env()
        .format(log_format)
        .init();

    info!("==== {}-{} ====", &name, env!("CARGO_PKG_VERSION"));

    let num_instances: isize = args.value_of("instances").unwrap().parse().expect(&format!(
        "Invalid number provided for --instances : {}",
        args.value_of("instances").unwrap()
    ));
    let bind_cpu_arg = args.value_of("bind_cpu").map(|s| {
        s.parse::<isize>()
            .expect(&format!("Invalid number passed for --bind_cpu : {}", s))
    });
    match bind_cpu_arg {
        Some(s) if s < 0 => {}
        _ => match util::bind_to_core(bind_cpu_arg.map(|id| id as usize)) {
            Some(id) => info!("Bound to core #{}", id),
            None => {
                warn!("Failed to bind to requested core...");
            }
        },
    };

    // Initialize the fuzzer core based on the yaml config
    let mut core = Core::init(
        args.value_of("prefix").unwrap(),
        args.value_of("config").unwrap(),
    )?;

    // Spawn the next instance if needed
    let child = util::spawn_next_instance(num_instances, &core.config.prev_wd)?;
    if let Some(mut p) = child {
        if args.is_present("single_run") {
            info!("Waiting for other instances to exit because of --single-run");
            let _ = p.wait();
        }
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

    loop {
        //Call every plugin's init function
        if let Err(e) = core.init_plugins() {
            error!("{}", e);
            break;
        }

        info!("Core & plugins initialized succesfully");

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

    //Allow plugins to cleanup after themselves
    core.destroy_plugins();

    if core.exiting() {
        info!("Done !");
    } else {
        error!("Done !");
        std::process::exit(1);
    }

    Ok(())
}
