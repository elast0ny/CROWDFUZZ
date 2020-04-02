use log::*;
use sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

use std::path::Path;
use std::process::{Child, Command, Stdio};

/// Binds the current process to the specified core. If None, the function will search existing processes
/// and increment the core ID for every fuzzer process that is running
pub fn bind_to_core(target_core: Option<usize>) -> Option<usize> {
    let core_ids = core_affinity::get_core_ids().unwrap();
    let mut target_core_id = 0;
    if let Some(id) = target_core {
        if target_core_id >= core_ids.len() {
            warn!(
                "Tried to bind to core {} but only {} cores available...",
                target_core_id,
                core_ids.len()
            );
            return None;
        }

        target_core_id = id;
    } else {
        let prog_name: &'static str;
        if cfg!(target_os = "windows") {
            prog_name = concat!(env!("CARGO_PKG_NAME"), ".exe");
        } else {
            prog_name = env!("CARGO_PKG_NAME");
        }

        debug!(
            "No core id provided, will pick core number (# of '{}' - 1)",
            prog_name
        );

        let system = System::new_with_specifics(RefreshKind::new().with_processes());
        let prog_name: &'static str;
        if cfg!(target_os = "windows") {
            prog_name = concat!(env!("CARGO_PKG_NAME"), ".exe");
        } else {
            prog_name = env!("CARGO_PKG_NAME");
        }
        for (_pid, info) in system.get_processes().iter() {
            if info.name() == prog_name {
                target_core_id += 1;
            }
        }
        if target_core_id == 0 {
            error!("Unable to find our own process '{}' in the currently running processes on the system...", prog_name);
            return None;
        }

        target_core_id -= 1;
    }

    if target_core_id > core_ids.len() {
        error!(
            "Trying to bind to core #{} but only {} cores available",
            target_core_id,
            core_ids.len()
        );
        return None;
    }

    core_affinity::set_for_current(core_ids[target_core_id]);
    return Some(target_core_id);
}

/// Spawns another instance of the fuzzer
pub fn spawn_next_instance(
    instance_num: isize,
    cwd: &Path,
) -> Result<Option<Child>, std::io::Error> {
    let mut new_inst_num = instance_num;
    if instance_num <= 0 {
        new_inst_num = (core_affinity::get_core_ids().unwrap().len() as isize) + instance_num;
        if new_inst_num <= 0 {
            return Ok(None);
        }
        info!("Spawning {} instances", new_inst_num);
    }

    if new_inst_num == 1 {
        return Ok(None);
    }

    let mut args = std::env::args();
    let process_path = args.next().unwrap();

    let mut last_is_instance = false;
    let mut new_args: Vec<String> = Vec::new();
    for arg in args {
        // strip verbose from child process
        if arg == "--verbose" || (arg.starts_with("-v") && arg.chars().skip(1).all(|c| c == 'v')) {
            continue;
        }

        if last_is_instance {
            new_args.push((new_inst_num - 1).to_string());
            last_is_instance = false;
            continue;
        }
        if arg == "--instances" {
            last_is_instance = true;
        }
        new_args.push(arg);
    }

    // Save cwd
    let cur_dir = std::env::current_dir()?;

    // Change to directory that invoked us before spawning
    std::env::set_current_dir(&cwd)?;
    //info!("{}\\{} {:?}", cwd.to_string_lossy(), process_path, new_args);
    let child = match Command::new(&process_path)
        .args(&new_args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => {
            //info!("{}", std::str::from_utf8(&child.wait_with_output().unwrap().stderr).unwrap());
            Some(child)
        }
        Err(e) => {
            error!(
                "Failed to create process {}/{} {:?}",
                cwd.to_string_lossy(),
                process_path,
                new_args
            );
            return Err(e);
        }
    };

    //restore cwd
    std::env::set_current_dir(&cur_dir)?;

    info!("Spawned next fuzzer instance !");
    Ok(child)
}
