use ::log::*;
use sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

use std::path::Path;
use std::process::{Child, Command, Stdio};

use crate::*;

pub fn get_num_instances() -> Result<usize> {
    let mut num_found = 0;
    let prog_name: &'static str;
    if cfg!(target_os = "windows") {
        prog_name = concat!(env!("CARGO_PKG_NAME"), ".exe");
    } else {
        prog_name = env!("CARGO_PKG_NAME");
    }

    let system = System::new_with_specifics(RefreshKind::new().with_processes());

    for (_pid, info) in system.get_processes().iter() {
        if info.name() == prog_name {
            num_found += 1;
        }
    }

    // We should at least find ourselves
    if num_found == 0 {
        return Err(From::from(format!(
            "Unable to find ourselves in the current running processes... (Looking for '{}')",
            prog_name
        )));
    }

    Ok(num_found)
}

#[cfg(target_os = "windows")]
use ::affinity::set_process_affinity as set_affinity;
#[cfg(not(target_os = "windows"))]
use ::affinity::set_thread_affinity as set_affinity;

/// Binds the current process to the specified core.
pub fn bind_to_core(target_core: usize) -> Result<usize> {
    set_affinity(&[target_core])?;
    Ok(target_core)
}

/// Spawns another instance of the fuzzer
pub fn spawn_self(cwd: &Path, allow_stdout: bool) -> Result<Option<Child>> {
    let mut args = std::env::args();
    let process_path = args.next().unwrap();
    let mut new_args: Vec<String> = Vec::new();

    let mut skip_next = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        // strip verbose from child process
        if !allow_stdout
            && (arg == ARG_VERBOSE_LONG
                || (arg.starts_with(ARG_VERBOSE_SHORT) && arg.chars().skip(1).all(|c| c == 'v')))
        {
            continue;
        } else if arg == ARG_INSTANCES_LONG || arg == ARG_INSTANCES_SHORT {
            skip_next = true;
            continue;
        }

        new_args.push(arg);
    }

    // Save cwd
    let cur_dir = std::env::current_dir()?;

    // Change to directory that invoked us before spawning
    std::env::set_current_dir(&cwd)?;
    trace!("{}\\{} {:?}", cwd.to_string_lossy(), process_path, new_args);
    let child = match Command::new(&process_path)
        .args(&new_args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(if allow_stdout {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stderr(if allow_stdout {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .spawn()
    {
        Ok(child) => Some(child),
        Err(e) => {
            error!(
                "Failed to create process {}/{} {:?}",
                cwd.to_string_lossy(),
                process_path,
                new_args
            );
            return Err(From::from(e));
        }
    };

    //restore cwd
    std::env::set_current_dir(&cur_dir)?;
    Ok(child)
}
