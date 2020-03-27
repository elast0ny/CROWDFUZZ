use std::process::ExitStatus;
use std::os::unix::process::ExitStatusExt;

pub fn get_exception(status: &ExitStatus) -> i32 {
    status.signal()
}