use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

pub fn get_exception(status: &ExitStatus) -> Option<i32> {
    status.signal()
}
