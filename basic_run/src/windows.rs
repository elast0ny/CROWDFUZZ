// TODO : Windows has no nice ways to detect a target application crash.
//      Either the target returns normaly setting its exit status to whatever arbitrary value it picks
//      or the target crashes and windows sets the exception code in the exit status.
//      Therefore, in rare case, target applications could emulate crashing by setting the exit status themselves...
use std::process::ExitStatus;

pub fn get_exception(status: &ExitStatus) -> Option<i32> {
    match status.code() {
        Some(s) => {
            if s < 0 {
                Some(s)
            } else {
                None
            }
        }
        None => None,
    }
}
