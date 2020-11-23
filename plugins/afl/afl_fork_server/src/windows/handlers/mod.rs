mod debug;
mod events;
mod fuzz;

pub use debug::*;
pub use events::*;
pub use fuzz::*;

pub use super::*;

pub fn is_eq_lowercased(str1: &str, str2: &str) -> bool {

    let mut str1_chars = str1.chars().map(|c| c.to_lowercase().collect());
    let mut str2_chars = str2.chars().map(|c| c.to_lowercase().collect());

    loop {
        let s1: Option<String> = str1_chars.next();
        let s2: Option<String> = str2_chars.next();

        match (s1, s2) {
            (None, None) => break,
            (Some(s1), Some(s2)) if s1 != s2 => return false,
            _ => return false,
        }
    }

    return true;
}