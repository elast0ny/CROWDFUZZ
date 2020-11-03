use std::ffi::CString;

pub mod dynamorio;
pub use dynamorio as dr;

/// This is where the drrun.exe client code lives
pub mod client;

use ::simple_parse::{SpRead, SpWrite};

#[derive(SpRead, SpWrite)]
#[sp(id_type = "u8")]
pub enum PersistenceMode {
    #[sp(id = "0")]
    Native,
    #[sp(id = "1")]
    InApp,
}

#[derive(SpRead, SpWrite)]
#[sp(id_type = "u8")]
pub enum CoverageType {
    #[sp(id = "0")]
    BasicBlock,
    #[sp(id = "1")]
    Edge,
}

#[derive(SpRead, SpWrite)]
pub struct ClientOptions {
    debug_mode: bool,
    nudge_kills: bool,
    persistence_mode: PersistenceMode,
    coverage_kind: CoverageType,
    log_dir: CString,
    target_modules: Vec<CString>,
}
impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            debug_mode: false,
            nudge_kills: false,
            persistence_mode: PersistenceMode::Native,
            coverage_kind: CoverageType::BasicBlock,
            log_dir: CString::default(),
            target_modules: Vec::new(),
        }
    }
}


unsafe impl Send for ClientOptions {}
unsafe impl Sync for ClientOptions {}
