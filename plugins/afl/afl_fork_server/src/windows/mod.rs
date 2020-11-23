use std::collections::HashSet;

pub use ::dynamorio_sys as dr;
use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;

/// This is where the drrun.exe client code lives
pub mod client;
pub use client::*;
mod handlers;
pub use handlers::*;

mod server;
pub use server::*;

use ::simple_parse::{SpRead, SpWrite};

#[derive(SpRead, SpWrite)]
#[sp(id_type = "u8")]
pub enum Message {
    #[sp(id = "0")]
    Error(String),
    #[sp(id = "1")]
    Exiting,
    
    #[sp(id = "2")]
    ReqNextInput,
    #[sp(id = "3")]
    NextInputReady,
    #[sp(id = "4")]
    NextInputBytes(Vec<u8>),
    #[sp(id = "5")]
    ExecResult(::cflib::TargetExitStatus)
}

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
    None,
    #[sp(id = "1")]
    BasicBlock,
    #[sp(id = "2")]
    Edge,
}

#[derive(SpRead, SpWrite)]
#[sp(id_type = "u8")]
pub enum TargetFunction {
    #[sp(id = "0")]
    Offset(usize),
    #[sp(id = "1")]
    Symbol(String),
}

#[repr(i32)]
#[derive(SpRead, SpWrite, Primitive)]
#[sp(id_type = "u8")]
pub enum CallingConvention {
    #[sp(id = "0")]
    Stdcall = dr::drwrap_callconv_t_DRWRAP_CALLCONV_CDECL,
    #[sp(id = "1")]
    Fastcall = dr::drwrap_callconv_t_DRWRAP_CALLCONV_FASTCALL,
    #[sp(id = "2")]
    Thiscall = dr::drwrap_callconv_t_DRWRAP_CALLCONV_THISCALL,
    #[sp(id = "3")]
    MS64 = dr::drwrap_callconv_t_DRWRAP_CALLCONV_MICROSOFT_X64,
}

#[derive(SpRead, SpWrite)]
pub struct ClientOptions {
    server_addr: String,
    shmem_id: String,
    debug_fpath: Option<String>,
    
    nudge_kills: bool,
    thread_coverage: bool,
    persistence_mode: PersistenceMode,
    
    coverage_kind: CoverageType,
    cov_modules: HashSet<String>,
    
    target_module: String,
    target_function: TargetFunction,
    calling_convention: CallingConvention,
    target_nargs: usize,
    fuzz_iterations: usize,

    no_loop: bool,
    dr_presist_cache: bool,
}
impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            shmem_id: String::new(),
            debug_fpath: None,
            nudge_kills: true,
            thread_coverage: false,
            persistence_mode: PersistenceMode::Native,
            coverage_kind: CoverageType::BasicBlock,
            cov_modules: HashSet::new(),
            target_module: String::new(),
            target_function: TargetFunction::Offset(0),
            calling_convention: CallingConvention::from_i32(dr::drwrap_callconv_t_DRWRAP_CALLCONV_DEFAULT).unwrap(),
            target_nargs: 0,
            fuzz_iterations: 1000,
            no_loop: false,
            dr_presist_cache: false,
        }
    }
}
