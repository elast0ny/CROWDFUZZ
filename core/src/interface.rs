
use std::collections::{HashMap, VecDeque};

use cflib::*;
use crate::*;


impl<'a> PluginInterface for Core<'a> {
    fn set_ctx(&mut self, plugin_ctx: *mut u8) {
        
    }
    fn get_ctx(&self) -> *mut u8 {
        std::ptr::null_mut()
    }
    fn get_store(&mut self) -> &mut HashMap<String, VecDeque<*mut u8>> {
        &mut self.store
    }
    fn log(&self, level: ::log::Level, msg: &str) {

    }
    fn add_stat(&mut self, stat: NewStat) -> Result<Stat> {
        return Err(From::from("Not implemented yet".to_string()));
    }
}