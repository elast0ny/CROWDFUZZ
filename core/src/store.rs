use std::collections::HashMap;
use crate::core::CfCore;
use ::log::*;
use cflib::*;

pub struct Store {
    pub avg_denominator: u64,
    pub no_mutate: bool,
    pub content: CfStore,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            avg_denominator: 0,
            no_mutate: false,
            content: HashMap::new(),
        }
    }
}

impl<'a> CfCore<'a> {
    /// Add all of the store keys that the core controls
    pub fn init_public_store(&mut self) {

        let store = &mut self.store.content;
        store.insert(STORE_INPUT_DIR.to_string(), box_leak!(self.config.input.as_str()));
        store.insert(STORE_STATE_DIR.to_string(), box_leak!(self.config.state.as_str()));
        store.insert(STORE_RESULTS_DIR.to_string(), box_leak!(self.config.results.as_str()));
        store.insert(STORE_TARGET_BIN.to_string(), box_leak!(self.config.target.as_str()));
        store.insert(STORE_TARGET_ARGS.to_string(), box_leak!(&mut self.config.target_args));
        store.insert(STORE_CWD.to_string(), box_leak!(self.config.cwd.as_str()));
        store.insert(STORE_FUZZER_ID.to_string(), box_leak!(self.config.prefix.as_str()));
        store.insert(STORE_PLUGIN_CONF.to_string(), box_leak!(&mut self.config.plugin_conf));
        store.insert(STORE_AVG_DENOMINATOR.to_string(), &mut self.store.avg_denominator as *mut _ as _);
        store.insert(STORE_NUM_EXECS.to_string(), self.stats.num_execs.val as *mut _ as _);
        store.insert(STORE_NO_MUTATE.to_string(), &mut self.store.no_mutate as *mut _ as _);
    }

    pub fn clear_public_store(&mut self) {
        let store = &mut self.store.content;
        trace!("Cleaning core store values");
        
        trace!("store['{}']", STORE_INPUT_DIR);
        if let Some(v) = store.remove(STORE_INPUT_DIR) {
            box_take!(v, &str);
        }
        trace!("store['{}']", STORE_STATE_DIR);
        if let Some(v) = store.remove(STORE_STATE_DIR) {
            box_take!(v, &str);
        }
        trace!("store['{}']", STORE_RESULTS_DIR);
        if let Some(v) = store.remove(STORE_RESULTS_DIR) {
            box_take!(v, &str);
        }
        trace!("store['{}']", STORE_TARGET_BIN);
        if let Some(v) = store.remove(STORE_TARGET_BIN) {
            box_take!(v, &str);
        }
        trace!("store['{}']", STORE_TARGET_ARGS);
        if let Some(v) = store.remove(STORE_TARGET_ARGS) {
            box_take!(v, &mut Vec<String>);
        }
        trace!("store['{}']", STORE_CWD);
        if let Some(v) = store.remove(STORE_CWD) {
            box_take!(v, &str);
        }
        trace!("store['{}']", STORE_FUZZER_ID);
        if let Some(v) = store.remove(STORE_FUZZER_ID) {
            box_take!(v, &str);
        }
        trace!("store['{}']", STORE_PLUGIN_CONF);
        if let Some(v) = store.remove(STORE_PLUGIN_CONF) {
            box_take!(v, &HashMap<String, String>);
        }

        trace!("store['{}']", STORE_AVG_DENOMINATOR);
        let _ = store.remove(STORE_AVG_DENOMINATOR);
        trace!("store['{}']", STORE_NUM_EXECS);
        let _ = store.remove(STORE_NUM_EXECS);
        trace!("store['{}']", STORE_NO_MUTATE);
        let _ = store.remove(STORE_NO_MUTATE);
    }
}
