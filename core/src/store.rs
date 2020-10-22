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
        store.insert(STORE_INPUT_DIR.to_string(), ref_to_raw!(self.config.input));
        store.insert(STORE_STATE_DIR.to_string(), ref_to_raw!(self.config.state));
        store.insert(STORE_RESULTS_DIR.to_string(), ref_to_raw!(self.config.results));
        store.insert(STORE_TARGET_BIN.to_string(), ref_to_raw!(self.config.target));
        store.insert(STORE_TARGET_ARGS.to_string(), ref_to_raw!(self.config.target_args));
        store.insert(STORE_CWD.to_string(), ref_to_raw!(self.config.cwd));
        store.insert(STORE_FUZZER_ID.to_string(), ref_to_raw!(self.config.prefix));
        store.insert(STORE_PLUGIN_CONF.to_string(), ref_to_raw!(self.config.plugin_conf));
        store.insert(STORE_AVG_DENOMINATOR.to_string(), ref_to_raw!(self.store.avg_denominator));
        store.insert(STORE_NUM_EXECS.to_string(), ref_to_raw!(self.stats.num_execs.val));
        store.insert(STORE_NO_MUTATE.to_string(), mutref_to_raw!(self.store.no_mutate));
    }

    pub fn clear_public_store(&mut self) {
        let store = &mut self.store.content;
        trace!("Cleaning core store values");
        
        let _ = store.remove(STORE_INPUT_DIR);
        let _ = store.remove(STORE_STATE_DIR);
        let _ = store.remove(STORE_RESULTS_DIR);
        let _ = store.remove(STORE_TARGET_BIN);
        let _ = store.remove(STORE_TARGET_ARGS);
        let _ = store.remove(STORE_CWD);
        let _ = store.remove(STORE_FUZZER_ID);
        let _ = store.remove(STORE_PLUGIN_CONF);
        let _ = store.remove(STORE_AVG_DENOMINATOR);
        let _ = store.remove(STORE_NUM_EXECS);
        let _ = store.remove(STORE_NO_MUTATE);
    }
}
