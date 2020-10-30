use crate::core::CfCore;
use ::log::*;
use cflib::*;
use std::collections::HashMap;

pub struct Store {
    pub avg_denominator: u64,
    pub no_mutate: bool,
    pub no_select: bool,
    pub content: CfStore,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            avg_denominator: 0,
            no_mutate: false,
            no_select: false,
            content: HashMap::new(),
        }
    }
}

impl<'a> CfCore<'a> {
    /// Add all of the store keys that the core controls
    pub fn init_public_store(&mut self) {
        let store = &mut self.store.content;
        let _ = store.insert_exclusive(STORE_INPUT_DIR, &self.config.input, None);
        let _ = store.insert_exclusive(STORE_STATE_DIR, &self.config.state, None);
        let _ = store.insert_exclusive(STORE_RESULTS_DIR, &self.config.results, None);
        let _ = store.insert_exclusive(STORE_TARGET_BIN, &self.config.target, None);
        let _ = store.insert_exclusive(STORE_TARGET_ARGS, &self.config.target_args, None);
        let _ = store.insert_exclusive(STORE_CWD, &self.config.cwd, None);
        let _ = store.insert_exclusive(STORE_FUZZER_NAME, &self.config.prefix, None);
        let _ = store.insert_exclusive(STORE_FUZZER_ID, &self.config.instance_id, None);
        let _ = store.insert_exclusive(STORE_PLUGIN_CONF, &self.config.plugin_conf, None);
        let _ = store.insert_exclusive(STORE_AVG_DENOMINATOR, &self.store.avg_denominator, None);
        let _ = store.insert_exclusive(STORE_NUM_EXECS, self.stats.num_execs.val, None);
        let _ = store.insert_exclusive(STORE_NO_MUTATE, &self.store.no_mutate, None);
        let _ = store.insert_exclusive(STORE_NO_SELECT, &self.store.no_select, None);
        let _ = store.insert_exclusive(STORE_CORE_STATE, self.ctx.stats.get_state(), None);
    }

    pub fn clear_public_store(&mut self) {
        let store = &mut self.store.content;
        trace!("Cleaning core store values");
        store.remove(STORE_INPUT_DIR).unwrap();
        store.remove(STORE_STATE_DIR).unwrap();
        store.remove(STORE_RESULTS_DIR).unwrap();
        store.remove(STORE_TARGET_BIN).unwrap();
        store.remove(STORE_TARGET_ARGS).unwrap();
        store.remove(STORE_CWD).unwrap();
        store.remove(STORE_FUZZER_NAME).unwrap();
        store.remove(STORE_FUZZER_ID).unwrap();
        store.remove(STORE_PLUGIN_CONF).unwrap();
        store.remove(STORE_AVG_DENOMINATOR).unwrap();
        store.remove(STORE_NUM_EXECS).unwrap();
        store.remove(STORE_NO_MUTATE).unwrap();
        store.remove(STORE_NO_SELECT).unwrap();
        store.remove(STORE_CORE_STATE).unwrap();
    }
}
