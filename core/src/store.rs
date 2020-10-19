use std::collections::hash_map::Entry;
use std::collections::VecDeque;
use crate::core::CfCore;
use ::log::*;
use cflib::*;

impl<'a> CfCore<'a> {
    /// Add all of the store keys that the core controls
    pub fn init_public_store(&mut self) {

        let store = &mut self.store;
        let mut tmp: VecDeque<*mut u8>; 
        
        tmp = VecDeque::with_capacity(1);
        let t = box_leak!(self.config.input.as_str());
        debug!("{:p}", t);
        tmp.push_front(t);
        store.insert(STORE_INPUT_DIR.to_string(), tmp);

        tmp = VecDeque::with_capacity(1);
        tmp.push_front(box_leak!(self.config.state.as_str()));
        store.insert(STORE_STATE_DIR.to_string(), tmp);

        tmp = VecDeque::with_capacity(1);
        tmp.push_front(box_leak!(self.config.results.as_str()));
        store.insert(STORE_RESULTS_DIR.to_string(), tmp);

        tmp = VecDeque::with_capacity(1);
        tmp.push_front(box_leak!(self.config.target.as_str()));
        store.insert(STORE_TARGET_BIN.to_string(), tmp);

        tmp = VecDeque::with_capacity(self.config.target_args.len());
        for arg in &mut self.config.target_args {
            tmp.push_back(box_leak!(arg.as_str()));
        }
        store.insert(STORE_TARGET_ARGS.to_string(), tmp);

        tmp = VecDeque::with_capacity(1);
        tmp.push_front(box_leak!(self.config.cwd.as_str()));
        store.insert(STORE_CWD.to_string(), tmp);

        tmp = VecDeque::with_capacity(1);
        tmp.push_front(box_leak!(self.config.prefix.as_str()));
        store.insert(STORE_FUZZER_ID.to_string(), tmp);

        tmp = VecDeque::with_capacity(1);
        tmp.push_front(box_leak!(&mut self.config.plugin_conf));
        store.insert(STORE_PLUGIN_CONF.to_string(), tmp);

        tmp = VecDeque::with_capacity(1);
        tmp.push_front(&mut self.stats.avg_denominator as *mut _ as _);
        store.insert(STORE_AVG_DENOMINATOR.to_string(), tmp);

        tmp = VecDeque::with_capacity(1);
        tmp.push_front(self.stats.num_execs.val as *mut _ as _);
        store.insert(STORE_NUM_EXECS.to_string(), tmp);
    }

    pub fn clear_public_store(&mut self) {
        let store = &mut self.store;

        debug!("store['{}']", STORE_INPUT_DIR);
        if let Entry::Occupied(mut v) = store.entry(STORE_INPUT_DIR.to_string()) {
            let _ = box_take!(v.get_mut().pop_front().unwrap(), &str);
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_STATE_DIR);
        if let Entry::Occupied(mut v) = store.entry(STORE_STATE_DIR.to_string()) {
            let _ = box_take!(v.get_mut().pop_front().unwrap(), &str);
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_RESULTS_DIR);
        if let Entry::Occupied(mut v) = store.entry(STORE_RESULTS_DIR.to_string()) {
            let _ = box_take!(v.get_mut().pop_front().unwrap(), &str);
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_TARGET_BIN);
        if let Entry::Occupied(mut v) = store.entry(STORE_TARGET_BIN.to_string()) {
            let _ = box_take!(v.get_mut().pop_front().unwrap(), &str);
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_TARGET_ARGS);
        if let Entry::Occupied(mut v) = store.entry(STORE_TARGET_ARGS.to_string()) {
            for _ in &self.config.target_args {
                let _ = box_take!(v.get_mut().pop_front().unwrap(), &str);
            }
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_CWD);
        if let Entry::Occupied(mut v) = store.entry(STORE_CWD.to_string()) {
            let _ = box_take!(v.get_mut().pop_front().unwrap(), &str);
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_FUZZER_ID);
        if let Entry::Occupied(mut v) = store.entry(STORE_FUZZER_ID.to_string()) {
            let _ = box_take!(v.get_mut().pop_front().unwrap(), &str);
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_PLUGIN_CONF);
        if let Entry::Occupied(mut v) = store.entry(STORE_PLUGIN_CONF.to_string()) {
            let _ = box_take!(v.get_mut().pop_front().unwrap(), &std::collections::HashMap<String, String>);
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_AVG_DENOMINATOR);
        if let Entry::Occupied(mut v) = store.entry(STORE_AVG_DENOMINATOR.to_string()) {
            let _ = v.get_mut().pop_front().unwrap();
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
        debug!("store['{}']", STORE_NUM_EXECS);
        if let Entry::Occupied(mut v) = store.entry(STORE_NUM_EXECS.to_string()) {
            let _ = v.get_mut().pop_front().unwrap();
            if v.get_mut().is_empty() {
                v.remove();
            }
        }
    }
}
