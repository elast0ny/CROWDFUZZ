use std::collections::hash_map::Entry;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::ptr::null_mut;

use crate::core::Core;

use cflib::*;

impl Core {
    pub fn init_public_store(&mut self) {
        //Input dir
        self.store_push_front(
            String::from(KEY_INPUT_DIR_STR),
            Box::leak(Box::new(CFUtf8::from_str(&self.config.input))) as *mut _ as _,
        );
        //State dir
        self.store_push_front(
            String::from(KEY_STATE_DIR_STR),
            Box::leak(Box::new(CFUtf8::from_str(&self.config.state))) as *mut _ as _,
        );
        //Result dir
        self.store_push_front(
            String::from(KEY_RESULT_DIR_STR),
            Box::leak(Box::new(CFUtf8::from_str(&self.config.results))) as *mut _ as _,
        );
        // Working directory
        self.store_push_front(
            String::from(KEY_CWD_STR),
            Box::leak(Box::new(CFUtf8::from_str(&self.config.cwd))) as *mut _ as _,
        );
        // Target bin
        self.store_push_front(
            String::from(KEY_TARGET_PATH_STR),
            Box::leak(Box::new(CFUtf8::from_str(&self.config.target))) as *mut _ as _,
        );
        // Target args
        let mut tmp_list = Vec::with_capacity(self.config.target_args.len());
        for arg in &self.config.target_args {
            tmp_list.push(Box::leak(Box::new(CFUtf8::from_str(arg))) as *mut _ as _);
        }
        for arg in &tmp_list {
            self.store_push_back(String::from(KEY_TARGET_ARGS_STR), *arg);
        }

        let exec_only = Box::new(CF_FALSE);
        // Exec only key
        self.store_push_front(
            String::from(KEY_EXEC_ONLY_MODE_STR),
            Box::leak(exec_only) as *mut _ as _,
        );

        // Input file name
        self.store_push_front(
            String::from(KEY_CUR_INPUT_PATH_STR),
            Box::leak(Box::new(CFUtf8::from_str(&self.config.input_file_name))) as *mut _ as _,
        );
        // Average denominator (# of items included in average calculations)
        self.store_push_front(
            String::from(KEY_AVG_DENOMINATOR_STR),
            &self.avg_denominator as *const _ as _,
        );
        // Current number of executions
        let ptr: *mut c_void = self.stats.num_execs as *mut _ as _;
        self.store_push_front(String::from(KEY_CUR_EXEC_NUM_STR), ptr);
        // Fuzzer prefix
        self.store_push_front(
            String::from(KEY_FUZZER_ID_STR),
            Box::leak(Box::new(CFUtf8::from_str(&self.config.prefix))) as *mut _ as _,
        );

        //Plugin config
        let mut conf_tuples = Vec::new();
        for map in self.config.plugin_conf.iter() {
            for (key, item) in map.iter() {
                let key_val = Box::new(CFUtf8::from_str(key));
                let item_val = Box::new(CFUtf8::from_str(item));
                let conf_pair = Box::new(CFTuple {
                    first: Box::leak(key_val) as *mut _ as _,
                    second: Box::leak(item_val) as *mut _ as _,
                });
                conf_tuples.push(Box::leak(conf_pair) as *mut _ as *mut c_void);
            }
        }
        for conf_val in conf_tuples {
            self.store_push_back(String::from(KEY_PLUGIN_CONF_STR), conf_val);
        }
    }

    pub fn clear_public_store(&mut self) {
        // Free up resources taken our store keys
        let mut tmp_ptr: *mut CFUtf8;
        unsafe {
            let _: Box<CFUtf8> = Box::from_raw(self.store_pop_front(KEY_INPUT_DIR_STR) as *mut _);
            let _: Box<CFUtf8> = Box::from_raw(self.store_pop_front(KEY_STATE_DIR_STR) as *mut _);
            let _: Box<CFUtf8> = Box::from_raw(self.store_pop_front(KEY_RESULT_DIR_STR) as *mut _);
            let _: Box<CFUtf8> = Box::from_raw(self.store_pop_front(KEY_TARGET_PATH_STR) as *mut _);
            let _: Box<CFUtf8> = Box::from_raw(self.store_pop_front(KEY_CWD_STR) as *mut _);
            let _: Box<CFUtf8> =
                Box::from_raw(self.store_pop_front(KEY_CUR_INPUT_PATH_STR) as *mut _);
            let _: Box<CFUtf8> = Box::from_raw(self.store_pop_front(KEY_FUZZER_ID_STR) as *mut _);
            let _: Box<u8> = Box::from_raw(self.store_pop_front(KEY_EXEC_ONLY_MODE_STR) as *mut _);

            let _ = self.store_pop_front(KEY_AVG_DENOMINATOR_STR) as *mut c_void;
            let _ = self.store_pop_front(KEY_CUR_EXEC_NUM_STR) as *mut c_void;
            while !{
                tmp_ptr = self.store_pop_front(KEY_TARGET_ARGS_STR) as _;
                tmp_ptr
            }
            .is_null()
            {
                Box::from_raw(tmp_ptr);
            }

            //Plugin config
            for i in 0..self.config.plugin_conf.len() {
                for _y in 0..self.config.plugin_conf[i].len() {
                    tmp_ptr = self.store_pop_front(KEY_PLUGIN_CONF_STR) as _;
                    let tmp: &CFTuple = &(*(tmp_ptr as *const _));
                    Box::from_raw(tmp.first as *mut CFUtf8);
                    Box::from_raw(tmp.second as *mut CFUtf8);
                    Box::from_raw(tmp_ptr);
                }
            }
        }
    }

    pub fn store_push_back(&mut self, key: String, value: *mut c_void) {
        let key_vec: &mut VecDeque<*mut c_void> = match self.store.entry(key) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => v.insert(VecDeque::with_capacity(2)),
        };

        key_vec.push_back(value);
    }
    pub fn store_push_front(&mut self, key: String, value: *mut c_void) {
        let key_vec: &mut VecDeque<*mut c_void> = match self.store.entry(key) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => v.insert(VecDeque::with_capacity(2)),
        };

        key_vec.push_front(value);
    }
    pub fn store_pop_back(&mut self, key: &str) -> *mut c_void {
        match self.store.get_mut(key) {
            Some(v) => v.pop_back().unwrap_or(null_mut()),
            None => null_mut(),
        }
    }
    pub fn store_pop_front(&mut self, key: &str) -> *mut c_void {
        match self.store.get_mut(key) {
            Some(v) => v.pop_front().unwrap_or(null_mut()),
            None => null_mut(),
        }
    }
    pub fn store_get_mut(&mut self, key: &str, index: usize) -> *mut c_void {
        match self.store.get_mut(key) {
            Some(v) => {
                if let Some(data) = v.get_mut(index) {
                    *data
                } else {
                    null_mut()
                }
            }
            None => null_mut(),
        }
    }
    pub fn store_len(&mut self, key: &str) -> usize {
        match self.store.get(key) {
            Some(v) => v.len(),
            None => 0,
        }
    }
}
