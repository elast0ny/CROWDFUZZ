use std::collections::hash_map::Entry;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::ptr::null_mut;

use crate::core::Core;

impl Core {
    pub fn init_public_store(&mut self) {
        self.store_push_front(
            String::from(cflib::KEY_INPUT_DIR_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.input))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_STATE_DIR_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.state))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_RESULT_DIR_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.results))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_TARGET_PATH_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.target))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_CWD_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.cwd))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_CUR_INPUT_PATH_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(
                &self.config.input_file_name,
            ))) as *mut _ as _,
        );
        self.store_push_front(
            String::from(cflib::KEY_AVG_DENOMINATOR_STR),
            &self.avg_denominator as *const _ as _,
        );
        let ptr: *mut c_void = self.stats.num_execs as *mut _ as _;
        self.store_push_front(String::from(cflib::KEY_CUR_EXEC_NUM_STR), ptr);

        let mut tmp_list = Vec::with_capacity(self.config.target_args.len());
        for arg in &self.config.target_args {
            tmp_list.push(Box::leak(Box::new(cflib::CTuple::from_utf8(arg))) as *mut _ as _);
        }
        for arg in &tmp_list {
            self.store_push_back(String::from(cflib::KEY_TARGET_ARGS_STR), *arg);
        }
        self.store_push_front(
            String::from(cflib::KEY_FUZZER_ID_STR),
            Box::leak(Box::new(cflib::CTuple::from_utf8(&self.config.prefix))) as *mut _ as _,
        );
    }

    pub fn clear_public_store(&mut self) {
        // Free up resources taken our store keys
        let mut tmp_ptr: *mut cflib::CTuple;
        unsafe {
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_INPUT_DIR_STR) as *mut _);
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_STATE_DIR_STR) as *mut _);
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_RESULT_DIR_STR) as *mut _);
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_TARGET_PATH_STR) as *mut _);
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_CWD_STR) as *mut _);
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_CUR_INPUT_PATH_STR) as *mut _);
            let _: Box<cflib::CTuple> =
                Box::from_raw(self.store_pop_front(cflib::KEY_FUZZER_ID_STR) as *mut _);

            let _ = self.store_pop_front(cflib::KEY_AVG_DENOMINATOR_STR) as *mut c_void;
            let _ = self.store_pop_front(cflib::KEY_CUR_EXEC_NUM_STR) as *mut c_void;
            while !{
                tmp_ptr = self.store_pop_front(cflib::KEY_TARGET_ARGS_STR) as _;
                tmp_ptr
            }
            .is_null()
            {
                Box::from_raw(tmp_ptr);
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
