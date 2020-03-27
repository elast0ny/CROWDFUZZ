use std::collections::hash_map::Entry;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::ptr::null_mut;

use crate::core::Core;

impl Core {
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
