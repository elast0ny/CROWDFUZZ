
use ::cflib::*;
use crypto::digest::Digest;
use std::fs::File;
use std::io::prelude::*;


use crate::*;

impl<'i> State<'i> {
    /// Calculates a unique ID for a file
    pub fn is_unique(&mut self, input: &CfInput) -> bool {
        self.hasher.reset();
        for chunk in &input.chunks {
            self.hasher.input(chunk);
        }
        self.hasher.result(&mut self.tmp_uid);

        self.unique_files.contains(&self.tmp_uid)
    }

    pub fn save_input(&mut self, input: &CfInput) {

        use std::fmt::Write;

        // This updates the tmp_uid
        if !self.is_unique(input) {
            return;
        }

        self.tmp_str.clear();
        for b in &self.tmp_uid {
            let _ = write!(&mut self.tmp_str, "{:02X}", *b);
        }

        self.queue_dir.push(&self.tmp_str);
        let mut file = match File::create(&self.queue_dir) {
            Ok(f) => f,
            _ => return,
        };

        // Write file contents
        for chunk in &input.chunks {
            let _ = file.write_all(chunk);
        }

        // Add file to our tracked file list
        self.input_list.push(CfInputInfo {

        });

    }
}