
use ::cflib::*;
use crypto::digest::Digest;

use crate::*;


impl<'i> State<'i> {
    /// Calculates a unique ID for a file
    pub fn calc_uid(&mut self, input: &CfInput) {
        self.hasher.reset();
        for chunk in &input.chunks {
            self.hasher.input(chunk);
        }
        self.tmp_uid.clear();
        self.hasher.result(&mut self.tmp_uid);
    }
}