use std::fs::{self, File};
use std::io::prelude::*;
use std::path::Path;

use ::cflib::*;
use ::crypto::{digest::Digest, sha1::Sha1};

use crate::*;

// We currently use Sha1. It might be worth exploring speed differences
// with doing a pre crc32 check first ?
fn compute_uid(hasher: &mut Sha1, chunks: &[&[u8]], dst: &mut [u8; 20]) {
    hasher.reset();
    for chunk in chunks {
        hasher.input(chunk);
    }
    hasher.result(dst);
}

fn read_file(src: &Path, dst: &mut Vec<u8>) -> bool {
    // Open file
    let mut fin = match File::open(src) {
        Ok(f) => f,
        _ => return false,
    };
    // Read contents
    dst.clear();
    if fin.read_to_end(dst).is_err() {
        return false;
    }
    true
}

fn write_file(dst: &Path, chunks: &[&[u8]]) -> bool {
    let mut file = match File::create(dst) {
        Ok(f) => f,
        _ => return false,
    };
    // Write file contents
    for chunk in chunks {
        if file.write_all(chunk).is_err() {
            let _ = std::fs::remove_file(&dst);
            return false;
        }
    }
    true
}

impl State {
    pub fn init(&mut self, core: &dyn PluginInterface, extra_input_folder: &str) {
        // first scan the input directory
        if let Ok(list) = fs::read_dir(extra_input_folder) {
            for r in list {
                let item = match r {
                    Ok(i) => i,
                    _ => continue,
                };
                // Skip directories
                let path = item.path();
                if path.is_dir() {
                    continue;
                }

                //_core.log(::log::Level::Info, "File in input dir !");

                // Add our temporary file to the list of new_inputs
                self.new_inputs.push(CfNewInput {
                    contents: None,
                    path: Some(path),
                });

                // Save if new
                self.save_new_inputs(core, false);
            }
        }

        // scan the queue directory
        if let Ok(list) = fs::read_dir(&self.queue_dir) {
            for r in list {
                let item = match r {
                    Ok(i) => i,
                    _ => continue,
                };
                // Skip directories
                let path = item.path();
                if path.is_dir() {
                    continue;
                }

                //_core.log(::log::Level::Info, "File in input dir !");
                if !read_file(path.as_path(), &mut self.tmp_buf) {
                    continue;
                }

                // Compute the hash of input into tmp_uid
                compute_uid(&mut self.hasher, &[&mut self.tmp_buf], &mut self.tmp_uid);
                if !self.unique_files.insert(self.tmp_uid) {
                    //_core.log(::log::Level::Info, "existing file");
                    //true is returned if new entry
                    continue;
                }

                // Add file to input_list
                self.input_list.push(CfInputInfo {
                    uid: self.tmp_uid.to_vec(),
                    path: Some(path),
                    contents: None,
                });
            }
        }
    }

    /// Save any new file
    pub fn save_new_inputs(&mut self, _core: &dyn PluginInterface, write_to_queue: bool) -> bool {
        let mut saved_one = false;
        let mut cur_input: Vec<&[u8]> = Vec::with_capacity(1);
        let mut cur_fpath: Option<PathBuf>;

        for new_input in self.new_inputs.drain(..) {
            cur_input.clear();

            // Either content was passed or we must read a file
            match new_input.contents {
                Some(v) => {
                    cur_fpath = None;
                    for chunk in raw_to_ref!(v, CfInput).chunks.iter() {
                        cur_input.push(chunk);
                    }
                }
                None => {
                    match new_input.path {
                        Some(p) if read_file(p.as_path(), &mut self.tmp_buf) => {
                            cur_fpath = Some(p);
                            // Borrow checker doesnt realise that vec.clear() drops the immutable ref...
                            cur_input.push(unsafe {
                                std::slice::from_raw_parts(
                                    self.tmp_buf.as_ptr(),
                                    self.tmp_buf.len(),
                                )
                            });
                        }
                        _ => continue,
                    }
                }
            };

            // Compute the hash of input into tmp_uid
            compute_uid(&mut self.hasher, &cur_input, &mut self.tmp_uid);
            if !self.unique_files.insert(self.tmp_uid) {
                //_core.log(::log::Level::Info, "existing file");
                //true is returned if new entry
                continue;
            }

            if cur_fpath.is_none() {
                // Convert hex digest to hex string
                self.tmp_str.clear();
                use std::fmt::Write;
                for b in &self.tmp_uid {
                    let _ = write!(&mut self.tmp_str, "{:02X}", *b);
                }
                // append to base directory
                self.queue_dir.push(&self.tmp_str);
                cur_fpath = Some(self.queue_dir.clone());
                let _ = self.queue_dir.pop();
            }

            //_core.log(::log::Level::Info, &format!("sha1 {:?}", &mut self.tmp_uid));

            if write_to_queue && !write_file(cur_fpath.as_ref().unwrap().as_path(), &cur_input) {
                let _ = self.unique_files.remove(&self.tmp_uid);
                continue;
            }

            // Add file to input_list
            self.input_list.push(CfInputInfo {
                uid: self.tmp_uid.to_vec(),
                path: cur_fpath,
                contents: None,
            });

            *self.num_inputs.val += 1;
            saved_one = true;
        }

        saved_one
    }
}
