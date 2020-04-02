use ::bindgen;
use ::bindgen::callbacks::{MacroParsingBehavior, ParseCallbacks};
use std::path::PathBuf;

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct StringMacroCallback {
    macros: Arc<Mutex<HashMap<String, String>>>,
}

impl ParseCallbacks for StringMacroCallback {
    fn will_parse_macro(&self, _name: &str) -> MacroParsingBehavior {
        //if name.starts_with("_SYMBOL") || name.starts_with("SYMBOL") || name.starts_with("KEY") {
        //    MacroParsingBehavior::Ignore
        //} else {
        MacroParsingBehavior::Default
        //}
    }

    /// Convert all C string macros to rust &'static str
    fn str_macro(&self, name: &str, value: &[u8]) {
        let mut new_name = format!("{}_STR", name);
        let mut collision_num = 0;
        let mut macros = self.macros.lock().unwrap();
        while macros.contains_key(&new_name) {
            collision_num += 1;
            new_name = format!("{}_STR_{}", name, collision_num);
        }
        macros.insert(new_name, String::from(from_utf8(value).unwrap()));
    }
}

fn main() {
    let extra_macros = Arc::new(Mutex::new(HashMap::new()));

    let bindings = bindgen::Builder::default()
        .header("include/cflib.h")
        .size_t_is_usize(true)
        .rustfmt_bindings(true)
        .blacklist_item("wchar_t")
        .blacklist_item("max_align_t")
        .parse_callbacks(Box::new(StringMacroCallback {
            macros: extra_macros.clone(),
        }))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    //let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = PathBuf::from("src/");
    let bindings_path = out_path.join("bindings.rs");
    bindings
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings!");

    let mut f = OpenOptions::new()
        .write(true)
        .append(true)
        .open(&bindings_path)
        .unwrap();
    for (k, v) in extra_macros.lock().unwrap().drain() {
        writeln!(f, "pub const {}: &'static str = \"{}\";", k, v).unwrap();
    }
}
