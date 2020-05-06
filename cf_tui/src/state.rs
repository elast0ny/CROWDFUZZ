use std::{
    collections::HashSet,
    error::Error,
    mem::size_of_val,
    time::{SystemTime, UNIX_EPOCH},
};

use ::shared_memory::SharedMem;
use ::sysinfo::{ProcessExt, RefreshKind, System, SystemExt};

// Every first stat is the exec time
pub const COMPONENT_EXEC_TIME_IDX: usize = 0;

pub struct CachedStat {
    stat_ref: cflib::StatRef,
    cache: cflib::StatVal,
    pretty_tag: String,
    tag_prefix: Option<&'static str>,
    tag_postfix: Option<&'static str>,
    str_repr_stale: bool,
    str_repr: String,
}
impl CachedStat {
    pub fn new(stat_ref: cflib::StatRef) -> Self {
        let (pretty_tag, (tag_prefix, tag_postfix)) = cflib::strip_tag_hints(stat_ref.get_tag());
        let pretty_tag = String::from(pretty_tag);
        let cache = stat_ref.to_owned();
        let str_repr = String::new();
        let str_repr_stale = true;

        Self {
            stat_ref,
            cache,
            pretty_tag,
            tag_prefix,
            tag_postfix,
            str_repr_stale,
            str_repr,
        }
    }

    pub fn val_as_mut(&mut self) -> &mut cflib::StatVal {
        &mut self.cache
    }

    pub fn val_as_ref(&self) -> &cflib::StatVal {
        &self.cache
    }

    /// Return the stat tag
    pub fn get_tag(&self) -> &str {
        self.pretty_tag.as_ref()
    }
    pub fn get_orig_tag(&self) -> &str {
        self.stat_ref.get_tag()
    }

    pub fn get_type(&self) -> cflib::StatType {
        self.stat_ref.get_type()
    }

    /// Returns the current string representation of the stat data
    /// Calling this might trigger an update of the internal string representation
    pub fn val_as_str(&mut self) -> &str {
        if self.str_repr_stale {
            self.update_str_repr();
        }
        self.str_repr.as_str()
    }

    /// Returns a (tag, val) tuple
    pub fn get_tuple(&mut self) -> (&str, &str) {
        if self.str_repr_stale {
            self.update_str_repr();
        }
        (self.get_tag(), self.str_repr.as_str())
    }

    /// Updates the cached value of the stat
    pub fn refresh(&mut self, force: bool) -> bool {
        if force || !self.cache.is_equal(&self.stat_ref) ||
            //Epoch values "change" as time progresses
            match self.tag_postfix {
                Some(cflib::NUM_POSTFIX_EPOCHS_STR) => true,
                _ => false,
            }
        {
            self.cache.update(&self.stat_ref);
            // Fixup static epoch to represent number of seconds elpased
            if let Some(cflib::NUM_POSTFIX_EPOCHS_STR) = self.tag_postfix {
                match self.cache {
                    cflib::StatVal::Number(ref mut v) => {
                        *v = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            - *v
                    }
                    _ => {}
                };
            }
            self.set_val_changed();
            true
        } else {
            false
        }
    }

    pub fn set_val_changed(&mut self) {
        self.str_repr_stale = true;
    }

    fn update_str_repr(&mut self) {
        if self.str_repr_stale {
            if let Some(postfix) = self.tag_postfix {
                cflib::write_pretty_stat(&mut self.str_repr, &self.cache, postfix);
            } else {
                self.cache.write_str(&mut self.str_repr);
            }
            self.str_repr_stale = false;
        }
    }
}

use std::fmt;
impl fmt::Display for CachedStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cache)
    }
}

pub struct Plugin {
    pub name: String,
    // Name with some details
    pub stats: Vec<CachedStat>,
}

impl Plugin {
    pub fn refresh(&mut self, force: bool) {
        for stat in self.stats.iter_mut() {
            stat.refresh(force);
        }
    }

    pub fn combine_stats(plugin: &mut Self, plugin_list: &[&Self], stat_idx: Option<usize>) {
        if plugin_list.len() == 0 {
            return;
        }
        let num_plugins = 1 + plugin_list.len();

        //Only merge specific stat
        if let Some(idx) = stat_idx {
            for cur_plugin in plugin_list {
                let stat = &cur_plugin.stats[idx];
                if stat.tag_prefix.is_none() {
                    continue;
                }
                // Add the value
                match plugin.stats[idx].val_as_mut() {
                    cflib::StatVal::Number(v) => *v += stat.val_as_ref().as_num().unwrap(),
                    _ => continue,
                };
            }

            // If average, divide by number of values
            if let Some(cflib::TAG_PREFIX_AVERAGE_STR) = plugin.stats[idx].tag_prefix {
                if let cflib::StatVal::Number(v) = plugin.stats[idx].val_as_mut() {
                    *v /= num_plugins as u64;
                }
            }
            return;
        }

        // Merge ALL stats
        for cur_plugin in plugin_list {
            for (idx, stat) in cur_plugin.stats.iter().enumerate() {
                // Only prefixes for now have same behavior, add up average_ | total_
                if stat.tag_prefix.is_none() {
                    continue;
                }
                // Add the value
                match plugin.stats[idx].val_as_mut() {
                    cflib::StatVal::Number(v) => *v += stat.val_as_ref().as_num().unwrap(),
                    _ => continue,
                };
            }
        }

        // fixup averages
        for stat in plugin.stats.iter_mut() {
            // If average, divide by number of values
            if let Some(cflib::TAG_PREFIX_AVERAGE_STR) = stat.tag_prefix {
                if let cflib::StatVal::Number(v) = stat.val_as_mut() {
                    *v /= num_plugins as u64;
                }
            }
        }
    }
}

pub struct Fuzzer {
    #[allow(unused)]
    shmem: SharedMem,
    pub cur_plugin_idx: usize,
    pub pid: u32,
    pub pretty_name: String,
    pub core: Plugin,
    pub max_plugin_name_len: u16,
    pub plugins: Vec<Plugin>,
    // Plugin idx and stat idx for the avg_target_exec_time
    pub target_exec_stat: Option<(usize, usize)>,
}

impl Fuzzer {
    /// refresh the current plugin stats
    pub fn refresh_plugin(&mut self, plugin_idx: usize) -> &mut Plugin {
        let cur_plugin = &mut self.plugins[plugin_idx];

        cur_plugin.refresh(false);

        // Substract target_exec_time from the plugin time if applicable
        if let Some((idx, stat_idx)) = self.target_exec_stat {
            if plugin_idx != idx {
                return cur_plugin;
            }
            let target_time = cur_plugin.stats[stat_idx].val_as_mut().as_num().unwrap();
            match cur_plugin.stats[COMPONENT_EXEC_TIME_IDX].val_as_mut() {
                cflib::StatVal::Number(v) => {
                    if target_time < *v {
                        *v -= target_time;
                    } else {
                        *v = 0;
                    }
                    cur_plugin.stats[COMPONENT_EXEC_TIME_IDX].set_val_changed();
                }
                _ => {}
            };
        }

        cur_plugin
    }

    /// Refresh the core stats
    pub fn refresh(&mut self, force: bool) {
        // Update all core stats
        self.core.refresh(force);

        // We must fixup plugin exec time if its running the target bin
        if let Some((exec_plugin_idx, exec_stat_idx)) = self.target_exec_stat {
            for (cur_idx, plugin) in self.plugins.iter_mut().enumerate() {
                plugin.stats[COMPONENT_EXEC_TIME_IDX].refresh(false);
                if cur_idx == exec_plugin_idx {
                    plugin.stats[exec_stat_idx].refresh(false);
                    let target_exec_time =
                        plugin.stats[exec_stat_idx].val_as_ref().as_num().unwrap();
                    if let cflib::StatVal::Number(ref mut v) =
                        plugin.stats[COMPONENT_EXEC_TIME_IDX].val_as_mut()
                    {
                        if target_exec_time > *v {
                            *v = 0;
                        } else {
                            *v -= target_exec_time;
                        }
                    }
                }
            }
        // Regular refresh
        } else {
            for plugin in self.plugins.iter_mut() {
                plugin.stats[COMPONENT_EXEC_TIME_IDX].refresh(false);
            }
        }
    }

    pub fn is_alive(pid: u32, sys_info: &mut System) -> bool {
        match sys_info.get_process(pid as _) {
            None => false,
            Some(p) => p.name().starts_with("crowdfuzz"),
        }
    }

    pub fn new(shmem: SharedMem, sys_info: &mut System) -> Result<Self, Box<dyn Error>> {
        let shmem_base: *mut u8 = shmem.get_ptr() as *mut _;
        let header: &'static cflib::StatFileHeader = unsafe { &mut *(shmem_base as *mut _) };
        let mut shmem_idx = size_of_val(header);
        //println!("{:p} : {} {} {}", shmem_base, header.stat_len, header.pid, header.state);

        // Can safely read header
        if header.stat_len <= size_of_val(header) as u32 {
            return Err(From::from(format!("Fuzzer not initialized yet")));
        // Core is initialized
        } else if header.state != cflib::CORE_FUZZING {
            return Err(From::from(format!("Fuzzer not initialized yet")));
        } else if !Fuzzer::is_alive(header.pid, sys_info) {
            // Trigger a refresh to make sure it didnt spawn recently
            sys_info.refresh_processes();
            if !Fuzzer::is_alive(header.pid, sys_info) {
                return Err(From::from(format!(
                    "Fuzzer with pid {} not alive anymore...",
                    header.pid
                )));
            }
        }

        // First stat should be the fuzzer core
        let core_name: String;
        let cur_stat = cflib::StatRef::from_base_ptr(
            unsafe { shmem_base.add(shmem_idx) },
            header.stat_len as usize - shmem_idx,
        )?;
        let cur_val = cur_stat.to_owned();
        match cur_val {
            cflib::StatVal::Component(name) => {
                core_name = name;
            }
            _ => {
                return Err(From::from(
                    "Fuzzer stats does not start with a Component stat".to_owned(),
                ))
            }
        };
        shmem_idx += cur_stat.mem_len();

        let mut cur_fuzzer = Fuzzer {
            shmem,
            pretty_name: format!("{}({})", core_name, header.pid),
            pid: header.pid,
            core: Plugin {
                name: core_name,
                stats: Vec::new(),
            },
            max_plugin_name_len: 0,
            cur_plugin_idx: 0,
            plugins: Vec::new(),
            target_exec_stat: None,
        };

        let (mut target_plugin_idx, mut target_stat_idx) = (0usize, 0usize);
        let mut cur_plugin: &mut Plugin = &mut cur_fuzzer.core;
        loop {
            // Parse the next shmem blob
            if shmem_idx >= header.stat_len as usize {
                break;
            }
            let cur_stat = cflib::StatRef::from_base_ptr(
                unsafe { shmem_base.add(shmem_idx) },
                header.stat_len as usize - shmem_idx,
            )?;
            shmem_idx += cur_stat.mem_len();

            let cur_tag = cur_stat.get_tag();
            // Found new component
            if cur_stat.is_component() {
                let name = cur_tag;
                if name.len() as u16 > cur_fuzzer.max_plugin_name_len {
                    cur_fuzzer.max_plugin_name_len = name.len() as u16;
                }
                if cur_fuzzer.target_exec_stat.is_none() {
                    target_plugin_idx += 1;
                    target_stat_idx = 0;
                }
                // Got all stats for last plugin, refresh them
                cur_plugin.refresh(true);

                // Add plugin to list
                cur_fuzzer.plugins.push(Plugin {
                    name: name.to_string(),
                    stats: Vec::new(),
                });
                cur_plugin = cur_fuzzer.plugins.last_mut().unwrap();
            // Found new stat
            } else {
                let new_stat = CachedStat::new(cur_stat);
                if cur_fuzzer.target_exec_stat.is_none() {
                    if new_stat.get_type() == cflib::STAT_NUMBER as _
                        && new_stat.get_orig_tag() == cflib::STAT_TAG_TARGET_EXEC_TIME_STR
                    {
                        cur_fuzzer.target_exec_stat =
                            Some((target_plugin_idx - 1, target_stat_idx));
                    } else {
                        target_stat_idx += 1;
                    }
                }
                cur_plugin.stats.push(new_stat);
            }
        }
        Ok(cur_fuzzer)
    }
}

pub struct State {
    pub unique_fuzzers: HashSet<String>,
    pub fuzzers: Vec<Fuzzer>,
    pub fuzzer_prefix: String,
    pub stat_file_prefix: String,
    pub monitored_dir: String,
    pub sys_info: System,
    pub changed: bool,
    pub tab_titles: Vec<String>,
}

impl State {
    pub fn new(args: ::clap::ArgMatches) -> Self {
        let mut state = Self {
            unique_fuzzers: HashSet::new(),
            fuzzers: Vec::new(),
            fuzzer_prefix: String::from(args.value_of("fuzzer_prefix").unwrap()),
            stat_file_prefix: String::from(args.value_of("stats_prefix").unwrap()),
            monitored_dir: String::from(args.value_of("project_state").unwrap()),
            sys_info: System::new_with_specifics(
                RefreshKind::new().with_processes().with_cpu().with_memory(),
            ),
            tab_titles: Vec::new(),
            changed: true,
        };

        state.sys_info.refresh_cpu();
        state.sys_info.refresh_memory();

        state
    }
    /// Removes any dead fuzzer and scans the directories for new fuzzers
    pub fn update_fuzzers(&mut self) {
        self.sys_info.refresh_processes();
        let mut to_del: Vec<usize> = Vec::new();
        for (idx, fuzzer) in self.fuzzers.iter().enumerate() {
            if !Fuzzer::is_alive(fuzzer.pid, &mut self.sys_info) {
                to_del.push(idx);
            }
        }
        if to_del.len() > 0 {
            self.remove_fuzzers(&to_del);
        }

        let mut found_files = Vec::new();
        if let Ok(mut dir_list) = std::fs::read_dir(&self.monitored_dir) {
            while let Some(Ok(entry)) = dir_list.next() {
                let metadata = match entry.metadata() {
                    Ok(v) => v,
                    _ => continue,
                };
                if !metadata.is_file() {
                    continue;
                }

                let file_path = entry.path();
                if file_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with(&self.stat_file_prefix)
                {
                    found_files.push(file_path);
                }
            }
        }

        // Try to load all the files
        for fpath in found_files.iter() {
            let shmem = match SharedMem::open_linked(&fpath) {
                Ok(m) => {
                    // we already are tracking this fuzzer
                    if self.unique_fuzzers.contains(m.get_os_path()) {
                        continue;
                    }
                    m
                }
                Err(_e) => {
                    //println!("Failed to open {} : {:?}", fpath.to_string_lossy(), e);
                    continue;
                }
            };

            let new_fuzzer = match Fuzzer::new(shmem, &mut self.sys_info) {
                Ok(f) => f,
                Err(_e) => {
                    //println!("Failed to parse '{}' : {:?}", fpath.to_string_lossy(), e);
                    continue;
                }
            };
            self.add_fuzzer(new_fuzzer);
        }
    }

    /// Returns whether this fuzzer can be combined with the other existing fuzzers
    fn is_valid_fuzzer(&mut self, fuzzer: &Fuzzer) -> bool {
        if self.fuzzers.len() == 0 {
            return true;
        }

        // Compare stats to the first fuzzer
        let baseline_fuzzer = &self.fuzzers[0];
        if baseline_fuzzer.core.stats.len() != fuzzer.core.stats.len()
            || baseline_fuzzer.plugins.len() != fuzzer.plugins.len()
        {
            eprintln!(
                "Ignoring fuzzer {} because of incompatible projects",
                fuzzer.pid
            );
            return false;
        }

        // Validate fuzzer core stats
        for (idx, stat) in fuzzer.core.stats.iter().enumerate() {
            let baseline_stat = &baseline_fuzzer.core.stats[idx];

            if baseline_stat.get_tag() != stat.get_tag()
                || baseline_stat.get_type() != stat.get_type()
            {
                eprintln!(
                    "Ignoring fuzzer {} : stat {} doesnt match",
                    fuzzer.pid,
                    stat.get_tag()
                );
                return false;
            }
        }

        // Validate plugins
        for (idx, plugin) in fuzzer.plugins.iter().enumerate() {
            let baseline_plugin = &baseline_fuzzer.plugins[idx];

            if baseline_plugin.name != plugin.name
                || baseline_plugin.stats.len() != plugin.stats.len()
            {
                eprintln!(
                    "Ignoring fuzzer {} : plugin {} doesnt match",
                    fuzzer.pid, plugin.name
                );
                return false;
            }

            for (idx, stat) in plugin.stats.iter().enumerate() {
                let baseline_stat = &baseline_plugin.stats[idx];

                if baseline_stat.get_tag() != stat.get_tag()
                    || baseline_stat.get_type() != stat.get_type()
                {
                    eprintln!(
                        "Ignoring fuzzer {} : stat {} doesnt match",
                        fuzzer.pid,
                        stat.get_tag()
                    );
                    return false;
                }
            }
        }
        return true;
    }

    fn add_fuzzer(&mut self, fuzzer: Fuzzer) {
        self.changed = true;

        self.unique_fuzzers
            .insert(fuzzer.shmem.get_os_path().to_string());

        if self.is_valid_fuzzer(&fuzzer) {
            self.fuzzers.push(fuzzer);
        }
    }

    fn remove_fuzzers(&mut self, idx_list: &[usize]) {
        self.changed = true;
        for idx in idx_list.iter().rev() {
            let fuzzer = self.fuzzers.remove(*idx);
            self.unique_fuzzers.remove(fuzzer.shmem.get_os_path());
        }
    }
}
