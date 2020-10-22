use ::crossterm::{
    cursor::{DisableBlinking, EnableBlinking, Hide, Show},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ::sysinfo::{ProcessorExt, SystemExt};
use ::tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::*,
    Frame, Terminal,
};
use std::io::{stdout, Stdout, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use cflib::*;

use crate::*;

pub struct UiState {
    pub tab_title: String,
    pub selected_tab: usize,
    pub footer_content: Vec<String>,
    pub selected_plugin: usize,
    pub main_title: String,

    // Cached stats
    pub main_view: Vec<(String, CachedStat)>,
    pub plugins_list_view: Vec<(String, CachedStat)>,
    pub plugins_view: Vec<(String, CachedStat)>,

    // State for dynamic lists
    pub plugin_list: ListState,
}
impl Default for UiState {
    fn default() -> Self {
        Self {
            tab_title: String::from("Fuzzers (0)"),
            selected_tab: 0,
            footer_content: vec![
                String::from("Load [cpu "),
                String::new(), // 1
                String::from(", mem "),
                String::new(), // 3
                String::from("]"),
            ],
            selected_plugin: 0,
            main_title: String::new(),
            main_view: Vec::new(),
            plugins_list_view: Vec::new(),
            plugins_view: Vec::new(),
            plugin_list: ListState::default(),
        }
    }
}
impl UiState {
    pub fn clear_all(&mut self) {
        // Clear all the cached values
        self.main_view.clear();
        self.plugins_list_view.clear();
        self.plugins_view.clear();

        self.selected_plugin = 0;
        self.selected_tab = 0;
        self.plugin_list.select(None);
    }
}

pub fn decrement_selected(val: &mut usize, max: usize, loop_to_max: bool) {
    if *val == 0 {
        if loop_to_max {
            *val = max - 1;
        }
        return;
    }
    *val -= 1;
}

pub fn increment_selected(val: &mut usize, max: usize, loop_to_zero: bool) {
    if *val == max - 1 {
        if loop_to_zero {
            *val = 0;
        }
        return;
    }
    *val += 1;
}

pub fn select_next_plugin(state: &mut State) {
    if !state.fuzzers.is_empty() {
        let prev = state.ui.selected_plugin;
        increment_selected(&mut state.ui.selected_plugin, state.fuzzers[0].stats.plugins.len() - 1, true);
        if prev != state.ui.selected_plugin {
            state.ui.plugins_view.clear();
            state.ui.plugin_list.select(Some(state.ui.selected_plugin))
        }
    }
}

pub fn select_prev_plugin(state: &mut State) {
    if !state.fuzzers.is_empty() {
        let prev = state.ui.selected_plugin;
        decrement_selected(&mut state.ui.selected_plugin, state.fuzzers[0].stats.plugins.len() - 1, true);
        if prev != state.ui.selected_plugin {
            state.ui.plugins_view.clear();
            state.ui.plugin_list.select(Some(state.ui.selected_plugin))
        }
    }
}

pub fn draw<B: Backend>(state: &mut State, f: &mut Frame<B>) {
    let size = f.size();
    // Split terminal into 3 main parts
    let rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Length(size.height - 4),
                Constraint::Length(1),
            ]
            .as_ref(),
        )
        .split(size);

    // Draw main sections
    let (header_rect, content_rect, footer_rect) = (rects[0], rects[1], rects[2]);
    draw_header(state, f, header_rect);
    draw_fuzzer(state, f, content_rect);
    draw_footer(state, f, footer_rect);
}

/// Renders selectable tabs
pub fn draw_header<B: Backend>(state: &mut State, f: &mut Frame<B>, area: Rect) {
    let fuzzer_tab_titles = std::iter::once("All")
        .chain(
            state
                .fuzzers
                .iter()
                .map(|f| f.stats.plugins[0].name.as_str()),
        )
        .collect::<Vec<&str>>()
        .drain(..)
        .map(Spans::from)
        .collect();

    let fuzzer_tabs = Tabs::new(fuzzer_tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(state.ui.tab_title.as_str()),
        )
        .highlight_style(Style::default().fg(Color::Yellow))
        .select(state.ui.selected_tab);
    f.render_widget(fuzzer_tabs, area);
}

pub fn get_or_add_cached_stat<'a>(list : &'a mut Vec<(String, CachedStat)>, idx: usize, tag: &str, stat: &mut StatVal) -> &'a mut (String, CachedStat) {

    if list.len() <= idx {
        list.push((String::from(tag), CachedStat::from(stat)))     
    }
    
    if list.len() <= idx {
        let _ = destroy_ui();
        panic!("Trying to get cached_stat {}/{}", idx, list.len()-1);
    }
    let r = list.get_mut(idx).unwrap();
    if r.0.as_str() != tag {
        let _ = destroy_ui();
        panic!("Fuzzers have different stats !?");
    }
    
    r    
}

pub fn agregate_stat(cached_val: &mut ui::CachedStat, tag: &str, stat: &mut StatVal, total_vals: usize) {

    let (cur_num, mut stat_num) = match (&mut cached_val.val, stat)  {
        (CachedStatVal::Num(ref mut c), StatVal::Num(ref s)) => (c, *s.val),
        _ => return, // Can only agregate numbers
    };

    // Convert time since EPOCH to delta from now
    if let Some(postfix) = strip_tag_postfix(tag).1 {
        if postfix == TAG_POSTFIX_EPOCHS {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if stat_num > now {
                stat_num = 0;
            } else {
                stat_num = now - stat_num;
            }
        }
    }
    
    // Total
    if tag.starts_with(TAG_PREFIX_TOTAL) {
        *cur_num += stat_num;
    // Average
    } else if tag.starts_with(TAG_PREFIX_AVG) {
        update_average(cur_num, stat_num, total_vals as u64);
    }
    
}

/// Draws the view when a fuzzer is selected
pub fn draw_fuzzer<B: Backend>(state: &mut State, f: &mut Frame<B>, area: Rect) {
    use std::fmt::Write;
    let mut fuzzer_list = Vec::with_capacity(1);
    
    state.ui.main_title.clear();

    let fuzzer_details = Block::default().borders(Borders::ALL).title(state.ui.main_title.as_str());
    if state.fuzzers.is_empty() {
        let content = Paragraph::new(Span::raw("<No fuzzers>"))
            .block(fuzzer_details)
            .style(Style::default().fg(Color::Red))
            .alignment(tui::layout::Alignment::Center);
        f.render_widget(content, area);
        return;
    }

    // Add up the fuzzers for the current view
    if state.ui.selected_tab == 0 {            
        state.ui.main_title.push_str("Overview");
        for fuzzer in state.fuzzers.iter_mut() {
            fuzzer_list.push(fuzzer);
        }
    } else {
        let fuzzer = state.fuzzers.get_mut(state.ui.selected_tab - 1).unwrap();
        let _ = write!(&mut state.ui.main_title, "core({})", fuzzer.stats.pid);
        fuzzer_list.push(fuzzer);
    }

    // Compute stat values
    for (fuzzer_idx, fuzzer) in fuzzer_list.drain(..).enumerate() {
        'plugin_loop: for (plugin_idx, plugin) in fuzzer.stats.plugins.iter_mut().enumerate() {

            // Calculate either the main core plugin view or selected plugin view
            let mut cached_view = if plugin_idx == 0 {
                // First plugin is for the core
                Some(&mut state.ui.main_view)
            } else if plugin_idx - 1 == state.ui.selected_plugin {
                // This is the active plugin in the plugin_details view
                Some(&mut state.ui.plugins_view)
            } else {
                None
            };
            
            for (stat_idx, stat) in plugin.stats.iter_mut().enumerate() {
                // Calculate exec time for all plugins
                if plugin_idx != 0 && stat_idx == 0 {
                    let (_, cached_val) = get_or_add_cached_stat(&mut state.ui.plugins_list_view, plugin_idx-1, plugin.name.as_str(), &mut stat.val);
                    if fuzzer_idx == 0 {
                        cached_val.set(&mut stat.val);
                    } else {
                        agregate_stat(cached_val, plugin.name.as_str(), &mut stat.val, fuzzer_idx + 1);
                    }
                }

                // If this is the fuzzer core or selected plugin stats
                let cached_view = match cached_view {
                    Some(ref mut c) => c,
                    None => continue 'plugin_loop,
                };
                
                // Rename first stat to core/plugin time
                let cur_tag = if stat_idx == 0 {
                    if plugin_idx == 0 {
                        "avg_core_time_us"
                    } else {
                        "avg_plugin_time_us"
                    }                    
                } else {
                    stat.tag.as_str() 
                };
                
                let (cached_tag, cached_val) = get_or_add_cached_stat(cached_view, stat_idx, cur_tag, &mut stat.val);
                if fuzzer_idx == 0 {
                    cached_val.set(&mut stat.val);

                    // Convert time since EPOCH to delta from now
                    if let Some(postfix) = strip_tag_postfix(cached_tag.as_str()).1 {
                        if postfix == TAG_POSTFIX_EPOCHS {
                            if let CachedStatVal::Num(ref mut v) = cached_val.val {
                                let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                                if *v > now {
                                    *v = 0;
                                } else {
                                    *v = now - *v;
                                }
                            }
                        }
                    }
                } else {
                    agregate_stat(cached_val, stat.tag.as_str(), &mut stat.val, fuzzer_idx + 1);
                }
            }
        }
    }

    let mut max_tag_len: usize = 0;
    let mut max_val_len: usize = 0;
    let mut max_plugin_name_len: usize = 0;
    let mut max_plugin_tag_len: usize = 0;
    
    // Generate string representations and calculate max lengths for ui splitting
    for (tag, val) in state.ui.main_view.iter_mut() {
        let (stripped_tag, tag_hints) =  strip_tag_hints(tag.as_str());
        if stripped_tag.len() > max_tag_len {
            max_tag_len = stripped_tag.len();
        }
        val.update_str_repr(tag_hints);
        if val.str_repr.len() > max_val_len {
            max_val_len = val.str_repr.len();
        }
    }
    for (tag, val) in state.ui.plugins_list_view.iter_mut() {
        if tag.len() > max_plugin_name_len {
            max_plugin_name_len = tag.len();
        }
        val.update_str_repr((None, Some(TAG_POSTFIX_US)));
    }
    for (tag, val) in state.ui.plugins_view.iter_mut() {
        let (stripped_tag, tag_hints) =  strip_tag_hints(tag.as_str());
        if stripped_tag.len() > max_plugin_tag_len {
            max_plugin_tag_len = stripped_tag.len();
        }
        val.update_str_repr(tag_hints);
    }

    use std::cmp::max;

    // Split the view accordingly vertically
    let details_rect = area;
        let rects = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length((max(state.ui.main_view.len(), state.ui.plugins_list_view.len()) + 2) as u16),
                    Constraint::Percentage(100),
                ]
                .as_ref(),
            )
            .split(details_rect);
    let core_details_rect = rects[0];
    let plugin_details_rect = rects[1];
    // Split the main view for core & plugin list
    let rects = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Length((1 + max_tag_len + 2) as u16),
                Constraint::Length((max_val_len + 1) as u16),
                Constraint::Length((2 + max_plugin_name_len + 2) as u16),
                Constraint::Percentage(100),
                
            ]
            .as_ref(),
        )
        .split(core_details_rect);
    let core_tag_list_rect = rects[0];
    let core_val_list_rect = rects[1];
    let plugins_list_rect = rects[2];
    let plugins_time_rect = rects[3];
    // Split bottom area for currently selected plugin
    let rects = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Length((1 + max_plugin_tag_len + 2) as u16),
                Constraint::Percentage(100),
            ]
            .as_ref(),
        )
        .split(plugin_details_rect);
    let plugin_tag_list_rect = rects[0];
    let plugin_val_list_rect = rects[1];

    // core stat tags
    let items: Vec<ListItem>= state.ui.main_view.iter().map(|i| ListItem::new(strip_tag_hints(i.0.as_str()).0)).collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
            .title(state.ui.main_title.as_str()),
        );
    f.render_widget(list, core_tag_list_rect);
    // core stat values
    let items: Vec<ListItem>= state.ui.main_view.iter().map(|i| ListItem::new(i.1.str_repr.as_str())).collect();
    let list = List::new(items).block(Block::default().borders(Borders::TOP | Borders::BOTTOM));
    f.render_widget(list, core_val_list_rect);

    // plugin list names
    let items: Vec<ListItem>= state.ui.plugins_list_view.iter().map(|i| ListItem::new(i.0.as_str())).collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
            .title("Plugins"),
        ).highlight_symbol(">")
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, plugins_list_rect, &mut state.ui.plugin_list);
    // plugin list times
    let items: Vec<ListItem>= state.ui.plugins_list_view.iter().map(|i| ListItem::new(i.1.str_repr.as_str())).collect();
    let list = List::new(items).block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_widget(list, plugins_time_rect);

    // selected plugin stat tags
    let items: Vec<ListItem>= state.ui.plugins_view.iter().map(|i| ListItem::new(strip_tag_hints(i.0.as_str()).0)).collect();
    let list = List::new(items).block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
        .title(state.fuzzers[0].stats.plugins[state.ui.selected_plugin + 1].name.as_ref()));
    f.render_widget(list, plugin_tag_list_rect);
    //  selected stat values
    let items: Vec<ListItem>= state.ui.plugins_view.iter().map(|i| ListItem::new(i.1.str_repr.as_str())).collect();
    let list = List::new(items).block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT));
    f.render_widget(list, plugin_val_list_rect);
}

pub fn draw_footer<B: Backend>(state: &mut State, f: &mut Frame<B>, area: Rect) {
    state.sys_info.refresh_cpu();
    state.sys_info.refresh_memory();
    let cpu_speed = state
        .sys_info
        .get_processors()
        .iter()
        .fold(0f32, |t, c| t + c.get_cpu_usage()) as usize
        / state.sys_info.get_processors().len();
    let mem_usage =
        ((state.sys_info.get_used_memory() * 100) / state.sys_info.get_total_memory()) as usize;

    use std::fmt::Write;
    let cpu_str = &mut state.ui.footer_content[1];
    cpu_str.clear();
    let _ = write!(cpu_str, "{:02}%", cpu_speed);
    let mem_str = &mut state.ui.footer_content[3];
    mem_str.clear();
    let _ = write!(mem_str, "{:02}%", mem_usage);

    // Apply color to cpu and mem
    let footer = state
        .ui
        .footer_content
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            if idx == 1 {
                Span::styled(
                    s,
                    if cpu_speed > 90 {
                        Style::default().fg(Color::Red)
                    } else if cpu_speed > 75 {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::Green)
                    },
                )
            } else if idx == 3 {
                Span::styled(
                    s,
                    if mem_usage > 90 {
                        Style::default().fg(Color::Red)
                    } else if mem_usage > 75 {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::Green)
                    },
                )
            } else {
                Span::raw(s)
            }
        })
        .collect::<Vec<Span>>();

    let bottom_stats = Paragraph::new(Spans::from(footer))
        //.style(Style::default())
        //.alignment(Alignment::Center)
        .wrap(tui::widgets::Wrap { trim: true });

    f.render_widget(bottom_stats, area);
}

pub fn init_ui() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    // Setup the UI
    enable_raw_mode()?;
    let mut stdout = stdout();
    #[allow(deprecated)]
    execute!(stdout, EnterAlternateScreen, Hide, DisableBlinking)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;
    Ok(terminal)
}

pub fn destroy_ui() -> Result<()> {
    #[allow(deprecated)]
    execute!(stdout(), EnableBlinking, Show, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}

pub struct CachedStat {
    pub val: CachedStatVal,
    pub str_repr_val: Option<u64>,
    pub str_repr: String,
}
impl CachedStat {
    pub fn from(val: &mut StatVal) -> Self {
        // Create copy of real stat
        let val = match val {
            StatVal::Num(v) => CachedStatVal::Num(*v.val),
            StatVal::Str(v) => CachedStatVal::Str(String::from(*v.get())),
            StatVal::Bytes(v) => CachedStatVal::Bytes(Vec::from(*v.get())),
        };

        Self {
            val,
            str_repr_val: None,
            str_repr: String::new(),
        } 
    }

    pub fn set(&mut self, new_val: &mut StatVal) {
        use std::ops::Deref;
    
        match new_val {
            StatVal::Num(v) => match self.val {
                CachedStatVal::Num(ref mut s) => {
                    *s = *v.val;
                },
                _ => panic!("CachedStat::set() with mismatch StatVal"),
            },
            cflib::StatVal::Str(v) => {
                let val = v.get();
                match self.val {
                    CachedStatVal::Str(ref mut s) => {
                        if s != *val {
                            s.clear();
                            s.push_str(*val);
                            self.str_repr_val = Some(1);
                        }
                    }
                    _ => panic!("CachedStat::set() with mismatch StatVal"),
                }
            }
            cflib::StatVal::Bytes(v) => {
                let val = v.get();
                match self.val {
                    CachedStatVal::Bytes(ref mut s) => {
                        if val.deref() != s {
                            s.clear();
                            s.extend_from_slice(*val);
                            self.str_repr_val = Some(1);
                        }
                    }
                    _ => panic!("CachedStat::set() with mismatch StatVal"),
                }
            }
        }
    }

    pub fn update_str_repr(&mut self, tag_hints: (Option<&'static str>, Option<&'static str>)) {
        let must_update = match self.str_repr_val {
            None => true,
            Some(cur_val) => {
                match self.val {
                    CachedStatVal::Num(ref v) => *v != cur_val,
                    _ => cur_val == 1,
                }
            }
        };

        if !must_update {
            return;
        }
        

        self.str_repr.clear();
        match self.val {
            CachedStatVal::Num(v) => {
                self.str_repr_val = Some(v);
                // If this number is a timestamp, pretend it keeps changing
                if let Some(postfix) = tag_hints.1 {
                    if postfix == TAG_POSTFIX_EPOCHS {
                        self.str_repr_val = None;
                    }
                }
                pretty_num(&mut self.str_repr, v, tag_hints);
            },
            CachedStatVal::Str(ref s) => {
                self.str_repr_val = Some(0);
                pretty_str(&mut self.str_repr, s, tag_hints);
            },
            CachedStatVal::Bytes(ref b) => {
                self.str_repr_val = Some(0);
                pretty_bytes(&mut self.str_repr, b, tag_hints);
            },
        }
    }
}

pub enum CachedStatVal {
    Num(u64),
    Str(String),
    Bytes(Vec<u8>),
}
