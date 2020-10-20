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
use std::borrow::Cow;
use std::{
    error::Error,
    io::{stdout, Stdout, Write},
};

use crate::*;



pub struct UiState {
    pub tab_title: String,
    pub selected_tab: usize,
    pub footer_content: Vec<String>,
    pub selected_plugin: usize,

    pub main_title: String,
    pub main_view: Vec<(String, CachedStat)>,
    pub plugins_list_view: Vec<(String, CachedStat)>,
    pub plugins_view: Vec<(String, CachedStat)>,
}
impl Default for UiState {
    fn default() -> Self {
        Self {
            tab_title: String::from("Fuzzers (0)"),
            selected_tab: 0,
            footer_content: vec![
                String::from("Load [cpu "),
                String::new(),
                String::from(", mem "),
                String::new(),
                String::from("]"),
            ],
            selected_plugin: 0,
            main_title: String::new(),
            main_view: Vec::new(),
            plugins_list_view: Vec::new(),
            plugins_view: Vec::new(),
        }
    }
}

pub fn decrement_selected(val: &mut usize, max_loop: Option<usize>) {
    if *val == 0 {
        if let Some(max_val) = max_loop {
            *val = max_val - 1;
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
    //draw_fuzzer(state, f, content_rect);
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

/// Draws the view when a fuzzer is selected
pub fn draw_fuzzer<B: Backend>(state: &mut State, f: &mut Frame<B>, area: Rect) {
    use std::fmt::Write;

    let cur_fuzzer;
    let selected_plugin_idx;
    let cur_tab_name: &str;
    
    state.ui.main_title.clear();
    let mut fuzzer_list = Vec::with_capacity(1);

    // Add up the fuzzers for the current view
    if state.ui.selected_tab == 0 {            
        state.ui.main_title.push_str("Overview");

        let fuzzer_details = Block::default().borders(Borders::ALL).title(state.ui.main_title.as_str());
        if state.fuzzers.len() == 0 {
            let content = Paragraph::new(Span::raw("<No fuzzers>"))
                .block(fuzzer_details)
                .style(Style::default().fg(Color::Red))
                .alignment(tui::layout::Alignment::Center);
            f.render_widget(content, area);
            return;
        }

        for fuzzer in state.fuzzers.iter_mut() {
            fuzzer_list.push(fuzzer);
        }
    } else {
        let fuzzer = state.fuzzers.get_mut(state.ui.selected_tab - 1).unwrap();
        let _ = write!(&mut state.ui.main_title, "pid({})", fuzzer.stats.pid);
        fuzzer_list.push(fuzzer);
    }

    // Refresh stat values
    for (fuzzer_idx, fuzzer) in fuzzer_list.drain(..).enumerate() {
        for (plugin_idx, plugin) in fuzzer.stats.plugins.iter_mut().enumerate() {
            let cached_view = if plugin_idx == 0 {
                &mut state.ui.main_view
            } else {
                &mut state.ui.plugins_view
            };

            for (stat_idx, stat) in plugin.stats.iter_mut().enumerate() {
                let (cached_tag, cached_val) = match cached_view.get_mut(stat_idx) {
                    Some(v) => {
                        if v.0.as_str() != stat.tag {
                            destroy_ui();
                            panic!("Fuzzers have different stats !?");
                        }
                        v
                    },
                    None => {
                        cached_view.push((String::from(stat.tag), CachedStat::from(&mut stat.val)));
                        cached_view.get_mut(stat_idx).unwrap()
                    }
                };

                if fuzzer_idx == 0 {
                    cached_val.set(&mut stat.val);
                } else {
                    let cur_val = if let CachedStat::Num(ref mut a) = cached_val {
                        a
                    } else {
                        // Keep first value we got
                        continue;
                    };

                    // Calculate averages and totals
                    if let cflib::StatVal::Num(v) = stat.val {
                        if stat.tag.starts_with(cflib::TAG_PREFIX_TOTAL) {
                            *cur_val += *v.val;
                        } else if stat.tag.starts_with(cflib::TAG_PREFIX_AVG) {
                            cflib::update_average(cur_val, *v.val, fuzzer_idx as u64 + 1);
                        }
                    }
                    // Keep first value we got
                }
            }
        }
    }

    // Overview
    if state.ui.selected_tab == 0 {
        let fuzzer_details = Block::default().borders(Borders::ALL).title("Overview");
        if state.fuzzers.len() == 0 {
            let content = Paragraph::new(Span::raw("<No fuzzers>"))
                .block(fuzzer_details)
                .style(Style::default().fg(Color::Red))
                .alignment(tui::layout::Alignment::Center);
            f.render_widget(content, area);
            return;
        }

        // Refresh stat values
        for fuzzer in state.fuzzers.iter_mut() {
            for (plugin_idx, plugin) in fuzzer.stats.plugins.iter_mut().enumerate() {
                let cached_view = if plugin_idx == 0 {
                    &mut state.ui.main_view
                } else {
                    &mut state.ui.plugins_view
                };

                for (stat_idx, stat) in plugin.stats.iter_mut().enumerate() {
                    
                }
            }
        }

        // Merge stats
        let (head, tail) = self.state.fuzzers.split_at_mut(1);
        // Fuzzer stats
        Plugin::combine_stats(
            &mut head[0].core,
            &tail.iter().map(|f| &f.core).collect::<Vec<&Plugin>>(),
            None,
        );
        // Plugin stats
        for (idx, plugin) in head[0].plugins.iter_mut().enumerate() {
            let plugin_list = &tail
                .iter()
                .map(|f| &f.plugins[idx])
                .collect::<Vec<&Plugin>>();
            if idx == selected_plugin_idx {
                Plugin::combine_stats(plugin, plugin_list, None);
            } else {
                Plugin::combine_stats(plugin, plugin_list, Some(COMPONENT_EXEC_TIME_IDX));
            }
        }
        cur_fuzzer = &mut self.state.fuzzers[0];
        cur_tab_name = "Overview"
    // Specific fuzzer selected
    } else {
        cur_fuzzer = &mut self.state.fuzzers[self.selected_tab - 1];
        selected_plugin_idx = cur_fuzzer.cur_plugin_idx;
        // Refresh fuzzer stats
        cur_fuzzer.refresh(false);
        // Refresh stats for selected plugin
        cur_fuzzer.refresh_plugin(selected_plugin_idx);
        cur_tab_name = cur_fuzzer.pretty_name.as_str();
    }

    let plugin_details_rect;

    // Render the top view (fuzzer stats and plugin list)
    {
        let mut max_fuzzer_val = 0;
        let mut fuzzer_titles = Vec::new();
        let mut fuzzer_vals = Vec::new();
        for s in cur_fuzzer.core.stats.iter_mut() {
            let (tag, val) = s.get_tuple();
            fuzzer_titles.push(Text::Raw(Cow::from(tag)));
            if val.len() > max_fuzzer_val {
                max_fuzzer_val = val.len();
            }
            fuzzer_vals.push(Text::Raw(Cow::from(val)));
        }

        // split total area into subsections
        let details_rect = area;
        let rects = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length((self.fuzzer_stats_heigth + 2) as u16),
                    Constraint::Percentage(100),
                ]
                .as_ref(),
            )
            .split(details_rect);
        let core_details_rect = rects[0];
        plugin_details_rect = rects[1];
        let rects = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Length((self.max_core_stat_title + 2) as u16),
                    Constraint::Length((max_fuzzer_val + 1) as u16),
                    Constraint::Length((self.max_plugin_name + 3) as u16),
                    Constraint::Percentage(100),
                ]
                .as_ref(),
            )
            .split(core_details_rect);
        let core_tag_list_rect = rects[0];
        let core_val_list_rect = rects[1];
        let plugins_list_rect = rects[2];
        let plugins_time_rect = rects[3];

        // Render fuzzer stat titles
        let core_tag_list = List::new(fuzzer_titles.drain(..)).block(
            Block::default()
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                .title(cur_tab_name),
        );
        f.render_widget(core_tag_list, core_tag_list_rect);
        // Render fuzzer stat values
        let core_val_list = List::new(fuzzer_vals.drain(..))
            .block(Block::default().borders(Borders::TOP | Borders::BOTTOM));
        f.render_widget(core_val_list, core_val_list_rect);

        // Render list of plugin names
        let mut plugin_names = Vec::with_capacity(cur_fuzzer.plugins.len());
        let mut plugin_times = Vec::with_capacity(cur_fuzzer.plugins.len());
        for plugin in cur_fuzzer.plugins.iter_mut() {
            plugin_names.push(Text::Raw(Cow::from(plugin.name.as_str())));
            plugin_times.push(Text::Raw(Cow::from(
                plugin.stats[COMPONENT_EXEC_TIME_IDX].val_as_str(),
            )));
        }
        let plugin_list = List::new(plugin_names.drain(..))
            .block(
                Block::default()
                    .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                    .title("Plugins"),
            )
            .highlight_symbol(">")
            .highlight_style(Style::default().fg(Color::Yellow).modifier(Modifier::BOLD));
        f.render_stateful_widget(plugin_list, plugins_list_rect, &mut self.plugins_list_state);

        // Render each average exec time for the plugin list
        let plugin_times = List::new(plugin_times.drain(..))
            .block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT))
            .highlight_style(Style::default().fg(Color::Yellow).modifier(Modifier::BOLD));
        f.render_stateful_widget(
            plugin_times,
            plugins_time_rect,
            &mut self.plugins_list_state,
        );
    }

    // Render the selected plugin details
    {
        let cur_plugin = &mut cur_fuzzer.plugins[selected_plugin_idx];

        let mut _max_plugin_val = 0;
        let mut plugin_titles = Vec::new();
        let mut plugin_vals = Vec::new();
        for s in cur_plugin.stats.iter_mut() {
            let (tag, val) = s.get_tuple();
            plugin_titles.push(Text::Raw(Cow::from(tag)));
            if val.len() > _max_plugin_val {
                _max_plugin_val = val.len();
            }
            plugin_vals.push(Text::Raw(Cow::from(val)));
        }

        // Split bottom area for currently selected plugin
        let rects = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(
                [
                    Constraint::Length((self.max_plugin_stat_title + 2) as u16),
                    Constraint::Percentage(100),
                ]
                .as_ref(),
            )
            .split(plugin_details_rect);
        let plugin_tag_list_rect = rects[0];
        let plugin_val_list_rect = rects[1];

        // Render selected plugin stat names
        let plugin_tag_list = List::new(plugin_titles.drain(..)).block(
            Block::default()
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                .title(cur_plugin.name.as_ref()),
        );
        f.render_widget(plugin_tag_list, plugin_tag_list_rect);
        // Render selected plugin stat values
        let plugin_val_list = List::new(plugin_vals.drain(..))
            .block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT));
        f.render_widget(plugin_val_list, plugin_val_list_rect);
    }
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


pub enum CachedStat {
    Num(u64),
    Str(String),
    Bytes(Vec<u8>),
}
impl CachedStat {
    pub fn from(val: &mut cflib::StatVal) -> Self {
        match val {
            cflib::StatVal::Num(v) => Self::Num(*v.val),
            cflib::StatVal::Str(v) => Self::Str(String::from(*v.get())),
            cflib::StatVal::Bytes(v) => Self::Bytes(Vec::from(*v.get())),
        }
    }
    pub fn set(&mut self, new_val: &mut cflib::StatVal) {
        use std::ops::Deref;
        match new_val {
            cflib::StatVal::Num(v) => match self {
                Self::Num(ref mut s) => *s = *v.val,
                _ => panic!("CachedStat::set() with mismatch StatVal"),
            },
            cflib::StatVal::Str(v) => {
                let val = v.get();
                match self {
                    Self::Str(ref mut s) => {
                        if s != *val {
                            s.clear();
                            s.push_str(*val);
                        }
                    }
                    _ => panic!("CachedStat::set() with mismatch StatVal"),
                }
            }
            cflib::StatVal::Bytes(v) => {
                let val = v.get();
                match self {
                    Self::Bytes(ref mut s) => {
                        if val.deref() != s {
                            s.clear();
                            s.extend_from_slice(*val);
                        }
                    }
                    _ => panic!("CachedStat::set() with mismatch StatVal"),
                }
            }
        }
    }
}