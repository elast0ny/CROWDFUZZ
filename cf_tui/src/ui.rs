use ::crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ::sysinfo::{ProcessorExt, SystemExt};
use ::tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
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
    pub cur_fuzz_idx: usize,
    pub tab_header: String,
    pub footer: Vec<String>,
    pub footer_cpu_idx: usize,
    pub footer_mem_idx: usize,
}

impl UiState {
    pub fn new() -> Self {
        let mut footer = Vec::new();
        footer.push("Load [Cpu ".to_owned());
        let footer_cpu_idx = footer.len();
        footer.push("000%".to_owned());
        footer.push(", Mem ".to_owned());
        let footer_mem_idx = footer.len();
        footer.push("000%".to_owned());
        footer.push("]".to_owned());

        let mut state = Self {
            cur_fuzz_idx: 0,
            tab_header: String::with_capacity(12),
            footer,
            footer_cpu_idx,
            footer_mem_idx 
        };

        state.update_tab_header(0);
        state
    }

    pub fn update_tab_header(&mut self, num_fuzzers: usize) {
        use std::fmt::Write;
        self.tab_header.clear();
        let _ = write!(&mut self.tab_header, "Fuzzers({})", num_fuzzers);
    }

    pub fn update_footer(&mut self, cpu_load: usize, mem_load: usize) {
        use std::fmt::Write;
        let cpu_str = &mut self.footer[self.footer_cpu_idx];
        cpu_str.clear();
        let _ = write!(cpu_str, "{:02}%", cpu_load);

        let mem_str = &mut self.footer[self.footer_mem_idx];
        mem_str.clear();
        let _ = write!(mem_str, "{:02}%", mem_load);
    } 
}

pub fn init_ui() -> Result<Terminal<CrosstermBackend<Stdout>>, Box<dyn Error>> {
    // Setup the UI
    enable_raw_mode()?;
    let mut stdout = stdout();
    #[allow(deprecated)]
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;
    Ok(terminal)
}

pub fn destroy_ui() -> Result<(), Box<dyn Error>> {
    #[allow(deprecated)]
    execute!(stdout(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}

pub fn draw<B: Backend>(mut f: Frame<B>, state: &mut State) {
    let size = f.size();
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

    // Fuzzer tabs
    let tab_rect = rects[0];
    let fuzzer_tab_titles = std::iter::once("All")
        .chain(state.fuzzers.iter().map(|f| f.core.name))
        .collect::<Vec<&str>>();
    let mut fuzzer_tabs = Tabs::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(&state.ui.tab_header),
        )
        .highlight_style(Style::default().fg(Color::Yellow))
        .titles(&fuzzer_tab_titles)
        .select(state.ui.cur_fuzz_idx);
    f.render(&mut fuzzer_tabs, tab_rect);

    if state.ui.cur_fuzz_idx == 0 {
        draw_all(&mut f, state, rects[1]);
    } else {
        draw_fuzzer(&mut f, state, rects[1]);
    }

    draw_footer(&mut f, state, rects[2]);
}

pub fn draw_footer<B: Backend>(f: &mut Frame<B>, state: &mut State, area: Rect) {
    
    state.sys_info.refresh_cpu();
    state.sys_info.refresh_memory();
    let cpu_speed = state
        .sys_info
        .get_processors()
        .iter()
        .fold(0f32, |t, c| t + c.get_cpu_usage()) as usize
        / state.sys_info.get_processors().len();
    let mem_usage = ((state.sys_info.get_used_memory() * 100) / state.sys_info.get_total_memory()) as usize;
    state.ui.update_footer(cpu_speed, mem_usage);

    // Apply color to cpu and mem
    let footer = state.ui.footer.iter().enumerate().map(|(idx, s)| {
        if idx == state.ui.footer_cpu_idx {
            Text::styled(s, 
            if cpu_speed > 90 {
                Style::default().fg(Color::Red)
            } else if cpu_speed > 75 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            })
        } else if idx == state.ui.footer_mem_idx {
            Text::styled(s, 
            if mem_usage > 90 {
                Style::default().fg(Color::Red)
            } else if mem_usage > 75 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            })
        } else {
            Text::raw(s)
        }
    }).collect::<Vec<Text>>();

    let mut bottom_stats = Paragraph::new(footer.iter())
        //.style(Style::default())
        //.alignment(Alignment::Center)
        .wrap(false);

    f.render(&mut bottom_stats, area);
}

/// Draws the view for total stats for the current fuzzers
pub fn draw_all<B: Backend>(f: &mut Frame<B>, _state: &mut State, area: Rect) {
    let mut fuzzer_details = Block::default().borders(Borders::ALL).title("None");
    f.render(&mut fuzzer_details, area);
}

/// Draws the view when a fuzzer is selected
pub fn draw_fuzzer<B: Backend>(f: &mut Frame<B>, state: &mut State, area: Rect) {
    let cur_fuzzer = &mut state.fuzzers[state.ui.cur_fuzz_idx - 1];
    let core_title = format!("{}({})", cur_fuzzer.core.name, cur_fuzzer.pid);

    // Fuzzer details
    let mut max_details = cur_fuzzer.core.stats.len();
    if max_details < cur_fuzzer.plugins.len() {
        max_details = cur_fuzzer.plugins.len();
    }
    max_details += 2;

    // Load up current stats in string repr
    cur_fuzzer.core.refresh_stat_vals();
    cur_fuzzer.core.stats[0].update_pretty_str_repr();
    for (idx, plugin) in cur_fuzzer.plugins.iter_mut().enumerate() {
        plugin.stats[0].update_pretty_str_repr();
        if idx == cur_fuzzer.cur_plugin_idx {
            plugin.refresh_stat_vals()
        }
    }

    let details_rect = area;
    let rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(max_details as u16),
                Constraint::Percentage(100),
            ]
            .as_ref(),
        )
        .split(details_rect);
    let core_details_rect = rects[0];
    let plugin_details_rect = rects[1];
    let rects = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Length(cur_fuzzer.core.max_tag_len + 2),
                Constraint::Length(cur_fuzzer.core.max_val_len + 2),
                Constraint::Length(cur_fuzzer.max_plugin_name_len + 2),
                Constraint::Percentage(100),
            ]
            .as_ref(),
        )
        .split(core_details_rect);
    let core_tag_list_rect = rects[0];
    let core_val_list_rect = rects[1];
    let plugins_list_rect = rects[2];
    let plugins_time_rect = rects[3];

    // Fuzzer core stat tags
    let mut core_tag_list = List::new(
        cur_fuzzer
            .core
            .stats
            .iter()
            .map(|s| Text::Raw(Cow::from(s.get_tag()))),
    )
    .block(
        Block::default()
            .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
            .title(&core_title),
    );
    f.render(&mut core_tag_list, core_tag_list_rect);
    // Fuzzer core stat values
    let mut core_val_list = List::new(
        cur_fuzzer
            .core
            .stats
            .iter()
            .map(|s| Text::Raw(Cow::from(s.as_str()))),
    )
    .block(Block::default().borders(Borders::TOP | Borders::BOTTOM));
    f.render(&mut core_val_list, core_val_list_rect);
    // Fuzzer core plugin list
    let mut plugin_names: Vec<&str> = Vec::with_capacity(cur_fuzzer.plugins.len());
    let mut plugin_times: Vec<&str> = Vec::with_capacity(cur_fuzzer.plugins.len());
    for plugin in cur_fuzzer.plugins.iter() {
        plugin_names.push(plugin.name);
        plugin_times.push(plugin.stats[0].as_str());
    }
    let mut plugin_list = SelectableList::default()
        .block(
            Block::default()
                .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
                .title("Plugins"),
        )
        .items(&plugin_names)
        .select(Some(cur_fuzzer.cur_plugin_idx))
        .highlight_style(Style::default().fg(Color::Yellow).modifier(Modifier::BOLD));
    f.render(&mut plugin_list, plugins_list_rect);
    let mut plugin_times = SelectableList::default()
        .block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT))
        .items(&plugin_times)
        .select(Some(cur_fuzzer.cur_plugin_idx))
        .highlight_style(Style::default().fg(Color::Yellow).modifier(Modifier::BOLD));
    f.render(&mut plugin_times, plugins_time_rect);

    let cur_plugin = &mut cur_fuzzer.plugins[cur_fuzzer.cur_plugin_idx];
    // Current selected plugin stats
    let rects = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Length(cur_plugin.max_tag_len + 2),
                Constraint::Percentage(100),
            ]
            .as_ref(),
        )
        .split(plugin_details_rect);
    let plugin_tag_list_rect = rects[0];
    let plugin_val_list_rect = rects[1];

    // Plugins stat tags
    let mut plugin_tag_list = List::new(
        cur_plugin
            .stats
            .iter()
            .map(|s| Text::Raw(Cow::from(s.get_tag()))),
    )
    .block(
        Block::default()
            .borders(Borders::TOP | Borders::BOTTOM | Borders::LEFT)
            .title(cur_plugin.name),
    );
    f.render(&mut plugin_tag_list, plugin_tag_list_rect);

    // Plugins stat values
    let mut plugin_val_list = List::new(
        cur_plugin
            .stats
            .iter()
            .map(|s| Text::Raw(Cow::from(s.as_str()))),
    )
    .block(Block::default().borders(Borders::TOP | Borders::BOTTOM | Borders::RIGHT));
    f.render(&mut plugin_val_list, plugin_val_list_rect);
}
