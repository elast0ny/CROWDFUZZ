use std::io::Write;

/// This function sets the log level for env_logger.
/// It will set it to at least minimum_level and can be bumped up
/// with verbose_level or RUST_LOG env var. (Whichever one is higher)
pub fn set_log_level(verbose_level: &usize, minimum_level: &str) -> String {
    let level_order: [&'static str; 5] = ["error", "warn", "info", "debug", "trace"];
    let default_log_level: String = match std::env::var("RUST_LOG") {
        Ok(v) => v,
        Err(_e) => String::from(level_order[0]),
    };

    let mut cur_level: usize = 0;
    let mut wanted_level: usize = 0;

    for (i, &level_str) in level_order.iter().enumerate() {
        if level_str == default_log_level {
            cur_level = i;
        }

        if level_str == minimum_level {
            wanted_level = i + verbose_level;
            if wanted_level >= level_order.len() {
                wanted_level = level_order.len() - 1;
            }
        }
    }

    if wanted_level > cur_level {
        std::env::set_var("RUST_LOG", level_order[wanted_level]);
        return String::from(level_order[wanted_level]);
    }

    default_log_level
}

/// Custom logging format
pub fn log_format(
    buf: &mut env_logger::fmt::Formatter,
    record: &log::Record,
) -> std::io::Result<()> {
    let mut level_style = buf.style();
    let prefix: &'static str;
    match record.level() {
        log::Level::Error => {
            level_style.set_color(env_logger::fmt::Color::Red);
            prefix = "[X]";
        }
        log::Level::Warn => {
            level_style.set_color(env_logger::fmt::Color::Yellow);
            prefix = "[!]";
        }
        log::Level::Info => {
            level_style.set_color(env_logger::fmt::Color::Green);
            prefix = "[*]";
        }
        log::Level::Debug => {
            level_style.set_color(env_logger::fmt::Color::Blue);
            prefix = "[?]";
        }
        log::Level::Trace => {
            level_style.set_color(env_logger::fmt::Color::Magenta);
            prefix = "[.]";
        }
    };
    writeln!(buf, "{} {}", level_style.value(prefix), record.args())
}
