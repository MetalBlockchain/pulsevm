use spdlog::prelude::*;

/// Log level choices exposed via the CLI `--log-level` flag.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Critical,
    Off,
}

impl LogLevel {
    /// Map our CLI enum to the spdlog `LevelFilter`.
    fn to_spdlog_filter(self) -> spdlog::LevelFilter {
        match self {
            LogLevel::Trace    => LevelFilter::All,
            LogLevel::Debug    => LevelFilter::MoreSevereEqual(Level::Debug),
            LogLevel::Info     => LevelFilter::MoreSevereEqual(Level::Info),
            LogLevel::Warn     => LevelFilter::MoreSevereEqual(Level::Warn),
            LogLevel::Error    => LevelFilter::MoreSevereEqual(Level::Error),
            LogLevel::Critical => LevelFilter::MoreSevereEqual(Level::Critical),
            LogLevel::Off      => LevelFilter::Off,
        }
    }
}

/// Initialise the spdlog-rs default logger with the requested verbosity.
///
/// Call this once, early in `main`, before any log macros are used.
pub fn init(level: LogLevel) {
    let filter = level.to_spdlog_filter();

    // Configure the global default logger.
    spdlog::default_logger().set_level_filter(filter);

    trace!("logging initialised at level {:?} (filter={:?})", level, filter);
}
