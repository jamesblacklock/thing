pub const TRACE: u32 = 4;
pub const DEBUG: u32 = 3;
pub const INFO: u32 = 2;
pub const WARN: u32 = 1;
pub const ERROR: u32 = 0;

pub fn log_level() -> u32 {
    match std::env::var("LOG_LEVEL").unwrap_or("INFO".to_owned()).as_str() {
        "TRACE" => TRACE,
        "DEBUG" => DEBUG,
        "INFO"  => INFO,
        "WARN"  => WARN,
        _ => ERROR,
    }
}

#[macro_export]
macro_rules! log {
    ( $level:expr, $( $x:expr ),* ) => {
        {
            if crate::log::log_level() >= $level  {
                println!($($x,)*)
            }
        }
    };
}

#[macro_export] macro_rules! log_trace { ( $( $x:expr ),* ) => {{log!(crate::log::TRACE $(,$x)*)}}; }
#[macro_export] macro_rules! log_debug { ( $( $x:expr ),* ) => {{log!(crate::log::DEBUG $(,$x)*)}}; }
#[macro_export] macro_rules! log_info  { ( $( $x:expr ),* ) => {{log!(crate::log::INFO  $(,$x)*)}}; }
#[macro_export] macro_rules! log_warn  { ( $( $x:expr ),* ) => {{log!(crate::log::WARN $(,$x)*)}}; }
#[macro_export] macro_rules! log_error { ( $( $x:expr ),* ) => {{log!(crate::log::ERROR $(,$x)*)}}; }