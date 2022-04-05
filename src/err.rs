#[derive(Clone)]
pub enum Err {
    IOError(String),
    NetworkError(String),
    ValueError(String),
    ScriptError(String),
    ConsensusError(String),
    ChannelError,
}

pub type Result<T> = std::result::Result<T, Err>;

impl std::fmt::Debug for Err {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for Err {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Err::IOError(message) => write!(f, "{}", message),
            Err::NetworkError(message) => write!(f, "{}", message),
            Err::ValueError(message) => write!(f, "{}", message),
            Err::ScriptError(message) => write!(f, "{}", message),
            Err::ConsensusError(message) => write!(f, "{}", message),
            Err::ChannelError => write!(f, "channel closed unexpectedly"),
        }
    }
}