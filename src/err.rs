pub enum Err {
    NetworkError(String),
}

pub type Result<T> = std::result::Result<T, Err>;

impl std::fmt::Debug for Err {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Err::NetworkError(message) => write!(f, "{}", message),
        }
    }
}

impl std::fmt::Display for Err {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Err::NetworkError(message) => write!(f, "{}", message),
        }
    }
}