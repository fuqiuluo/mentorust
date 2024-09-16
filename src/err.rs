pub struct EapError {
    pub message: String,
}

impl EapError {
    pub fn new(message: &str) -> Self {
        Self {
            message: message.to_string()
        }
    }
}

impl std::fmt::Debug for EapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EapError: {}", self.message)
    }
}

impl From<std::io::Error> for EapError {
    fn from(e: std::io::Error) -> Self {
        Self {
            message: e.to_string()
        }
    }
}

impl From<pcap::Error> for EapError {
    fn from(value: pcap::Error) -> Self {
        Self {
            message: value.to_string()
        }
    }
}