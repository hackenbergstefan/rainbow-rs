use std::{error::Error, fmt};

use unicorn_engine::unicorn_const::uc_error;

#[derive(Debug)]
pub enum TraceEmulatorError {
    UcErr(uc_error),
    ElfParseError(elf::ParseError),
    IoError(std::io::Error),
    OtherError,
}

impl fmt::Display for TraceEmulatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<uc_error> for TraceEmulatorError {
    fn from(e: uc_error) -> Self {
        Self::UcErr(e)
    }
}
impl From<elf::ParseError> for TraceEmulatorError {
    fn from(e: elf::ParseError) -> Self {
        Self::ElfParseError(e)
    }
}

impl From<std::io::Error> for TraceEmulatorError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl Error for TraceEmulatorError {}
