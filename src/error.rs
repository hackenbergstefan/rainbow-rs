// SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
//
// SPDX-License-Identifier: MIT

use std::{error::Error, fmt::Display};

use unicorn_engine::unicorn_const::uc_error;

#[derive(Debug)]
pub struct UcError(uc_error);

impl Display for UcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UcError: {:?}", self.0)
    }
}

impl Error for UcError {}

impl UcError {
    pub fn new(e: uc_error) -> Self {
        Self(e)
    }
}

#[derive(Debug)]
pub struct CapstoneError(capstone::Error);

impl Display for CapstoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CapstoneError: {:?}", self.0)
    }
}

impl Error for CapstoneError {}

impl CapstoneError {
    pub fn new(e: capstone::Error) -> Self {
        Self(e)
    }
}
