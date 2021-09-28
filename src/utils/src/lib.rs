// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::ffi::CString;
use std::path::Path;
use std::{io, result};

pub mod resource_download;

// -----------------------------------------------------------------------------
/// A macro for printing errors only in debug mode.
#[macro_export]
#[cfg(debug_assertions)]
macro_rules! debug {
    ($( $args:expr ),*) => { eprintln!( $( $args ),* ); }
}

/// A macro that allows printing to be ignored in release mode.
#[macro_export]
#[cfg(not(debug_assertions))]
macro_rules! debug {
    ($( $args:expr ),*) => {
        ()
    };
}

// -----------------------------------------------------------------------------
/// Enum containing error types.
pub enum FifoError {
    Io(io::Error),
    Path,
}

impl std::fmt::Display for FifoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Erorr: {}", (*self))
    }
}

/// A safe wrapper around libc::mkfifo().
pub fn mkfifo<P: AsRef<Path>>(fifo_path: P, mode: u32) -> result::Result<(), FifoError> {
    let fifo_path_str = fifo_path.as_ref().to_str().ok_or(FifoError::Path)?;
    match CString::new(fifo_path_str) {
        Ok(fifo_path_cstr) => {
            // fifo_path_cstr was checked to be valid and the return of the unsafe code was checked
            let ret = unsafe { libc::mkfifo(fifo_path_cstr.as_ptr(), mode) };
            if ret != 0 {
                Err(FifoError::Io(io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
        Err(_) => Err(FifoError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "pipe name cannot contain null-bytes",
        ))),
    }
}
