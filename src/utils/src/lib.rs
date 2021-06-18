// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
#[macro_use]
extern crate enum_display_derive;

use std::ffi::CString;
use std::fmt::Display;
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
#[derive(Display)]
pub enum Error {
    Io(io::Error),
    Path,
}

/// A safe wrapper around libc::mkfifo().
pub fn mkfifo<P: AsRef<Path>>(fifo_path: P, mode: u32) -> result::Result<(), Error> {
    let fifo_path_str = fifo_path.as_ref().to_str().ok_or(Error::Path)?;
    let fifo_path_cstr = CString::new(fifo_path_str).unwrap();

    let ret = unsafe { libc::mkfifo(fifo_path_cstr.as_ptr(), mode) };

    if ret != 0 {
        Err(Error::Io(io::Error::last_os_error()))
    } else {
        Ok(())
    }
}
