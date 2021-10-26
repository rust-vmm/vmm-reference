// Copyright 2020 Sartura All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use crate::legacy::pipe::{PipeReaderWrapper, PipeWriterWrapper};
use std::io::{stdin, stdout, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;

use utils::debug;

/// A generic type used for wrapping the guest input implementation
/// (stdin, named pipe, unix socket etc.)
pub struct ConsoleReaderWrapper {
    reader: Option<PipeReaderWrapper>,
}

impl ConsoleReaderWrapper {
    pub fn new(buf: Option<PathBuf>) -> ConsoleReaderWrapper {
        match buf {
            None => ConsoleReaderWrapper { reader: None },
            Some(x) => ConsoleReaderWrapper {
                reader: match PipeReaderWrapper::new(x) {
                    Ok(p) => Some(p),
                    Err(_err) => {
                        debug!("ConsoleReaderWrapper failed with error {} to create a pipe reader, defaulting to stdin!", _err);
                        None
                    }
                },
            },
        }
    }
}

impl Read for ConsoleReaderWrapper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.reader.as_mut() {
            None => stdin().read(buf),
            Some(x) => x.read(buf),
        }
    }
}

impl AsRawFd for ConsoleReaderWrapper {
    fn as_raw_fd(&self) -> RawFd {
        match &self.reader {
            None => stdin().as_raw_fd(),
            Some(x) => x.as_raw_fd(),
        }
    }
}

/// A generic type used for wrapping the guest output implementation
/// (stdout, named pipe, unix socket etc.)
pub struct ConsoleWriterWrapper {
    writer: Box<dyn Write + Send>,
}

impl ConsoleWriterWrapper {
    pub fn new(buf: Option<PathBuf>) -> ConsoleWriterWrapper {
        let writer_obj: Box<dyn Write + Send> = match buf {
            None => Box::new(stdout()),
            Some(x) => match PipeWriterWrapper::new(x) {
                Ok(p) => Box::new(p),
                Err(_err) => {
                    debug!("ConsoleWriterWrapper failed with error {} to create a pipe writer, defaulting to stdout!", _err);
                    Box::new(stdout())
                }
            },
        };
        ConsoleWriterWrapper { writer: writer_obj }
    }
}

impl Write for ConsoleWriterWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
