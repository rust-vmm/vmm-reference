// Copyright 2020 Sartura All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;

/// A wrapper structure around that provides basic read functionality backed by
/// a named pipe implementation.
pub struct PipeReaderWrapper(File);

impl PipeReaderWrapper {
    pub fn new(buf: PathBuf) -> std::io::Result<PipeReaderWrapper> {
        match utils::mkfifo(&buf, libc::S_IRWXO) {
            Ok(_) => Ok(PipeReaderWrapper(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(&buf)?,
            )),
            Err(fifo_err) => match fifo_err {
                utils::FifoError::Io(error) => Err(error),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unknown error",
                )),
            },
        }
    }
}

impl Read for PipeReaderWrapper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl AsRawFd for PipeReaderWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// A wrapper structure around that provides basic write functionality backed by
/// a named pipe implementation.
pub struct PipeWriterWrapper(PathBuf);

impl PipeWriterWrapper {
    pub fn new(buf: PathBuf) -> std::io::Result<PipeWriterWrapper> {
        match utils::mkfifo(&buf, libc::S_IRWXO) {
            Ok(_) => Ok(PipeWriterWrapper(buf)),
            Err(fifo_err) => match fifo_err {
                utils::FifoError::Io(error) => Err(error),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "unknown error",
                )),
            },
        }
    }
}

impl Write for PipeWriterWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut pipe = match File::create(&self.0) {
            Err(err) => {
                println!("couldn't open pipe: {}", err);
                return Err(err);
            }
            Ok(input) => input,
        };
        pipe.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        //Flushing a pipe is meaningles
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::legacy::pipe::{PipeReaderWrapper, PipeWriterWrapper};
    use std::fs::{remove_file, File};
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};

    #[test]
    fn test_pipe_read() {
        let t = std::thread::spawn(move || {
            let write_buffer: [u8; 1] = [1];
            while !Path::new("test_in").exists() {}
            let mut output = match File::create("test_in") {
                Err(err) => panic!("couldn't open pipe: {}", err),
                Ok(input) => input,
            };
            let res = output.write(&write_buffer);
            assert!(res.is_ok());
            drop(output);
        });
        let mut read_buffer: [u8; 1] = [0];
        let input_pipe_path = PathBuf::from("test_in");
        let mut input = PipeReaderWrapper::new(input_pipe_path).unwrap();
        let res = input.read(&mut read_buffer);
        assert!(res.is_ok());
        assert_eq!(read_buffer[0], 1);
        drop(input);
        let res = remove_file("test_in");
        assert!(res.is_ok());
        t.join().unwrap();
    }
    #[test]
    fn test_pipe_write() {
        let t = std::thread::spawn(move || {
            let mut read_buffer: [u8; 1] = [0];
            while !Path::new("test_out").exists() {}
            let mut input = match File::open("test_out") {
                Err(err) => panic!("couldn't open pipe: {}", err),
                Ok(input) => input,
            };
            let res = input.read(&mut read_buffer);
            assert!(res.is_ok());
            assert_eq!(read_buffer[0], 1);
            drop(input);
            let res = remove_file("test_out");
            assert!(res.is_ok());
        });
        let write_buffer: [u8; 1] = [1];
        let output_pipe_path = PathBuf::from("test_out");
        let mut output = PipeWriterWrapper::new(output_pipe_path).unwrap();
        let res = output.write(&write_buffer);
        assert!(res.is_ok());
        drop(output);
        t.join().unwrap();
    }
}
