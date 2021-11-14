// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2019 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use log::LevelFilter;

use std::sync::Mutex;

pub(crate) struct Logger {
    output: Mutex<Box<dyn std::io::Write + Send>>,
    start: std::time::Instant,
}

impl Logger {
    pub(crate) fn init() {
        // Default to Debug.
        // TODO: Accept a command line argument to set the log level.
        let log_level = LevelFilter::Debug;

        let log_file: Box<dyn std::io::Write + Send> = Box::new(std::io::stderr());

        match log::set_boxed_logger(Box::new(Logger {
            output: Mutex::new(log_file),
            start: std::time::Instant::now(),
        })) {
            Ok(_) => log::set_max_level(log_level),
            Err(e) => eprintln!("Failed to initialize logger: {}.", e),
        }
    }
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        // Enabled for all log levels.
        // Control filtering by calling `set_max_level`.
        true
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let now = std::time::Instant::now();
        let duration = now.duration_since(self.start);

        if record.file().is_some() && record.line().is_some() {
            writeln!(
                *(*(self.output.lock().unwrap())),
                "vmm-reference: {:?}: <{}> {}:{}:{} -- {}",
                duration,
                std::thread::current().name().unwrap_or("anonymous"),
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            )
        } else {
            writeln!(
                *(*(self.output.lock().unwrap())),
                "vmm-reference: {:?}: <{}> {}:{} -- {}",
                duration,
                std::thread::current().name().unwrap_or("anonymous"),
                record.level(),
                record.target(),
                record.args()
            )
        }
        .ok();
    }

    fn flush(&self) {}
}
