// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
#[cfg(target_arch = "x86_64")]
use std::convert::TryFrom;
#[cfg(target_arch = "x86_64")]
use std::env;

use simple_logger::SimpleLogger;
use log::{LevelFilter, error};

#[cfg(target_arch = "x86_64")]
use api::CLI;
#[cfg(target_arch = "x86_64")]
use vmm::VMM;

fn main() {
    if cfg!(debug_assertions) {
        SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
    } else {
        SimpleLogger::new().with_level(LevelFilter::Info).init().unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    {
        match CLI::launch(
            env::args()
                .collect::<Vec<String>>()
                .iter()
                .map(|s| s.as_str())
                .collect(),
        ) {
            Ok(vmm_config) => {
                let mut vmm =
                    VMM::try_from(vmm_config).expect("Failed to create VMM from configurations");
                // For now we are just unwrapping here, in the future we might use a nicer way of
                // handling errors such as pretty printing them.
                vmm.run().unwrap();
            }
            Err(e) => {
                error!("Failed to parse command line options. {}", e);
            }
        }
    }
    #[cfg(target_arch = "aarch64")]
    error!("Reference VMM under construction!")
}
