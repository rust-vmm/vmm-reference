// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

extern crate cli;
extern crate vmm;

use std::convert::TryFrom;
use std::env;

use cli::CLI;
use vmm::VMM;

fn main() {
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
            vmm.run();
        }
        Err(e) => {
            eprintln!("Failed to parse command line options. {}", e);
        }
    }
}
