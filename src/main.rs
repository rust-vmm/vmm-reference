// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

extern crate cli;
extern crate vmm;

use std::convert::TryFrom;

use cli::CLI;
use vmm::VMM;

fn main() {
    let vmm_config =
        CLI::launch("reference-vmm".to_string()).expect("Failed to parse command line options");
    let mut vmm = VMM::try_from(vmm_config).expect("Failed to create VMM from configurations");
    vmm.run();
}
