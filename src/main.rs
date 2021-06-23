// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#[cfg(target_arch = "x86_64")]
mod main {
    use std::convert::TryFrom;
    use std::env;

    use api::CLI;
    use vmm::VMM;

    use anyhow::Context;

    pub type Result<T> = anyhow::Result<T>;

    pub fn run() -> Result<()> {
        let vmm_config = CLI::launch(
            env::args()
                .collect::<Vec<String>>()
                .iter()
                .map(|s| s.as_str())
                .collect(),
        )
        .context("Failed to parse CLI options")?;

        let mut vmm =
            VMM::try_from(vmm_config).context("Failed to create VMM from configurations")?;

        vmm.run().context("failed to run VMM")
    }
}

#[cfg(target_arch = "aarch64")]
mod main {
    pub type Result<T> = std::result::Result<T, String>;
    pub fn run() -> Result<()> {
        println!("Reference VMM under construction!");
        Ok(())
    }
}

fn main() -> main::Result<()> {
    main::run()
}
