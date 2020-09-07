// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

pub(crate) mod mpspec;
pub(crate) mod mptable;

/// Errors encountered during vCPU operation.
#[derive(Debug)]
pub enum Error {
    /// Failed to configure mptables.
    Mptable(mptable::Error),
}
