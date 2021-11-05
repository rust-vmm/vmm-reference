// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![cfg(target_arch = "x86_64")]
/// Abstractions for a basic filtering of `CPUID`.
pub mod cpuid;
/// Abstractions for building a Global Descriptor Table (GDT).
pub mod gdt;
pub mod mpspec;
pub mod mptable;
