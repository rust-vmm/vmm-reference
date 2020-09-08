// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

extern crate libc;
extern crate vmm;

use std::convert::TryFrom;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use libc::{_exit, fork, waitpid, WEXITSTATUS, WIFEXITED};

use vmm::{KernelConfig, MemoryConfig, VMMConfig, VcpuConfig, VMM};

mod test_utils;
use test_utils::*;

fn default_memory_config() -> MemoryConfig {
    MemoryConfig { mem_size_mib: 1024 }
}

fn default_kernel_config() -> KernelConfig {
    let kernel_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../resources/kernel/vmlinux-hello-busybox-halt");
    // Sanity check. Because the VMM runs in a separate process, if the file doesn't exist,
    // all we see is a different exit code than 0.
    assert!(kernel_path.as_path().exists());
    KernelConfig {
        path: kernel_path,
        himem_start: 0x0010_0000, // 1 MB
        cmdline: "console=ttyS0 i8042.nokbd reboot=k panic=1 pci=off".to_string(),
    }
}

fn default_vcpu_config() -> VcpuConfig {
    VcpuConfig { num_vcpus: 1 }
}

fn wait_vmm_child_process(vmm_pid: i32) {
    // Parent process: wait for the vmm to exit.
    let mut vmm_status: i32 = -1;
    let pid_done = unsafe { waitpid(vmm_pid, &mut vmm_status, 0) };
    assert_eq!(pid_done, vmm_pid);
    restore_stdin();
    assert!(WIFEXITED(vmm_status));
    assert_eq!(WEXITSTATUS(vmm_status), 0);
}

#[test]
fn test_dummy_vmm() {
    let pid = unsafe { fork() };
    let vmm_config = VMMConfig {
        kernel_config: default_kernel_config(),
        memory_config: default_memory_config(),
        vcpu_config: default_vcpu_config(),
    };
    match pid {
        0 => {
            set_panic_hook();
            match VMM::try_from(vmm_config) {
                Ok(mut vmm) => {
                    vmm.run();
                    // Shouldn't get here with this guest image. It will loop forever.
                    unsafe { _exit(-1) };
                }
                _ => unsafe { _exit(1) },
            }
        }
        vmm_pid => {
            // Parent process: give the VMM some time, then check the exit code.
            // It should terminate and return 0.
            sleep(Duration::from_secs(5));
            wait_vmm_child_process(vmm_pid);
        }
    }
}
