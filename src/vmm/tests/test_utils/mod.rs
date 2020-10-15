// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::io;
use std::panic;
use std::thread::sleep;
use std::time::Duration;

use libc::{_exit, waitpid, WEXITSTATUS, WIFEXITED};

use vmm::{VMMConfig, VMM};
use vmm_sys_util::terminal::Terminal;

const VMM_ERR_EXIT: i32 = -1;

pub fn restore_stdin() {
    let stdin = io::stdin();
    stdin.lock().set_canon_mode().unwrap();
}

pub fn set_panic_hook() {
    panic::set_hook(Box::new(move |_| {
        restore_stdin();
        unsafe {
            libc::exit(VMM_ERR_EXIT);
        }
    }));
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

pub fn run_vmm(pid: i32, vmm_config: VMMConfig) {
    match pid {
        0 => {
            set_panic_hook();
            match VMM::try_from(vmm_config) {
                Ok(mut vmm) => {
                    vmm.run();
                    // Shouldn't get here with this guest image.
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
