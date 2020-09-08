# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run the reference VMM."""

import os, signal, subprocess, time
import pytest


def test_reference_vmm():
    """Start the reference VMM and trust that it works."""

    # Memory config
    mem_size_mib = 1024

    # Kernel config
    cmdline = "console=ttyS0 i8042.nokbd reboot=k panic=1 pci=off"
    kernel_path = os.path.abspath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "resources/kernel/vmlinux-hello-busybox"
    ))
    himem_start = 1048576

    # vCPU config
    num_vcpus = 1

    vmm_cmd = [
        "cargo", "run", "--",
        "--memory", "mem_size_mib={}".format(mem_size_mib),
        "--kernel", "cmdline=\"{}\",path={},himem_start={}".format(
            cmdline, kernel_path, himem_start
        ),
        "--vcpus", "num_vcpus={}".format(num_vcpus)
    ]
    
    # We can't talk to the reference VMM yet, and it can't talk back.
    # If we try to capture the output, Python doesn't return control to the
    # test until the child process ends, which it doesn't. So we have to trust
    # that the output is there, let the VMM run for a bit, then kill it.
    # In the future, it will communicate via metrics / devices.
    vmm_process = subprocess.Popen(vmm_cmd)
    vmm_pid = vmm_process.pid

    time.sleep(3)

    os.kill(vmm_pid, signal.SIGHUP)
