# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Run the reference VMM and shut it down through a command on the serial."""

import os, signal, subprocess, time
import pytest
from subprocess import PIPE, STDOUT


def process_exists(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


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

    build_cmd = "cargo build --release"
    subprocess.run(build_cmd, shell=True, check=True)
    vmm_cmd = [
        "target/release/vmm-reference",
        "--memory", "mem_size_mib={}".format(mem_size_mib),
        "--kernel", "cmdline=\"{}\",path={},himem_start={}".format(
            cmdline, kernel_path, himem_start
        ),
        "--vcpus", "num_vcpus={}".format(num_vcpus)
    ]
    vmm_process = subprocess.Popen(vmm_cmd, stdout=PIPE, stdin=PIPE)

    # Let's quickly check if the process died (i.e. because of invalid vmm
    # configuration). We need to wait here because otherwise the returncode
    # will be None even if the `vmm_process` died.
    try:
        vmm_process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        # The process is still alive.
        pass
    assert(process_exists(vmm_process.pid))

    # Poll process for new output until we find the hello world message.
    # If we do not find the expected message, this loop will not break and the
    # test will fail when the timeout expires.
    expected_string = "Hello, world, from the rust-vmm reference VMM!"
    while True:
        nextline = vmm_process.stdout.readline()
        if expected_string in nextline.decode():
            break

    vmm_process.stdin.write(b'reboot -f\n')
    vmm_process.stdin.flush()

    # If the process hasn't ended within 3 seconds, this will raise a
    # TimeoutExpired exception and fail the test.
    vmm_process.wait(timeout=3)
