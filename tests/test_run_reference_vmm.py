# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Run the reference VMM and shut it down through a command on the serial."""

import os, signal, subprocess, time
import pytest
from subprocess import PIPE, STDOUT


KERNELS_INITRAMFS = ["vmlinux-hello-busybox", "bzimage-hello-busybox"]

"""
Temporarily removed the ("bzimage-focal", "rootfs.ext4") pair from the 
list below, because the init startup sequence in the guest takes too
long until getting to the cmdline prompt for some reason.
"""
KERNELS_DISK = [
    ("vmlinux-focal", "rootfs.ext4"),
]


def process_exists(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def resource_path(resource_type, resource_name):
    return os.path.abspath(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "resources/{}/{}".format(resource_type, resource_name)
    ))

"""
The following methods would be nice to have a part of class revolving
around the vmm process. Let's figure out how to proceed here as part
of the discussion around making the CI/testing easier to use, extend,
and run locally. 
"""

def start_vmm_process(kernel, disk):
    # Memory config
    mem_size_mib = 1024

    # Kernel config
    cmdline = "console=ttyS0 i8042.nokbd reboot=t panic=1 pci=off"
    kernel_path = resource_path("kernel", kernel)

    himem_start = 1048576

    # vCPU config
    num_vcpus = 1

    build_cmd = "cargo build --release"
    subprocess.run(build_cmd, shell=True, check=True)

    vmm_cmd = [
        "target/release/vmm-reference",
        "--memory", "size_mib={}".format(mem_size_mib),
        "--kernel", "cmdline=\"{}\",path={},himem_start={}".format(
            cmdline, kernel_path, himem_start
        ),
        "--vcpu", "num={}".format(num_vcpus)
    ]

    if disk is not None:
        disk_path = resource_path("disk", disk)
        vmm_cmd.append("--block")
        vmm_cmd.append("path={}".format(disk_path))

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

    return vmm_process


def shutdown(vmm_process):
    vmm_process.stdin.write(b'reboot -f\n')
    vmm_process.stdin.flush()

    # If the process hasn't ended within 3 seconds, this will raise a
    # TimeoutExpired exception and fail the test.
    vmm_process.wait(timeout=3)

def expect_string(vmm_process, expected_string):
    while True:
        nextline = vmm_process.stdout.readline()
        if expected_string in nextline.decode():
            break


@pytest.mark.parametrize("kernel", KERNELS_INITRAMFS)
def test_reference_vmm(kernel):
    """Start the reference VMM and verify that it works."""

    vmm_process = start_vmm_process(kernel, None)

    # Poll process for new output until we find the hello world message.
    # If we do not find the expected message, this loop will not break and the
    # test will fail when the timeout expires.
    expected_string = "Hello, world, from the rust-vmm reference VMM!"
    expect_string(vmm_process, expected_string)

    shutdown(vmm_process)


@pytest.mark.parametrize("kernel,disk", KERNELS_DISK)
def test_reference_vmm_with_disk(kernel, disk):
    """Start the reference VMM with a block device and verify that it works."""

    vmm_process = start_vmm_process(kernel, disk)

    expect_string(vmm_process, "Ubuntu 20.04 LTS ubuntu-rust-vmm ttyS0")

    shutdown(vmm_process)
