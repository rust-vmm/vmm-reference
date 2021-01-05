# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Run the reference VMM and shut it down through a command on the serial."""

import os, signal, subprocess, time
import pytest
from subprocess import PIPE, STDOUT
import tempfile


KERNELS_INITRAMFS = [
    "/tmp/vmlinux_busybox/linux-4.14.176/vmlinux-hello-busybox",
    "/tmp/vmlinux_busybox/linux-4.14.176/bzimage-hello-busybox"
]

"""
Temporarily removed the ("bzimage-focal", "rootfs.ext4") pair from the 
list below, because the init startup sequence in the guest takes too
long until getting to the cmdline prompt for some reason.
"""
KERNELS_DISK = [
    ("/tmp/ubuntu-focal/linux-5.4.81/vmlinux-focal",
     "/tmp/ubuntu-focal-disk/rootfs.ext4"),
]


def process_exists(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


"""
The following methods would be nice to have a part of class revolving
around the vmm process. Let's figure out how to proceed here as part
of the discussion around making the CI/testing easier to use, extend,
and run locally. 
"""


def start_vmm_process(kernel_path, disk_path):
    # Memory config
    mem_size_mib = 1024

    # Kernel config
    cmdline = "console=ttyS0 i8042.nokbd reboot=t panic=1 pci=off"

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
    tmp_file_path = None

    if disk_path is not None:
        # Terrible hack to have a rootfs owned by the user.
        with tempfile.NamedTemporaryFile(dir='/tmp', delete=True) as tmpfile:
            tmp_file_path = tmpfile.name
        cp_cmd = "cp {} {}".format(disk_path, tmp_file_path)
        subprocess.run(cp_cmd, shell=True, check=True)
        vmm_cmd.append("--block")
        vmm_cmd.append("path={}".format(tmp_file_path))

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

    return vmm_process, tmp_file_path


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

    vmm_process, _ = start_vmm_process(kernel, None)

    # Poll process for new output until we find the hello world message.
    # If we do not find the expected message, this loop will not break and the
    # test will fail when the timeout expires.
    expected_string = "Hello, world, from the rust-vmm reference VMM!"
    expect_string(vmm_process, expected_string)

    shutdown(vmm_process)


@pytest.mark.parametrize("kernel,disk", KERNELS_DISK)
def test_reference_vmm_with_disk(kernel, disk):
    """Start the reference VMM with a block device and verify that it works."""

    vmm_process, tmp_disk_path = start_vmm_process(kernel, disk)

    expect_string(vmm_process, "Ubuntu 20.04 LTS ubuntu-rust-vmm ttyS0")

    shutdown(vmm_process)
    if tmp_disk_path is not None:
        os.remove(tmp_disk_path)
