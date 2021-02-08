# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
"""Run the reference VMM and shut it down through a command on the serial."""

import os, signal, subprocess, time, fcntl
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

# No. of seconds after which to give up for the test
TEST_TIMEOUT = 30

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


def start_vmm_process(kernel_path, disk_path, num_vcpus = 1, mem_size_mib = 1024):
    # Kernel config
    cmdline = "console=ttyS0 i8042.nokbd reboot=t panic=1 pci=off"

    himem_start = 1048576

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

def setup_stdout_nonblocking(vmm_process):

    ## We'll need to do non-blocking I/O with the underlying sub-process since
    # we cannot use `communicate`, because `communicate` would close the
    # `stdin` that we later want to use to `shutdown`, to do that by hand,
    # we set `vmm_process.stdout` to non-blocking
    # Then we can use `os.read` that would raise `BlockingIOError`

    # FIXME: This should NOT be required to be done on every call, do it when we
    #        'Class'ify the test case
    flags = fcntl.fcntl(vmm_process.stdout, fcntl.F_GETFL)
    fcntl.fcntl(vmm_process.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)

def expect_string(vmm_process, expected_string, timeout=TEST_TIMEOUT):

    setup_stdout_nonblocking(vmm_process)

    # No. of seconds after which we'll give up
    giveup_after = timeout
    then = time.time()
    found = False
    # This is required because the pattern we are expecting might get split across two reads
    all_data = bytes()
    while not found:
        try:
            x = os.read(vmm_process.stdout.fileno(), 4096)
            all_data += x
            for line in all_data.split(b'\r\n'):
                if expected_string in line.decode():
                    found = True
                    return line.decode()
            # Whatever remains is collected in `all_data`.
            all_data = line
        except Exception as e:
            time.sleep(1)
            now = time.time()
            if now - then > giveup_after:
                raise TimeoutError(
                        "Timed out {} waiting for {}".format(now - then, expected_string))
        except Exception as _:
            raise


def expect_vcpus(vmm_process, expected_vcpus):

    # Actually following is not required because this function will be called after
    # `expect_string` is called once, which sets non-blocking, but let's not be
    # dependent on it, so it's just fine to call it again, less than ideal, but not
    # wrong.
    setup_stdout_nonblocking(vmm_process)

    # /proc/cpuinfo displays info about each vCPU
    vmm_process.stdin.write(b'cat /proc/cpuinfo\n')
    vmm_process.stdin.flush()

    siblings_line = expect_string(vmm_process, "siblings")
    actual_vcpus = int(siblings_line.split(":")[1].strip())

    assert actual_vcpus == expected_vcpus, \
            "Expected {}, found {} vCPUs".format(expected_vcpus, actual_vcpus)


def expect_mem(vmm_process, expected_mem_mib):
    expected_mem_kib = expected_mem_mib << 10

    # Extract memory information from the bootlog.
    # Example:
    # [    0.000000] Memory: 496512K/523896K available (8204K kernel
    # code, 646K rwdata, 1480K rodata, 2884K init, 2792K bss, 27384K reserved,
    # 0K cma-reserved)
    # The second value (523896K) is the initial guest memory in KiB, which we
    # will compare against the expected memory specified during VM creation.
    memory_string = expect_string(vmm_process, "Memory:")
    actual_mem_kib = int(memory_string.split('/')[1].split('K')[0])

    # Expect the difference between the expected and actual memory
    # to be a few hundred KiB.  For the guest memory sizes being tested, this
    # should be under 0.1% of the expected memory size.
    normalized_diff = (expected_mem_kib - float(actual_mem_kib)) / expected_mem_kib
    assert normalized_diff < 0.001, \
            "Expected {} KiB, found {} KiB of guest" \
            " memory".format(expected_mem_kib, actual_mem_kib)

def test_reference_vmm_timeout():
    """ Verifies timeout when the VM Boots but expected string is not found."""

    kernel = KERNELS_INITRAMFS[0]
    vmm_process, _ = start_vmm_process(kernel, None)

    with pytest.raises(TimeoutError) as e:
        expected_string = "Goodbye, world, from the rust-vmm reference VMM!"
        _ = expect_string(vmm_process, expected_string, timeout=20)

    shutdown(vmm_process)

    assert e.type is TimeoutError


@pytest.mark.parametrize("kernel", KERNELS_INITRAMFS)
def test_reference_vmm(kernel):
    """Start the reference VMM and verify that it works."""

    vmm_process, _ = start_vmm_process(kernel, None)

    # Poll process for new output until we find the hello world message.
    # If we do not find the expected message, this loop will not break and the
    # test will fail when the timeout expires.
    expected_string = "Hello, world, from the rust-vmm reference VMM!"
    _ = expect_string(vmm_process, expected_string)

    shutdown(vmm_process)


@pytest.mark.parametrize("kernel,disk", KERNELS_DISK)
def test_reference_vmm_with_disk(kernel, disk):
    """Start the reference VMM with a block device and verify that it works."""

    vmm_process, tmp_disk_path = start_vmm_process(kernel, disk)

    _ = expect_string(vmm_process, "Ubuntu 20.04 LTS ubuntu-rust-vmm ttyS0")

    shutdown(vmm_process)
    if tmp_disk_path is not None:
        os.remove(tmp_disk_path)


@pytest.mark.parametrize("kernel", KERNELS_INITRAMFS)
def test_reference_vmm_num_vcpus(kernel):
    """Start the reference VMM and verify the number of vCPUs."""

    num_vcpus = [1, 2, 4]

    for expected_vcpus in num_vcpus:
        # Start a VM with a specified number of vCPUs
        vmm_process, _ = start_vmm_process(kernel, None, expected_vcpus)

        # Poll the output from /proc/cpuinfo for the field displaying the the
        # number of vCPUs.
        #
        expect_vcpus(vmm_process, expected_vcpus)

        shutdown(vmm_process)


@pytest.mark.parametrize("kernel", KERNELS_INITRAMFS)
def test_reference_vmm_mem(kernel):
    """Start the reference VMM and verify the amount of guest memory."""

    # Test small and large guest memory sizes, as well as sizes around the
    # beginning of the MMIO gap, which require a partition of guest memory.
    #
    # The MMIO gap sits in 768 MiB at the end of the first 4GiB of memory, and
    # we want to ensure memory is correctly partitioned; therefore, in addition
    # to memory sizes that fit well below the and extend well beyond the gap,
    # we will test the edge cases around the start of the gap.
    # See 'vmm/src/lib.rs:create_guest_memory()`
    mmio_gap_end = 1 << 32
    mmio_gap_size = 768 << 20
    mmio_gap_start = mmio_gap_end - mmio_gap_size
    mmio_gap_start_mib = mmio_gap_start >> 20

    mem_sizes_mib = [
            512,
            mmio_gap_start_mib - 1,
            mmio_gap_start_mib,
            mmio_gap_start_mib + 1,
            8192]

    for expected_mem_mib in mem_sizes_mib:
        # Start a VM with a specified amount of memory
        vmm_process, _ = start_vmm_process(kernel, None, 1, expected_mem_mib)

        # Poll the output from /proc/meminfo for the field displaying the the
        # total amount of memory.
        #
        # If we do not find the field, this loop will not break and the
        # test will fail when the timeout expires.  If we find the field, but
        # the expected and actual guest memory sizes diverge by more than 0.1%,
        # the test will fail immediately with an explanation.
        expect_mem(vmm_process, expected_mem_mib)

        shutdown(vmm_process)
