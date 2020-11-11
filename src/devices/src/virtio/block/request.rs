// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

// Everything here is taken from Firecracker for now, with very small changes. We'll switch to
// the request parsing and execution building blocks from rust-vmm after we have an initial
// implementation.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::mem;
use std::os::linux::fs::MetadataExt;
use std::path::PathBuf;
use std::result;

use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryError,
};
use vm_virtio::DescriptorChain;

use super::{SECTOR_SHIFT, SECTOR_SIZE};

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;

const VIRTIO_BLK_S_IOERR: u32 = 1;
const VIRTIO_BLK_S_UNSUPP: u32 = 2;

const VIRTIO_BLK_ID_BYTES: u32 = 20;

const CONFIG_SPACE_SIZE: usize = 8;

#[derive(Debug)]
pub enum Error {
    DescriptorChainTooShort,
    DescriptorLengthTooSmall,
    GetFileMetadata(std::io::Error),
    GuestMemory(GuestMemoryError),
    InvalidOffset,
    UnexpectedReadOnlyDescriptor,
    UnexpectedWriteOnlyDescriptor,
}

#[derive(Debug)]
pub enum ExecuteError {
    BadRequest(Error),
    Flush(io::Error),
    Read(GuestMemoryError),
    Seek(io::Error),
    Write(GuestMemoryError),
    Unsupported(u32),
}

impl ExecuteError {
    pub fn status(&self) -> u32 {
        match *self {
            ExecuteError::BadRequest(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Flush(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Read(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Seek(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Write(_) => VIRTIO_BLK_S_IOERR,
            ExecuteError::Unsupported(_) => VIRTIO_BLK_S_UNSUPP,
        }
    }
}

/// Helper object for setting up all `Block` fields derived from its backing file.
pub struct DiskProperties {
    file_path: String,
    file: File,
    nsectors: u64,
    image_id: Vec<u8>,
}

impl DiskProperties {
    pub fn new(disk_image_path: String, is_disk_read_only: bool) -> io::Result<Self> {
        let mut disk_image = OpenOptions::new()
            .read(true)
            .write(!is_disk_read_only)
            .open(PathBuf::from(&disk_image_path))?;
        let disk_size = disk_image.seek(SeekFrom::End(0))? as u64;

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if disk_size % SECTOR_SIZE != 0 {
            // warn!(
            //     "Disk size {} is not a multiple of sector size {}; \
            //       the remainder will not be visible to the guest.",
            //     disk_size, SECTOR_SIZE
            // );
        }

        Ok(Self {
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: Self::build_disk_image_id(&disk_image),
            file_path: disk_image_path,
            file: disk_image,
        })
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                // warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
            }
        }
        default_id
    }

    /// Backing file path.
    pub fn file_path(&self) -> &String {
        &self.file_path
    }

    /// Provides vec containing the virtio block configuration space
    /// buffer. The config space is populated with the disk size based
    /// on the backing file size.
    pub fn virtio_block_config_space(&self) -> Vec<u8> {
        // The config space is little endian.
        let mut config = Vec::with_capacity(CONFIG_SPACE_SIZE);
        for i in 0..CONFIG_SPACE_SIZE {
            config.push((self.nsectors >> (8 * i)) as u8);
        }
        config
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RequestType {
    In,
    Out,
    Flush,
    GetDeviceID,
    Unsupported(u32),
}

impl From<u32> for RequestType {
    fn from(value: u32) -> Self {
        match value {
            VIRTIO_BLK_T_IN => RequestType::In,
            VIRTIO_BLK_T_OUT => RequestType::Out,
            VIRTIO_BLK_T_FLUSH => RequestType::Flush,
            t => RequestType::Unsupported(t),
        }
    }
}

pub struct Request {
    pub request_type: RequestType,
    pub data_len: u32,
    pub status_addr: GuestAddress,
    sector: u64,
    data_addr: GuestAddress,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}

// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

impl RequestHeader {
    /// Reads the request header from GuestMemoryMmap starting at `addr`.
    ///
    /// Virtio 1.0 specifies that the data is transmitted by the driver in little-endian
    /// format. Firecracker currently runs only on little endian platforms so we don't
    /// need to do an explicit little endian read as all reads are little endian by default.
    /// When running on a big endian platform, this code should not compile, and support
    /// for explicit little endian reads is required.
    #[cfg(target_endian = "little")]
    fn read_from<M: GuestMemory>(memory: &M, addr: GuestAddress) -> result::Result<Self, Error> {
        let request_header: RequestHeader = memory.read_obj(addr).map_err(Error::GuestMemory)?;
        Ok(request_header)
    }
}

impl Request {
    pub fn parse<M: GuestAddressSpace>(
        chain: &mut DescriptorChain<M>,
    ) -> result::Result<Request, Error> {
        let avail_desc = chain.next().unwrap();

        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        let request_header = RequestHeader::read_from(chain.memory(), avail_desc.addr())?;
        let mut req = Request {
            request_type: RequestType::from(request_header.request_type),
            sector: request_header.sector,
            data_addr: GuestAddress(0),
            data_len: 0,
            status_addr: GuestAddress(0),
        };

        let data_desc;
        let status_desc;
        let desc = chain.next().ok_or(Error::DescriptorChainTooShort)?;

        if !desc.has_next() {
            status_desc = desc;
            // Only flush requests are allowed to skip the data descriptor.
            if req.request_type != RequestType::Flush {
                return Err(Error::DescriptorChainTooShort);
            }
        } else {
            data_desc = desc;
            status_desc = chain.next().ok_or(Error::DescriptorChainTooShort)?;

            if data_desc.is_write_only() && req.request_type == RequestType::Out {
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::In {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }
            if !data_desc.is_write_only() && req.request_type == RequestType::GetDeviceID {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }

            // Check that the address of the data descriptor is valid in guest memory.
            let _ = chain
                .memory()
                .checked_offset(data_desc.addr(), data_desc.len() as usize)
                .ok_or(Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(
                    data_desc.addr(),
                )))?;

            req.data_addr = data_desc.addr();
            req.data_len = data_desc.len();
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        if status_desc.len() < 1 {
            return Err(Error::DescriptorLengthTooSmall);
        }

        // Check that the address of the status descriptor is valid in guest memory.
        // We will write an u32 status here after executing the request.
        let _ = chain
            .memory()
            .checked_offset(status_desc.addr(), mem::size_of::<u32>())
            .ok_or(Error::GuestMemory(GuestMemoryError::InvalidGuestAddress(
                status_desc.addr(),
            )))?;

        req.status_addr = status_desc.addr();

        Ok(req)
    }

    pub(crate) fn execute<M: GuestMemory>(
        &self,
        disk: &mut DiskProperties,
        mem: &M,
    ) -> result::Result<u32, ExecuteError> {
        let mut top: u64 = u64::from(self.data_len) / SECTOR_SIZE;
        if u64::from(self.data_len) % SECTOR_SIZE != 0 {
            top += 1;
        }
        top = top
            .checked_add(self.sector)
            .ok_or(ExecuteError::BadRequest(Error::InvalidOffset))?;
        if top > disk.nsectors() {
            return Err(ExecuteError::BadRequest(Error::InvalidOffset));
        }

        let diskfile = disk.file_mut();
        diskfile
            .seek(SeekFrom::Start(self.sector << SECTOR_SHIFT))
            .map_err(ExecuteError::Seek)?;

        match self.request_type {
            RequestType::In => {
                mem.read_from(self.data_addr, diskfile, self.data_len as usize)
                    .map_err(ExecuteError::Read)?;
                // METRICS.block.read_bytes.add(self.data_len as usize);
                // METRICS.block.read_count.inc();
                return Ok(self.data_len);
            }
            RequestType::Out => {
                mem.write_to(self.data_addr, diskfile, self.data_len as usize)
                    .map_err(ExecuteError::Write)?;
                // METRICS.block.write_bytes.add(self.data_len as usize);
                // METRICS.block.write_count.inc();
            }
            RequestType::Flush => match diskfile.flush() {
                Ok(_) => {
                    // METRICS.block.flush_count.inc();
                    return Ok(0);
                }
                Err(e) => return Err(ExecuteError::Flush(e)),
            },
            RequestType::GetDeviceID => {
                let disk_id = disk.image_id();
                if (self.data_len as usize) < disk_id.len() {
                    return Err(ExecuteError::BadRequest(Error::InvalidOffset));
                }
                mem.write_slice(disk_id, self.data_addr)
                    .map_err(ExecuteError::Write)?;
            }
            RequestType::Unsupported(t) => return Err(ExecuteError::Unsupported(t)),
        };
        Ok(0)
    }
}
