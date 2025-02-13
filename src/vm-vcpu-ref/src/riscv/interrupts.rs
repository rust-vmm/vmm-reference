use kvm_ioctls::{DeviceFd, VmFd};
//use kvm_bindings::{kvm_create_device, kvm_device_type_KVM_DEV_TYPE_RISCV_AIA, KVM_DEV_RISCV_AIA_GRP_ADDR, KVM_DEV_RISCV_AIA_ADDR_APLIC, KVM_DEV_RISCV_AIA_CONFIG_GUEST_BITS, KVM_DEV_RISCV_AIA_CONFIG_SRCS, KVM_DEV_RISCV_AIA_CTRL_INIT, KVM_DEV_RISCV_AIA_GRP_CTRL, KVM_DEV_RISCV_AIA_CONFIG_GROUP_SHIFT, KVM_DEV_RISCV_AIA_CONFIG_GROUP_BITS, KVM_DEV_RISCV_AIA_CONFIG_IDS, KVM_DEV_RISCV_AIA_CONFIG_MODE, KVM_DEV_RISCV_AIA_GRP_CONFIG, KVM_DEV_RISCV_AIA_CONFIG_HART_BITS};
use kvm_bindings::*;
use std::convert::TryInto;

const IMSIC_MMIO_GROUP_MIN_SHIFT: u64 = 24;
const AIA_IRQ_NUM_SRCS: u64 = 96;
const AIA_MSI_NUM: u64 = 255;
const BITS_PER_LONG: usize = std::mem::size_of::<usize>() * 8;
const IMSIC_MMIO_PAGE_SZ: u64 = 1u64 << 12;

/// Errors associated with operations related to the GIC.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Error {
    /// Error calling into KVM ioctl.
    #[error("Error calling into KVM ioctl: {0}")]
    Kvm(kvm_ioctls::Error),
    /// Error creating the APLIC device.
    #[error("Error creating the APLIC device: {0}")]
    CreateDevice(kvm_ioctls::Error),
    /// Error setting an attribute for the APLIC device.
    #[error("Error setting an attribute ({0}) for the APLIC device: {1}")]
    SetAttr(&'static str, kvm_ioctls::Error),
    /// Inconsisted vCPU count between APLIC and vCPU states.
    #[error("Inconsisted vCPU count between the APLIC and vCPU state")]
    InconsistentVcpuCount,
}

impl From<kvm_ioctls::Error> for Error {
    fn from(inner: kvm_ioctls::Error) -> Self {
        Error::Kvm(inner)
    }
}

/// Specialized result type for operations on the APLIC.
pub type Result<T> = std::result::Result<T, Error>;

/// High level wrapper for creating and managing the APLIC device.
#[derive(Debug)]
pub struct APlic {
    device_fd: DeviceFd,
    num_cpus: u8,
}

#[derive(Debug, Clone, Default)]
/// Struct to config the APlic
pub struct APlicConfig {
    /// Number of CPUs that this APLIC supports. This is not used when configuring
    /// a APLIC.
    pub num_cpus: u8,
}

impl APlic {
    /// Create a new Plic device
    pub fn new(config: APlicConfig, vm_fd: &VmFd) -> Result<APlic> {
        let device_fd = APlic::create_device(vm_fd)?;
        let mut aplic = APlic {
            num_cpus: config.num_cpus,
            device_fd,
        };
        aplic.configure_device()?;
        Ok(aplic)
    }

    // Helper function that sets the required attributes for the device.
    fn configure_device(&mut self) -> Result<()> {
        let hart_count = self.num_cpus as u64;
        let socket_count = 1;
        let mut max_hart_per_socket = 0;
        let imsic_base: u64 = 0x28000000;
        let aplic_base: u64 = 0xc000000;

        let mut attr = kvm_bindings::kvm_device_attr::default();
        let mut default_aia_mode: u32 = 0;
        attr.group = KVM_DEV_RISCV_AIA_GRP_CONFIG;
        attr.attr = KVM_DEV_RISCV_AIA_CONFIG_MODE as u64;
        attr.addr = &mut default_aia_mode as *const u32 as u64;
        // SAFETY: This is safe because we set properly kvm_device_attr struct
        assert!(unsafe { self.device_fd.get_device_attr(&mut attr).is_ok() });

        let attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: KVM_DEV_RISCV_AIA_CONFIG_SRCS as u64,
            addr: &AIA_IRQ_NUM_SRCS as *const u64 as u64,
            flags: 0,
        };
        self.device_fd
            .set_device_attr(&attr)
            .map_err(|e| Error::SetAttr("Could not config srcs", e))?;

        let attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: KVM_DEV_RISCV_AIA_CONFIG_IDS as u64,
            addr: &AIA_MSI_NUM as *const u64 as u64,
            flags: 0,
        };
        self.device_fd
            .set_device_attr(&attr)
            .map_err(|e| Error::SetAttr("Could not config ids", e))?;

        if socket_count > 1 {
            let socket_bits: u64 = find_last_bit(&[socket_count], BITS_PER_LONG) + 1;
            let attr = kvm_bindings::kvm_device_attr {
                group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
                attr: KVM_DEV_RISCV_AIA_CONFIG_GROUP_BITS as u64,
                addr: &socket_bits as *const u64 as u64,
                flags: 0,
            };
            self.device_fd
                .set_device_attr(&attr)
                .map_err(|e| Error::SetAttr("Could not set group bits", e))?;

            let attr = kvm_bindings::kvm_device_attr {
                group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
                attr: KVM_DEV_RISCV_AIA_CONFIG_GROUP_SHIFT as u64,
                addr: &IMSIC_MMIO_GROUP_MIN_SHIFT as *const u64 as u64,
                flags: 0,
            };
            self.device_fd
                .set_device_attr(&attr)
                .map_err(|e| Error::SetAttr("Could not set group shift", e))?;
        }

        let mut guest_bits: u64 = 0;
        let guest_num = 0;

        if guest_num != 0 {
            let last_bit = find_last_bit(&[guest_bits], BITS_PER_LONG) + 1;
            guest_bits = last_bit;
        }

        let attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: KVM_DEV_RISCV_AIA_CONFIG_GUEST_BITS as u64,
            addr: &guest_bits as *const u64 as u64,
            flags: 0,
        };
        self.device_fd
            .set_device_attr(&attr)
            .map_err(|e| Error::SetAttr("Could not set guest bits", e))?;

        let attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_ADDR,
            attr: KVM_DEV_RISCV_AIA_ADDR_APLIC as u64,
            addr: &aplic_base as *const u64 as u64,
            flags: 0,
        };
        self.device_fd
            .set_device_attr(&attr)
            .map_err(|e| Error::SetAttr("Could not set APLIC base address", e))?;

        let imsic_hart_num_guests: u64 = 1u64 << guest_bits;
        let imsic_hart_size: u64 = imsic_hart_num_guests * IMSIC_MMIO_PAGE_SZ;
        let group_shift = IMSIC_MMIO_GROUP_MIN_SHIFT;
        for socket in 0..socket_count {
            let socket_imsic_base = imsic_base + socket * (1u64 << group_shift);

            if max_hart_per_socket < hart_count {
                max_hart_per_socket = hart_count;
            }

            for i in 0..hart_count {
                let imsic_addr: u64 = socket_imsic_base + i * imsic_hart_size;
                let attr = kvm_bindings::kvm_device_attr {
                    group: KVM_DEV_RISCV_AIA_GRP_ADDR,
                    attr: 1 + i,
                    addr: &imsic_addr as *const u64 as u64,
                    flags: 0,
                };
                self.device_fd
                    .set_device_attr(&attr)
                    .map_err(|e| Error::SetAttr("Could not set IMSIC addr", e))?;
            }
        }

        let hart_bits = if max_hart_per_socket > 1 {
            max_hart_per_socket -= 1;
            find_last_bit(&[max_hart_per_socket], BITS_PER_LONG) + 1
        } else {
            0
        };

        let attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CONFIG,
            attr: u64::from(KVM_DEV_RISCV_AIA_CONFIG_HART_BITS),
            addr: &hart_bits as *const u64 as u64,
            flags: 0,
        };
        self.device_fd
            .set_device_attr(&attr)
            .map_err(|e| Error::SetAttr("Could not set hart bits", e))?;

        let attr = kvm_bindings::kvm_device_attr {
            group: KVM_DEV_RISCV_AIA_GRP_CTRL,
            attr: u64::from(KVM_DEV_RISCV_AIA_CTRL_INIT),
            addr: 0x0,
            flags: 0,
        };
        self.device_fd
            .set_device_attr(&attr)
            .map_err(|e| Error::SetAttr("Could not initialize AIA", e))?;

        Ok(())
    }

    // Create the device FD corresponding to the APLIC version specified as parameter.
    fn create_device(vm_fd: &VmFd) -> Result<DeviceFd> {
        let mut create_device_attr = kvm_create_device {
            type_: kvm_device_type_KVM_DEV_TYPE_RISCV_AIA,
            fd: 0,
            flags: 0,
        };
        vm_fd
            .create_device(&mut create_device_attr)
            .map_err(Error::CreateDevice)
    }
}

fn find_last_bit(addr: &[u64], size: usize) -> u64 {
    let mut words = size / BITS_PER_LONG;

    if size & (BITS_PER_LONG - 1) != 0 {
        let remaining_bits = size & (BITS_PER_LONG - 1);
        let tmp = addr[words] & (!0usize >> (BITS_PER_LONG - remaining_bits)) as u64;
        if tmp != 0 {
            return (words * BITS_PER_LONG + BITS_PER_LONG - 1 - tmp.leading_zeros() as usize)
                .try_into()
                .unwrap();
        }
    }

    while words > 0 {
        words -= 1;
        let tmp = addr[words];
        if tmp != 0 {
            return (words * BITS_PER_LONG + BITS_PER_LONG - 1 - tmp.leading_zeros() as usize)
                .try_into()
                .unwrap();
        }
    }

    size as u64
}
