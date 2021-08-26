pub(crate) const KVM_REG_ARM64: u64 = 0x6000000000000000;
pub(crate) const KVM_REG_SIZE_U64: u64 = 0x0030000000000000;
pub(crate) const KVM_REG_ARM_COPROC_SHIFT: u64 = 16;
pub(crate) const KVM_REG_ARM_CORE: u64 = 0x0010 << KVM_REG_ARM_COPROC_SHIFT;

macro_rules! arm64_core_reg {
    ($reg: tt) => {
        KVM_REG_ARM64
            | KVM_REG_SIZE_U64
            | KVM_REG_ARM_CORE
            | ((offset__of!(kvm_bindings::user_pt_regs, $reg) / 4) as u64)
    };
}

macro_rules! offset__of {
    ($str:ty, $($field:ident).+ $([$idx:expr])*) => {
        unsafe { &(*(0 as *const $str))$(.$field)*  $([$idx])* as *const _ as usize }
    }
}
