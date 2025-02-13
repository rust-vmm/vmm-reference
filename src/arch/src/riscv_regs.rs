#[cfg(target_arch = "riscv64")]
#[macro_export]
macro_rules! kvm_reg_riscv_core_reg {
    ($name:ident) => {
        offset_of!(kvm_bindings::user_regs_struct, $name) / std::mem::size_of::<u64>()
    };
}
#[macro_export]
macro_rules! riscv_core_reg {
    ($name:ident) => {
        kvm_reg_id!(
            KVM_REG_RISCV_CORE as u64,
            0,
            kvm_reg_riscv_core_reg!($name) as u64,
            KVM_REG_SIZE_U64
        )
    };
}

// Registers configuration macros
#[macro_export]
macro_rules! kvm_reg_riscv_config_reg {
    ($name:ident) => {
        offset_of!(kvm_bindings::kvm_riscv_config, $name) / std::mem::size_of::<u64>()
    };
}
#[macro_export]
macro_rules! riscv_config_reg {
    ($name:ident) => {
        kvm_reg_id!(
            KVM_REG_RISCV_CONFIG as u64,
            0,
            kvm_reg_riscv_config_reg!($name) as u64,
            KVM_REG_SIZE_U64
        )
    };
}

// Timer-related macros
#[macro_export]
macro_rules! kvm_reg_riscv_timer_reg {
    ($name:ident) => {
        offset_of!(kvm_riscv_timer, $name) / std::mem::size_of::<u64>()
    };
}
#[macro_export]
macro_rules! riscv_timer_reg {
    ($name:ident) => {
        kvm_reg_id!(
            KVM_REG_RISCV_TIMER as u64,
            0,
            kvm_reg_riscv_timer_reg!($name) as u64,
            KVM_REG_SIZE_U64
        )
    };
}

#[macro_export]
macro_rules! riscv_isa_ext_reg {
    ($id:expr) => {
        kvm_reg_id!(KVM_REG_RISCV_ISA_EXT as u64, 0, $id, KVM_REG_SIZE_U64)
    };
}

#[macro_export]
macro_rules! kvm_reg_id {
    ($stype:expr, $subtype:expr, $idx:expr, $size:expr) => {
        (KVM_REG_RISCV as u64)
            | ($stype as u64)
            | ($subtype as u64)
            | ($idx as u64)
            | ($size as u64)
    };
}
