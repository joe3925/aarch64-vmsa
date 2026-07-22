mod codec;
mod memory;
mod pas;
mod stage1_permissions;
mod stage2_permissions;
mod vmsa128;
mod vmsa64;

pub use codec::*;
pub(crate) use memory::*;
pub(crate) use pas::*;
pub(crate) use stage1_permissions::*;
pub use stage1_permissions::{Stage1PermissionRegisterPair, Stage1PermissionRegisters};
pub use stage2_permissions::Stage2PermissionRegisters;
pub(crate) use stage2_permissions::*;
use vmsa64::*;
use vmsa128::*;

use super::{D128Stage1AliasKind, Shareability};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2MemoryMode {
    FwbDisabled,
    FwbEnabled { mte_permission: bool },
}

pub trait Stage1MemoryConfig {
    fn mair(&self) -> u64;
    fn mair2(&self) -> Option<u64> {
        None
    }
}

pub trait Stage2MemoryConfig {
    fn stage2_memory_mode(&self) -> Stage2MemoryMode;
}

pub trait Stage1PermissionConfig {
    fn stage1_permission_registers(&self) -> Option<Stage1PermissionRegisters>;
}

pub trait Stage2PermissionConfig {
    fn stage2_permission_registers(&self) -> Option<Stage2PermissionRegisters>;
}

pub trait D128AliasConfig {
    fn d128_stage1_alias_kind(&self) -> D128Stage1AliasKind;
}

pub trait ShareabilityConfig {
    fn effective_shareability(&self) -> Shareability;
}

pub trait PasConfig {
    type Pas: Copy;
    fn configured_output_pas(&self) -> Self::Pas;
}

macro_rules! impl_ref_config {
    ($trait:ident, $method:ident, $ret:ty) => {
        impl<T: $trait + ?Sized> $trait for &T {
            fn $method(&self) -> $ret {
                (**self).$method()
            }
        }
    };
}

impl<T: Stage1MemoryConfig + ?Sized> Stage1MemoryConfig for &T {
    fn mair(&self) -> u64 {
        (**self).mair()
    }
    fn mair2(&self) -> Option<u64> {
        (**self).mair2()
    }
}
impl_ref_config!(Stage2MemoryConfig, stage2_memory_mode, Stage2MemoryMode);
impl<T: Stage1PermissionConfig + ?Sized> Stage1PermissionConfig for &T {
    fn stage1_permission_registers(&self) -> Option<Stage1PermissionRegisters> {
        (**self).stage1_permission_registers()
    }
}
impl_ref_config!(
    Stage2PermissionConfig,
    stage2_permission_registers,
    Option<Stage2PermissionRegisters>
);
impl_ref_config!(D128AliasConfig, d128_stage1_alias_kind, D128Stage1AliasKind);
impl_ref_config!(ShareabilityConfig, effective_shareability, Shareability);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveVmsaConfig<Pas = ()> {
    pub mair: u64,
    pub mair2: Option<u64>,
    pub stage1_permissions: Option<Stage1PermissionRegisters>,
    pub stage2_permissions: Option<Stage2PermissionRegisters>,
    pub stage2_memory_mode: Stage2MemoryMode,
    pub d128_stage1_alias: D128Stage1AliasKind,
    pub shareability: Shareability,
    pub output_pas: Pas,
}

impl<P> Stage1MemoryConfig for LiveVmsaConfig<P> {
    fn mair(&self) -> u64 {
        self.mair
    }
    fn mair2(&self) -> Option<u64> {
        self.mair2
    }
}
impl<P> Stage2MemoryConfig for LiveVmsaConfig<P> {
    fn stage2_memory_mode(&self) -> Stage2MemoryMode {
        self.stage2_memory_mode
    }
}
impl<P> Stage1PermissionConfig for LiveVmsaConfig<P> {
    fn stage1_permission_registers(&self) -> Option<Stage1PermissionRegisters> {
        self.stage1_permissions
    }
}
impl<P> Stage2PermissionConfig for LiveVmsaConfig<P> {
    fn stage2_permission_registers(&self) -> Option<Stage2PermissionRegisters> {
        self.stage2_permissions
    }
}
impl<P> D128AliasConfig for LiveVmsaConfig<P> {
    fn d128_stage1_alias_kind(&self) -> D128Stage1AliasKind {
        self.d128_stage1_alias
    }
}
impl<P> ShareabilityConfig for LiveVmsaConfig<P> {
    fn effective_shareability(&self) -> Shareability {
        self.shareability
    }
}
impl<P: Copy> PasConfig for LiveVmsaConfig<P> {
    type Pas = P;
    fn configured_output_pas(&self) -> Self::Pas {
        self.output_pas
    }
}

pub(crate) fn require_effective_shareability<C: ShareabilityConfig>(
    config: &C,
    requested: Shareability,
) -> Result<(), super::AttrError> {
    let effective = config.effective_shareability();
    if requested == effective {
        Ok(())
    } else {
        Err(super::AttrError::ShareabilityMismatch {
            requested,
            effective,
        })
    }
}

pub(crate) fn decode_shareability(
    raw: super::RawShareability,
) -> Result<Shareability, super::AttrError> {
    match raw.bits() {
        0b00 => Ok(Shareability::NonShareable),
        0b10 => Ok(Shareability::OuterShareable),
        0b11 => Ok(Shareability::InnerShareable),
        _ => Err(super::AttrError::InvalidShareability),
    }
}
