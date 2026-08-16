mod codec;
mod memory;
mod pas;
mod stage1_permissions;
mod stage2_permissions;
mod vmsa128;
mod vmsa64;

pub use codec::AttributeCodec;
pub(crate) use memory::*;
pub(crate) use pas::*;
pub(crate) use stage1_permissions::*;
pub use stage1_permissions::{
    Stage1BasePermissions, Stage1PermissionOverlays, Stage1PermissionRegisters,
    Stage1PermissionSettings,
};
pub(crate) use stage2_permissions::*;
pub use stage2_permissions::{
    Stage2BasePermissions, Stage2PermissionRegisters, Stage2PermissionSettings,
};

use super::{D128Stage1AliasKind, Shareability};

pub(crate) trait PermissionIndex: Copy {
    const COUNT: u8;
    fn new(value: u8) -> Result<Self, super::AttrError>;
    fn bits(self) -> u8;
}

impl PermissionIndex for super::FourBit {
    const COUNT: u8 = 16;

    fn new(value: u8) -> Result<Self, super::AttrError> {
        Self::new(value)
    }

    fn bits(self) -> u8 {
        self.bits()
    }
}

impl PermissionIndex for super::ThreeBit {
    const COUNT: u8 = 8;

    fn new(value: u8) -> Result<Self, super::AttrError> {
        Self::new(value)
    }

    fn bits(self) -> u8 {
        self.bits()
    }
}

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
    // todo add feature validation for aie pie poe and haft
    fn stage1_permissions(&self) -> Stage1PermissionSettings {
        Stage1PermissionSettings::direct()
    }
}

pub trait Stage2PermissionConfig {
    fn stage2_permissions(&self) -> Stage2PermissionSettings {
        Stage2PermissionSettings::direct()
    }
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
    fn stage1_permissions(&self) -> Stage1PermissionSettings {
        (**self).stage1_permissions()
    }
}
impl_ref_config!(
    Stage2PermissionConfig,
    stage2_permissions,
    Stage2PermissionSettings
);
impl_ref_config!(D128AliasConfig, d128_stage1_alias_kind, D128Stage1AliasKind);
impl_ref_config!(ShareabilityConfig, effective_shareability, Shareability);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveVmsaConfig<Pas = ()> {
    pub mair: u64,
    pub mair2: Option<u64>,
    pub stage1_permissions: Stage1PermissionSettings,
    pub stage2_permissions: Stage2PermissionSettings,
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
    fn stage1_permissions(&self) -> Stage1PermissionSettings {
        self.stage1_permissions
    }
}
impl<P> Stage2PermissionConfig for LiveVmsaConfig<P> {
    fn stage2_permissions(&self) -> Stage2PermissionSettings {
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
