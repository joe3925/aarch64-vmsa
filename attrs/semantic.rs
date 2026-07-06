use core::marker::PhantomData;

use super::{AttrError, PermissionModel, Stage1PasModel, Stage2PasContext};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Shareability {
    NonShareable = 0b00,
    OuterShareable = 0b10,
    InnerShareable = 0b11,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DeviceMemoryType {
    NonGatheringNonReorderingNoEarlyAck,
    NonGatheringNonReorderingEarlyAck,
    NonGatheringReorderingEarlyAck,
    GatheringReorderingEarlyAck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CachePolicy {
    WriteThrough,
    WriteBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AllocationHints {
    None,
    WriteAllocate,
    ReadAllocate,
    ReadWriteAllocate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Cacheability {
    NonCacheable,
    Cacheable {
        policy: CachePolicy,
        transience: MemoryTransience,
        allocation: AllocationHints,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum MemoryAttributes {
    Device(DeviceMemoryType),
    Normal {
        inner: Cacheability,
        outer: Cacheability,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SoftwareDefinedBits {
    pub bit0: bool,
    pub bit1: bool,
    pub bit2: bool,
    pub bit3: bool,
}

impl SoftwareDefinedBits {
    pub(crate) const fn bits(self) -> u128 {
        self.bit0 as u128
            | ((self.bit1 as u128) << 1)
            | ((self.bit2 as u128) << 2)
            | ((self.bit3 as u128) << 3)
    }

    pub(crate) const fn from_bits(bits: u128) -> Self {
        Self {
            bit0: bits & 1 != 0,
            bit1: bits & 2 != 0,
            bit2: bits & 4 != 0,
            bit3: bits & 8 != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureDependentLeafAlias {
    NonGlobal(bool),
    ForceNoExecute(bool),
    NonSecureExtension(bool),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum D128LeafAliasKind {
    NonGlobal,
    ForceNoExecute,
    NonSecureExtension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum MemoryTransience {
    Transient,
    NonTransient,
}

impl MemoryTransience {
    pub(crate) const fn not_transient_bit(self) -> bool {
        matches!(self, Self::NonTransient)
    }

    pub(crate) const fn from_not_transient_bit(bit: bool) -> Self {
        if bit {
            Self::NonTransient
        } else {
            Self::Transient
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DirtyState {
    Dirty,
    Clean,
}

impl DirtyState {
    pub(crate) const fn not_dirty_bit(self) -> bool {
        matches!(self, Self::Clean)
    }

    pub(crate) const fn from_not_dirty_bit(bit: bool) -> Self {
        if bit { Self::Clean } else { Self::Dirty }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DirtyBitManagement {
    SoftwareManaged,
    HardwareManaged,
}

impl DirtyBitManagement {
    pub(crate) const fn dbm_bit(self) -> bool {
        matches!(self, Self::HardwareManaged)
    }

    pub(crate) const fn from_dbm_bit(bit: bool) -> Self {
        if bit {
            Self::HardwareManaged
        } else {
            Self::SoftwareManaged
        }
    }
}

impl Shareability {
    pub(crate) const fn bits(self) -> u128 {
        self as u128
    }

    pub(crate) fn from_bits(bits: u128) -> Result<Self, AttrError> {
        match bits & 0b11 {
            0b00 => Ok(Self::NonShareable),
            0b10 => Ok(Self::OuterShareable),
            0b11 => Ok(Self::InnerShareable),
            _ => Err(AttrError::InvalidShareability),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1LeafAttrs<P, A, M, C>
where
    P: PermissionModel,
    A: Stage1PasModel,
{
    pub memory: M,
    pub permissions: P::LeafPermissions,
    pub pas: A::LeafAttr,
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1TableAttrs<P, A, C>
where
    P: PermissionModel,
    A: Stage1PasModel,
{
    pub permissions: P::TablePermissions,
    pub pas: A::TableAttr,
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2LeafAttrs<P, X, M, C>
where
    P: PermissionModel,
    X: Stage2PasContext,
{
    pub memory: M,
    pub permissions: P::LeafPermissions,
    pub controls: C,
    context: PhantomData<X>,
}

impl<P, X, M, C> Stage2LeafAttrs<P, X, M, C>
where
    P: PermissionModel,
    X: Stage2PasContext,
{
    pub const fn new(memory: M, permissions: P::LeafPermissions, controls: C) -> Self {
        Self {
            memory,
            permissions,
            controls,
            context: PhantomData,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2TableAttrs<P, X, C>
where
    P: PermissionModel,
    X: Stage2PasContext,
{
    pub permissions: P::TablePermissions,
    pub controls: C,
    context: PhantomData<X>,
}

impl<P, X, C> Stage2TableAttrs<P, X, C>
where
    P: PermissionModel,
    X: Stage2PasContext,
{
    pub const fn new(permissions: P::TablePermissions, controls: C) -> Self {
        Self {
            permissions,
            controls,
            context: PhantomData,
        }
    }
}
