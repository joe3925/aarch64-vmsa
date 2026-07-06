use core::fmt::Debug;

use crate::features::VmsaFeatures;
use crate::translation_regime::RegimeOwner;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DataAccess {
    None,
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinglePrivilegeLeafPermissions {
    pub data: DataAccess,
    pub execute: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinglePrivilegeTablePermissions {
    pub data_limit: DataAccess,
    pub execute: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoPrivilegeLeafPermissions {
    pub privileged_data: DataAccess,
    pub unprivileged_data: DataAccess,
    pub privileged_execute: bool,
    pub unprivileged_execute: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoPrivilegeTablePermissions {
    pub privileged_data_limit: DataAccess,
    pub unprivileged_data_limit: DataAccess,
    pub privileged_execute: bool,
    pub unprivileged_execute: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2LeafPermissions {
    pub data: DataAccess,
    pub privileged_execute: bool,
    pub unprivileged_execute: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2TablePermissions {
    pub data_limit: DataAccess,
    pub privileged_execute: bool,
    pub unprivileged_execute: bool,
}

pub trait PermissionModel: Copy + 'static {
    type LeafPermissions: Copy + Debug + Eq + PartialEq;
    type TablePermissions: Copy + Debug + Eq + PartialEq;

    const OWNER: RegimeOwner;
    const SUPPORTS_EL0: bool;
    const HAS_TTBR1: bool;
    const REQUIRED_FEATURES: VmsaFeatures;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1And0Permissions;

impl PermissionModel for El1And0Permissions {
    type LeafPermissions = TwoPrivilegeLeafPermissions;
    type TablePermissions = TwoPrivilegeTablePermissions;

    const OWNER: RegimeOwner = RegimeOwner::El1;
    const SUPPORTS_EL0: bool = true;
    const HAS_TTBR1: bool = true;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El2Permissions;

impl PermissionModel for El2Permissions {
    type LeafPermissions = SinglePrivilegeLeafPermissions;
    type TablePermissions = SinglePrivilegeTablePermissions;

    const OWNER: RegimeOwner = RegimeOwner::El2;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_el2();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El2And0Permissions;

impl PermissionModel for El2And0Permissions {
    type LeafPermissions = TwoPrivilegeLeafPermissions;
    type TablePermissions = TwoPrivilegeTablePermissions;

    const OWNER: RegimeOwner = RegimeOwner::El2;
    const SUPPORTS_EL0: bool = true;
    const HAS_TTBR1: bool = true;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_el2().with_el2_and0();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El3Permissions;

impl PermissionModel for El3Permissions {
    type LeafPermissions = SinglePrivilegeLeafPermissions;
    type TablePermissions = SinglePrivilegeTablePermissions;

    const OWNER: RegimeOwner = RegimeOwner::El3;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_el3();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Permissions;

impl PermissionModel for Stage2Permissions {
    type LeafPermissions = Stage2LeafPermissions;
    type TablePermissions = Stage2TablePermissions;

    const OWNER: RegimeOwner = RegimeOwner::El2;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: VmsaFeatures = VmsaFeatures::NONE.with_el2().with_stage2();
}
