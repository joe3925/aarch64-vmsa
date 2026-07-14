use core::fmt::Debug;

use crate::arch::FeatureRequirements;

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
pub struct SinglePrivilegeTablePermissionLimits {
    pub data_limit: DataAccess,
    pub execute_limit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoPrivilegeLeafPermissions {
    pub privileged_data: DataAccess,
    pub unprivileged_data: DataAccess,
    pub privileged_execute: bool,
    pub unprivileged_execute: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoPrivilegeTablePermissionLimits {
    pub privileged_data_limit: DataAccess,
    pub unprivileged_data_limit: DataAccess,
    pub privileged_execute_limit: bool,
    pub unprivileged_execute_limit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2LeafPermissions {
    pub data: DataAccess,
    pub privileged_execute: bool,
    pub unprivileged_execute: bool,
}

pub trait PrivilegeModel: Copy + 'static {
    type LeafPermissions: Copy + Debug + Eq + PartialEq;
    type TablePermissionLimits: Copy + Debug + Eq + PartialEq;
    const SUPPORTS_EL0: bool;
    const HAS_TTBR1: bool;
    const REQUIRED_FEATURES: FeatureRequirements;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El1And0Permissions;
impl PrivilegeModel for El1And0Permissions {
    type LeafPermissions = TwoPrivilegeLeafPermissions;
    type TablePermissionLimits = TwoPrivilegeTablePermissionLimits;
    const SUPPORTS_EL0: bool = true;
    const HAS_TTBR1: bool = true;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El2Permissions;
impl PrivilegeModel for El2Permissions {
    type LeafPermissions = SinglePrivilegeLeafPermissions;
    type TablePermissionLimits = SinglePrivilegeTablePermissionLimits;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE.with_el2();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El2And0Permissions;
impl PrivilegeModel for El2And0Permissions {
    type LeafPermissions = TwoPrivilegeLeafPermissions;
    type TablePermissionLimits = TwoPrivilegeTablePermissionLimits;
    const SUPPORTS_EL0: bool = true;
    const HAS_TTBR1: bool = true;
    const REQUIRED_FEATURES: FeatureRequirements =
        FeatureRequirements::NONE.with_el2().with_el2_and0();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct El3Permissions;
impl PrivilegeModel for El3Permissions {
    type LeafPermissions = SinglePrivilegeLeafPermissions;
    type TablePermissionLimits = SinglePrivilegeTablePermissionLimits;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE.with_el3();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Permissions;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2XnxPermissions;

pub trait Stage2PermissionModel: Copy + 'static {
    const REQUIRED_FEATURES: FeatureRequirements;
    const XNX: bool;
}

impl Stage2PermissionModel for Stage2Permissions {
    const REQUIRED_FEATURES: FeatureRequirements =
        FeatureRequirements::NONE.with_el2().with_stage2();
    const XNX: bool = false;
}

impl Stage2PermissionModel for Stage2XnxPermissions {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .with_el2()
        .with_stage2()
        .with_xnx();
    const XNX: bool = true;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1EffectivePermissions {
    pub privileged_data: DataAccess,
    pub unprivileged_data: DataAccess,
    pub privileged_execute: bool,
    pub unprivileged_execute: bool,
    pub privileged_gcs: bool,
    pub unprivileged_gcs: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum MostlyReadOnly {
    Unqualified,
    TopLevel1,
    TopLevel0,
    TopLevels0And1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Stage2Permission {
    NoAccess,
    MostlyReadOnly(MostlyReadOnly),
    WriteOnly,
    ReadOnly {
        privileged_execute: bool,
        unprivileged_execute: bool,
    },
    ReadWrite {
        privileged_execute: bool,
        unprivileged_execute: bool,
    },
}
