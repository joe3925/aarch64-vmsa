use core::fmt::Debug;

use crate::arch::{Capability, FeatureRequirements};
use crate::config::stage2::{Stage2Permissions, Stage2XnxPermissions};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DataAccess {
    None,
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinglePrivilegeTablePermissionLimits {
    pub data_limit: DataAccess,
    pub execute_limit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoPrivilegeTablePermissionLimits {
    pub privileged_data_limit: DataAccess,
    pub unprivileged_data_limit: DataAccess,
    pub privileged_execute_limit: bool,
    pub unprivileged_execute_limit: bool,
}

mod private {
    pub trait PrivilegeSealed {}
    pub trait Stage2Sealed {}
}

pub trait PrivilegeModel: private::PrivilegeSealed + Copy + 'static {
    type TablePermissionLimits: Copy + Debug + Eq + PartialEq;
    const SUPPORTS_EL0: bool;
    const HAS_TTBR1: bool;
    const REQUIRED_FEATURES: FeatureRequirements;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct El1And0Permissions;
impl private::PrivilegeSealed for El1And0Permissions {}
impl PrivilegeModel for El1And0Permissions {
    type TablePermissionLimits = TwoPrivilegeTablePermissionLimits;
    const SUPPORTS_EL0: bool = true;
    const HAS_TTBR1: bool = true;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct El2Permissions;
impl private::PrivilegeSealed for El2Permissions {}
impl PrivilegeModel for El2Permissions {
    type TablePermissionLimits = SinglePrivilegeTablePermissionLimits;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: FeatureRequirements =
        FeatureRequirements::NONE.require(Capability::El2);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct El2And0Permissions;
impl private::PrivilegeSealed for El2And0Permissions {}
impl PrivilegeModel for El2And0Permissions {
    type TablePermissionLimits = TwoPrivilegeTablePermissionLimits;
    const SUPPORTS_EL0: bool = true;
    const HAS_TTBR1: bool = true;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .require(Capability::El2)
        .require(Capability::El2And0);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct El3Permissions;
impl private::PrivilegeSealed for El3Permissions {}
impl PrivilegeModel for El3Permissions {
    type TablePermissionLimits = SinglePrivilegeTablePermissionLimits;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: FeatureRequirements =
        FeatureRequirements::NONE.require(Capability::El3);
}

impl private::Stage2Sealed for Stage2Permissions {}
impl private::Stage2Sealed for Stage2XnxPermissions {}

pub trait Stage2PermissionModel: private::Stage2Sealed + Copy + 'static {
    const REQUIRED_FEATURES: FeatureRequirements;
    const XNX: bool;
}

impl Stage2PermissionModel for Stage2Permissions {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .require(Capability::El2)
        .require(Capability::Stage2);
    const XNX: bool = false;
}

impl Stage2PermissionModel for Stage2XnxPermissions {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .require(Capability::El2)
        .require(Capability::Stage2)
        .require(Capability::Xnx);
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

impl Stage2Permission {
    pub const fn direct(
        data: DataAccess,
        privileged_execute: bool,
        unprivileged_execute: bool,
    ) -> Self {
        match data {
            DataAccess::None => Self::NoAccess,
            DataAccess::ReadOnly => Self::ReadOnly {
                privileged_execute,
                unprivileged_execute,
            },
            DataAccess::ReadWrite => Self::ReadWrite {
                privileged_execute,
                unprivileged_execute,
            },
        }
    }
}
