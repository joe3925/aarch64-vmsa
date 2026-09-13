use core::fmt::Debug;

use crate::arch::{Capability, FeatureRequirements};
use crate::config::stage2::{StandardStage2PermissionModel, XnxStage2PermissionModel};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DataRights {
    None,
    Read,
    Write,
    ReadWrite,
}

impl DataRights {
    pub const fn from_read_write(read: bool, write: bool) -> Self {
        match (read, write) {
            (false, false) => Self::None,
            (true, false) => Self::Read,
            (false, true) => Self::Write,
            (true, true) => Self::ReadWrite,
        }
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self::from_read_write(
            self.permits_read() && other.permits_read(),
            self.permits_write() && other.permits_write(),
        )
    }

    pub const fn permits_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    pub const fn permits_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ExecuteRights {
    Neither,
    Privileged,
    Unprivileged,
    Both,
}

impl ExecuteRights {
    pub const fn from_privileged_unprivileged(privileged: bool, unprivileged: bool) -> Self {
        match (privileged, unprivileged) {
            (false, false) => Self::Neither,
            (true, false) => Self::Privileged,
            (false, true) => Self::Unprivileged,
            (true, true) => Self::Both,
        }
    }

    pub const fn privileged(self) -> bool {
        matches!(self, Self::Privileged | Self::Both)
    }

    pub const fn unprivileged(self) -> bool {
        matches!(self, Self::Unprivileged | Self::Both)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self::from_privileged_unprivileged(
            self.privileged() && other.privileged(),
            self.unprivileged() && other.unprivileged(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PrivilegePair<T> {
    pub privileged: T,
    pub unprivileged: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SinglePrivilegeTableRestrictions {
    pub data_limit: DataRights,
    pub execute_limit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TwoPrivilegeTableRestrictions {
    pub privileged_data_limit: DataRights,
    pub unprivileged_data_limit: DataRights,
    pub privileged_execute_limit: bool,
    pub unprivileged_execute_limit: bool,
}

mod private {
    pub trait PrivilegeSealed {}
    pub trait Stage2Sealed {}
}

pub trait PrivilegeModel: private::PrivilegeSealed + Copy + 'static {
    type TableRestrictions: Copy + Debug + Eq + PartialEq;
    const SUPPORTS_EL0: bool;
    const HAS_TTBR1: bool;
    const REQUIRED_FEATURES: FeatureRequirements;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct El1And0Permissions;
impl private::PrivilegeSealed for El1And0Permissions {}
impl PrivilegeModel for El1And0Permissions {
    type TableRestrictions = TwoPrivilegeTableRestrictions;
    const SUPPORTS_EL0: bool = true;
    const HAS_TTBR1: bool = true;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct El2Permissions;
impl private::PrivilegeSealed for El2Permissions {}
impl PrivilegeModel for El2Permissions {
    type TableRestrictions = SinglePrivilegeTableRestrictions;
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
    type TableRestrictions = TwoPrivilegeTableRestrictions;
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
    type TableRestrictions = SinglePrivilegeTableRestrictions;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: FeatureRequirements =
        FeatureRequirements::NONE.require(Capability::El3);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct SmmuStreamPermissions;
impl private::PrivilegeSealed for SmmuStreamPermissions {}
impl PrivilegeModel for SmmuStreamPermissions {
    type TableRestrictions = TwoPrivilegeTableRestrictions;
    const SUPPORTS_EL0: bool = true;
    const HAS_TTBR1: bool = true;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct SmmuPrivilegedStreamPermissions;
impl private::PrivilegeSealed for SmmuPrivilegedStreamPermissions {}
impl PrivilegeModel for SmmuPrivilegedStreamPermissions {
    type TableRestrictions = SinglePrivilegeTableRestrictions;
    const SUPPORTS_EL0: bool = false;
    const HAS_TTBR1: bool = false;
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE;
}

impl private::Stage2Sealed for StandardStage2PermissionModel {}
impl private::Stage2Sealed for XnxStage2PermissionModel {}

pub trait Stage2PermissionModel: private::Stage2Sealed + Copy + 'static {
    const REQUIRED_FEATURES: FeatureRequirements;
    const XNX: bool;
}

impl Stage2PermissionModel for StandardStage2PermissionModel {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .require(Capability::El2)
        .require(Capability::Stage2);
    const XNX: bool = false;
}

impl Stage2PermissionModel for XnxStage2PermissionModel {
    const REQUIRED_FEATURES: FeatureRequirements = FeatureRequirements::NONE
        .require(Capability::El2)
        .require(Capability::Stage2)
        .require(Capability::Xnx);
    const XNX: bool = true;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1Permissions {
    pub data: PrivilegePair<DataRights>,
    pub execute: ExecuteRights,
    pub gcs: PrivilegePair<bool>,
}

impl Stage1Permissions {
    pub const fn new(
        privileged_data: DataRights,
        unprivileged_data: DataRights,
        privileged_execute: bool,
        unprivileged_execute: bool,
        privileged_gcs: bool,
        unprivileged_gcs: bool,
    ) -> Self {
        Self {
            data: PrivilegePair {
                privileged: privileged_data,
                unprivileged: unprivileged_data,
            },
            execute: ExecuteRights::from_privileged_unprivileged(
                privileged_execute,
                unprivileged_execute,
            ),
            gcs: PrivilegePair {
                privileged: privileged_gcs,
                unprivileged: unprivileged_gcs,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TopLevelRequirements {
    pub top_level0: bool,
    pub top_level1: bool,
}

impl TopLevelRequirements {
    pub const NONE: Self = Self {
        top_level0: false,
        top_level1: false,
    };
    pub const TOP_LEVEL0: Self = Self {
        top_level0: true,
        top_level1: false,
    };
    pub const TOP_LEVEL1: Self = Self {
        top_level0: false,
        top_level1: true,
    };
    pub const BOTH: Self = Self {
        top_level0: true,
        top_level1: true,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TableAccessPermissions {
    pub mmu: DataRights,
    pub rcw: DataRights,
    pub top_level: TopLevelRequirements,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Stage2Permissions {
    pub data: DataRights,
    pub execute: ExecuteRights,
    pub table_access: TableAccessPermissions,
}

impl Stage2Permissions {
    pub const fn no_access() -> Self {
        Self::direct(DataRights::None, ExecuteRights::Neither)
    }

    pub const fn read_only(execute: ExecuteRights) -> Self {
        Self::direct(DataRights::Read, execute)
    }

    pub const fn read_write(execute: ExecuteRights) -> Self {
        Self::direct(DataRights::ReadWrite, execute)
    }

    pub const fn direct(data: DataRights, execute: ExecuteRights) -> Self {
        Self {
            data,
            execute,
            table_access: TableAccessPermissions {
                mmu: data,
                rcw: data,
                top_level: TopLevelRequirements::NONE,
            },
        }
    }

    pub const fn special_write_only() -> Self {
        Self {
            data: DataRights::Write,
            execute: ExecuteRights::Neither,
            table_access: TableAccessPermissions {
                mmu: DataRights::None,
                rcw: DataRights::None,
                top_level: TopLevelRequirements::NONE,
            },
        }
    }

    pub const fn mostly_read_only(top_level: TopLevelRequirements) -> Self {
        Self {
            data: DataRights::Read,
            execute: ExecuteRights::Neither,
            table_access: TableAccessPermissions {
                mmu: DataRights::ReadWrite,
                rcw: DataRights::ReadWrite,
                top_level,
            },
        }
    }

    pub const fn intersection(self, other: Self) -> Self {
        let mut result = Self {
            data: self.data.intersection(other.data),
            execute: self.execute.intersection(other.execute),
            table_access: TableAccessPermissions {
                mmu: self.table_access.mmu.intersection(other.table_access.mmu),
                rcw: self.table_access.rcw.intersection(other.table_access.rcw),
                top_level: TopLevelRequirements {
                    top_level0: self.table_access.top_level.top_level0
                        || other.table_access.top_level.top_level0,
                    top_level1: self.table_access.top_level.top_level1
                        || other.table_access.top_level.top_level1,
                },
            },
        };
        // Top-level qualifiers distinguish MRO encodings. Once intersection has reduced the
        // table-update rights, the result is an ordinary permission and carries no qualifier.
        if !matches!(result.data, DataRights::Read)
            || !matches!(result.table_access.mmu, DataRights::ReadWrite)
            || !matches!(result.table_access.rcw, DataRights::ReadWrite)
        {
            result.table_access.top_level = TopLevelRequirements::NONE;
        }
        result
    }
}
