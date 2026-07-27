use crate::attrs::{
    AttrError, DataAccess, El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions,
    FourBit, LeafAp, PermissionIndices, PrivilegeModel, SinglePrivilegeLeafPermissions,
    SinglePrivilegeTablePermissionLimits, Stage1EffectivePermissions, TableAp,
    TwoPrivilegeLeafPermissions, TwoPrivilegeTablePermissionLimits,
};

use super::Stage1PermissionConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1PermissionRegisterPair {
    pub base: u64,
    pub overlay: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1PermissionRegisters {
    pub privileged: Stage1PermissionRegisterPair,
    pub unprivileged: Option<Stage1PermissionRegisterPair>,
    pub gcs_implemented: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1BasePermission {
    NoAccessApplyOverlay,
    ReadApplyOverlay,
    ExecuteApplyOverlay,
    ReadExecuteApplyOverlay,
    ReservedNoAccessApplyOverlay,
    ReadWriteApplyOverlay,
    ReadWriteExecuteApplyOverlayWithWxn,
    ReadWriteExecuteApplyOverlay,
    ReadNoOverlay,
    ReadGcsNoOverlay,
    ReadExecuteNoOverlay,
    ReservedNoAccessNoOverlay,
    ReadWriteNoOverlay,
    ReadWriteExecuteNoOverlay,
}

pub const STAGE1_BASE_DECODE: [Stage1BasePermission; 16] = [
    Stage1BasePermission::NoAccessApplyOverlay,
    Stage1BasePermission::ReadApplyOverlay,
    Stage1BasePermission::ExecuteApplyOverlay,
    Stage1BasePermission::ReadExecuteApplyOverlay,
    Stage1BasePermission::ReservedNoAccessApplyOverlay,
    Stage1BasePermission::ReadWriteApplyOverlay,
    Stage1BasePermission::ReadWriteExecuteApplyOverlayWithWxn,
    Stage1BasePermission::ReadWriteExecuteApplyOverlay,
    Stage1BasePermission::ReadNoOverlay,
    Stage1BasePermission::ReadGcsNoOverlay,
    Stage1BasePermission::ReadExecuteNoOverlay,
    Stage1BasePermission::ReservedNoAccessNoOverlay,
    Stage1BasePermission::ReadWriteNoOverlay,
    Stage1BasePermission::ReservedNoAccessNoOverlay,
    Stage1BasePermission::ReadWriteExecuteNoOverlay,
    Stage1BasePermission::ReservedNoAccessNoOverlay,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1OverlayPermission {
    NoAccess,
    Read,
    Execute,
    ReadExecute,
    Write,
    ReadWrite,
    WriteExecute,
    ReadWriteExecute,
    ReservedNoAccess,
}

pub const STAGE1_OVERLAY_DECODE: [Stage1OverlayPermission; 16] = [
    Stage1OverlayPermission::NoAccess,
    Stage1OverlayPermission::Read,
    Stage1OverlayPermission::Execute,
    Stage1OverlayPermission::ReadExecute,
    Stage1OverlayPermission::Write,
    Stage1OverlayPermission::ReadWrite,
    Stage1OverlayPermission::WriteExecute,
    Stage1OverlayPermission::ReadWriteExecute,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
];

pub fn encode_single_el_leaf_ap(access: DataAccess) -> Result<LeafAp, AttrError> {
    LeafAp::from_bits(match access {
        DataAccess::ReadWrite => 0b01,
        DataAccess::ReadOnly => 0b11,
        DataAccess::None => return Err(AttrError::UnencodablePermissions),
    })
}

pub fn decode_single_el_leaf_ap(ap: LeafAp) -> Result<DataAccess, AttrError> {
    match ap.bits() {
        0b01 => Ok(DataAccess::ReadWrite),
        0b11 => Ok(DataAccess::ReadOnly),
        bits => Err(AttrError::InvalidLeafAp(bits)),
    }
}

pub fn encode_two_privilege_leaf_ap(
    privileged: DataAccess,
    unprivileged: DataAccess,
) -> Result<LeafAp, AttrError> {
    LeafAp::from_bits(match (privileged, unprivileged) {
        (DataAccess::ReadWrite, DataAccess::None) => 0b00,
        (DataAccess::ReadWrite, DataAccess::ReadWrite) => 0b01,
        (DataAccess::ReadOnly, DataAccess::None) => 0b10,
        (DataAccess::ReadOnly, DataAccess::ReadOnly) => 0b11,
        _ => return Err(AttrError::UnencodablePermissions),
    })
}

pub fn decode_two_privilege_leaf_ap(ap: LeafAp) -> (DataAccess, DataAccess) {
    match ap.bits() {
        0b00 => (DataAccess::ReadWrite, DataAccess::None),
        0b01 => (DataAccess::ReadWrite, DataAccess::ReadWrite),
        0b10 => (DataAccess::ReadOnly, DataAccess::None),
        _ => (DataAccess::ReadOnly, DataAccess::ReadOnly),
    }
}

pub fn encode_single_privilege_table_ap(
    limits: SinglePrivilegeTablePermissionLimits,
) -> Result<TableAp, AttrError> {
    TableAp::from_bits(match limits.data_limit {
        DataAccess::ReadWrite => 0b00,
        DataAccess::ReadOnly => 0b10,
        DataAccess::None => return Err(AttrError::UnencodablePermissions),
    })
}

pub fn decode_single_privilege_table_ap(
    ap: TableAp,
    execute_limit: bool,
) -> Result<SinglePrivilegeTablePermissionLimits, AttrError> {
    let data_limit = match ap.bits() {
        0b00 => DataAccess::ReadWrite,
        0b10 => DataAccess::ReadOnly,
        bits => return Err(AttrError::InvalidTableAp(bits)),
    };
    Ok(SinglePrivilegeTablePermissionLimits {
        data_limit,
        execute_limit,
    })
}

pub fn encode_two_privilege_table_ap(
    limits: TwoPrivilegeTablePermissionLimits,
) -> Result<TableAp, AttrError> {
    TableAp::from_bits(
        match (limits.privileged_data_limit, limits.unprivileged_data_limit) {
            (DataAccess::ReadWrite, DataAccess::ReadWrite) => 0b00,
            (DataAccess::ReadWrite, DataAccess::None) => 0b01,
            (DataAccess::ReadOnly, DataAccess::ReadOnly) => 0b10,
            (DataAccess::ReadOnly, DataAccess::None) => 0b11,
            _ => return Err(AttrError::UnencodablePermissions),
        },
    )
}

pub fn decode_two_privilege_table_ap(
    ap: TableAp,
    privileged_execute_limit: bool,
    unprivileged_execute_limit: bool,
) -> TwoPrivilegeTablePermissionLimits {
    let (privileged_data_limit, unprivileged_data_limit) = match ap.bits() {
        0b00 => (DataAccess::ReadWrite, DataAccess::ReadWrite),
        0b01 => (DataAccess::ReadWrite, DataAccess::None),
        0b10 => (DataAccess::ReadOnly, DataAccess::ReadOnly),
        _ => (DataAccess::ReadOnly, DataAccess::None),
    };
    TwoPrivilegeTablePermissionLimits {
        privileged_data_limit,
        unprivileged_data_limit,
        privileged_execute_limit,
        unprivileged_execute_limit,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawStage1DirectLeafPermissions {
    pub ap: LeafAp,
    pub privileged_execute_never: bool,
    pub unprivileged_execute_never: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawStage1TablePermissionLimits {
    pub ap_table: TableAp,
    pub privileged_execute_never_limit: bool,
    pub unprivileged_execute_never_limit: bool,
}

pub trait Stage1DirectPermissionModel: PrivilegeModel {
    fn encode_leaf(
        permissions: Self::LeafPermissions,
    ) -> Result<RawStage1DirectLeafPermissions, AttrError>;

    fn decode_leaf(raw: RawStage1DirectLeafPermissions)
    -> Result<Self::LeafPermissions, AttrError>;

    fn encode_table(
        limits: Self::TablePermissionLimits,
    ) -> Result<RawStage1TablePermissionLimits, AttrError>;

    fn decode_table(
        raw: RawStage1TablePermissionLimits,
    ) -> Result<Self::TablePermissionLimits, AttrError>;
}

macro_rules! single_privilege_model {
    ($model:ty) => {
        impl Stage1DirectPermissionModel for $model {
            fn encode_leaf(
                value: Self::LeafPermissions,
            ) -> Result<RawStage1DirectLeafPermissions, AttrError> {
                Ok(RawStage1DirectLeafPermissions {
                    ap: encode_single_el_leaf_ap(value.data)?,
                    privileged_execute_never: false,
                    unprivileged_execute_never: !value.execute,
                })
            }

            fn decode_leaf(
                raw: RawStage1DirectLeafPermissions,
            ) -> Result<Self::LeafPermissions, AttrError> {
                if raw.privileged_execute_never {
                    return Err(AttrError::UnencodablePermissions);
                }
                Ok(SinglePrivilegeLeafPermissions {
                    data: decode_single_el_leaf_ap(raw.ap)?,
                    execute: !raw.unprivileged_execute_never,
                })
            }

            fn encode_table(
                value: Self::TablePermissionLimits,
            ) -> Result<RawStage1TablePermissionLimits, AttrError> {
                Ok(RawStage1TablePermissionLimits {
                    ap_table: encode_single_privilege_table_ap(value)?,
                    privileged_execute_never_limit: false,
                    unprivileged_execute_never_limit: !value.execute_limit,
                })
            }

            fn decode_table(
                raw: RawStage1TablePermissionLimits,
            ) -> Result<Self::TablePermissionLimits, AttrError> {
                if raw.privileged_execute_never_limit {
                    return Err(AttrError::UnencodablePermissions);
                }
                decode_single_privilege_table_ap(
                    raw.ap_table,
                    !raw.unprivileged_execute_never_limit,
                )
            }
        }
    };
}

single_privilege_model!(El2Permissions);
single_privilege_model!(El3Permissions);

macro_rules! two_privilege_model {
    ($model:ty) => {
        impl Stage1DirectPermissionModel for $model {
            fn encode_leaf(
                value: Self::LeafPermissions,
            ) -> Result<RawStage1DirectLeafPermissions, AttrError> {
                Ok(RawStage1DirectLeafPermissions {
                    ap: encode_two_privilege_leaf_ap(
                        value.privileged_data,
                        value.unprivileged_data,
                    )?,
                    privileged_execute_never: !value.privileged_execute,
                    unprivileged_execute_never: !value.unprivileged_execute,
                })
            }

            fn decode_leaf(
                raw: RawStage1DirectLeafPermissions,
            ) -> Result<Self::LeafPermissions, AttrError> {
                let (privileged_data, unprivileged_data) = decode_two_privilege_leaf_ap(raw.ap);
                Ok(TwoPrivilegeLeafPermissions {
                    privileged_data,
                    unprivileged_data,
                    privileged_execute: !raw.privileged_execute_never,
                    unprivileged_execute: !raw.unprivileged_execute_never,
                })
            }

            fn encode_table(
                value: Self::TablePermissionLimits,
            ) -> Result<RawStage1TablePermissionLimits, AttrError> {
                Ok(RawStage1TablePermissionLimits {
                    ap_table: encode_two_privilege_table_ap(value)?,
                    privileged_execute_never_limit: !value.privileged_execute_limit,
                    unprivileged_execute_never_limit: !value.unprivileged_execute_limit,
                })
            }

            fn decode_table(
                raw: RawStage1TablePermissionLimits,
            ) -> Result<Self::TablePermissionLimits, AttrError> {
                Ok(decode_two_privilege_table_ap(
                    raw.ap_table,
                    !raw.privileged_execute_never_limit,
                    !raw.unprivileged_execute_never_limit,
                ))
            }
        }
    };
}

two_privilege_model!(El1And0Permissions);
two_privilege_model!(El2And0Permissions);
