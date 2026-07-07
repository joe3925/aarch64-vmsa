use crate::attrs::{
    AttrError, DataAccess, El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions,
    FixedNonSecurePas, OutputAddressSpace, PermissionModel, RealmPas, RootPas, SecureSelectablePas,
    SinglePrivilegeLeafPermissions, SinglePrivilegeTablePermissions, Stage1PasModel,
    Stage2TablePermissions, TwoPrivilegeLeafPermissions, TwoPrivilegeTablePermissions,
};
use crate::layout::RawFieldBlock;

#[derive(Clone, Copy)]
pub(super) struct LeafPermissionBits {
    pub(super) ap: u128,
    pub(super) pxn: bool,
    pub(super) uxn: bool,
}

#[derive(Clone, Copy)]
pub(super) struct TablePermissionBits {
    pub(super) ap_table: u128,
    pub(super) pxn_table: bool,
    pub(super) uxn_table: bool,
}

pub(super) trait Stage1PermissionCodec: PermissionModel {
    fn encode_leaf_permissions(
        permissions: Self::LeafPermissions,
    ) -> Result<LeafPermissionBits, AttrError>;

    fn decode_leaf_permissions(
        lower: RawFieldBlock<10>,
        upper: RawFieldBlock<3>,
    ) -> Self::LeafPermissions;

    fn encode_table_permissions(
        permissions: Self::TablePermissions,
    ) -> Result<TablePermissionBits, AttrError>;

    fn decode_table_permissions(upper: RawFieldBlock<5>) -> Self::TablePermissions;
}

pub(super) trait Stage1PasCodec: Stage1PasModel {
    const USES_NSE: bool;

    fn encode_leaf_pas(pas: Self::LeafAttr) -> Result<(bool, bool), AttrError>;
    fn decode_leaf_pas(non_secure: bool, nse: bool) -> Self::LeafAttr;
    fn encode_table_pas(pas: Self::TableAttr) -> Result<bool, AttrError>;
    fn decode_table_pas(non_secure: bool) -> Self::TableAttr;
}

macro_rules! impl_two_privilege_codec {
    ($model:ty) => {
        impl Stage1PermissionCodec for $model {
            fn encode_leaf_permissions(
                permissions: Self::LeafPermissions,
            ) -> Result<LeafPermissionBits, AttrError> {
                encode_two_privilege_leaf_permissions(permissions)
            }

            fn decode_leaf_permissions(
                lower: RawFieldBlock<10>,
                upper: RawFieldBlock<3>,
            ) -> Self::LeafPermissions {
                decode_two_privilege_leaf_permissions(lower, upper)
            }

            fn encode_table_permissions(
                permissions: Self::TablePermissions,
            ) -> Result<TablePermissionBits, AttrError> {
                encode_two_privilege_table_permissions(permissions)
            }

            fn decode_table_permissions(upper: RawFieldBlock<5>) -> Self::TablePermissions {
                decode_two_privilege_table_permissions(upper)
            }
        }
    };
}

impl_two_privilege_codec!(El1And0Permissions);
impl_two_privilege_codec!(El2And0Permissions);

macro_rules! impl_single_privilege_codec {
    ($model:ty) => {
        impl Stage1PermissionCodec for $model {
            fn encode_leaf_permissions(
                permissions: Self::LeafPermissions,
            ) -> Result<LeafPermissionBits, AttrError> {
                encode_single_privilege_leaf_permissions(permissions)
            }

            fn decode_leaf_permissions(
                lower: RawFieldBlock<10>,
                upper: RawFieldBlock<3>,
            ) -> Self::LeafPermissions {
                decode_single_privilege_leaf_permissions(lower, upper)
            }

            fn encode_table_permissions(
                permissions: Self::TablePermissions,
            ) -> Result<TablePermissionBits, AttrError> {
                encode_single_privilege_table_permissions(permissions)
            }

            fn decode_table_permissions(upper: RawFieldBlock<5>) -> Self::TablePermissions {
                decode_single_privilege_table_permissions(upper)
            }
        }
    };
}

impl_single_privilege_codec!(El2Permissions);
impl_single_privilege_codec!(El3Permissions);

impl Stage1PasCodec for FixedNonSecurePas {
    const USES_NSE: bool = false;

    fn encode_leaf_pas(_pas: Self::LeafAttr) -> Result<(bool, bool), AttrError> {
        Ok((false, false))
    }

    fn decode_leaf_pas(_non_secure: bool, _nse: bool) -> Self::LeafAttr {}

    fn encode_table_pas(_pas: Self::TableAttr) -> Result<bool, AttrError> {
        Ok(false)
    }

    fn decode_table_pas(_non_secure: bool) -> Self::TableAttr {}
}

impl Stage1PasCodec for SecureSelectablePas {
    const USES_NSE: bool = false;

    fn encode_leaf_pas(pas: Self::LeafAttr) -> Result<(bool, bool), AttrError> {
        Ok((encode_secure_pas(pas)?, false))
    }

    fn decode_leaf_pas(non_secure: bool, _nse: bool) -> Self::LeafAttr {
        decode_secure_pas(non_secure)
    }

    fn encode_table_pas(pas: Self::TableAttr) -> Result<bool, AttrError> {
        encode_secure_pas(pas)
    }

    fn decode_table_pas(non_secure: bool) -> Self::TableAttr {
        decode_secure_pas(non_secure)
    }
}

impl Stage1PasCodec for RealmPas {
    const USES_NSE: bool = true;

    fn encode_leaf_pas(pas: Self::LeafAttr) -> Result<(bool, bool), AttrError> {
        Ok(encode_extended_pas(pas))
    }

    fn decode_leaf_pas(non_secure: bool, nse: bool) -> Self::LeafAttr {
        decode_extended_pas(non_secure, nse)
    }

    fn encode_table_pas(pas: Self::TableAttr) -> Result<bool, AttrError> {
        encode_regime_or_non_secure_pas(pas, OutputAddressSpace::Realm)
    }

    fn decode_table_pas(non_secure: bool) -> Self::TableAttr {
        decode_regime_or_non_secure_pas(non_secure, OutputAddressSpace::Realm)
    }
}

impl Stage1PasCodec for RootPas {
    const USES_NSE: bool = true;

    fn encode_leaf_pas(pas: Self::LeafAttr) -> Result<(bool, bool), AttrError> {
        Ok(encode_extended_pas(pas))
    }

    fn decode_leaf_pas(non_secure: bool, nse: bool) -> Self::LeafAttr {
        decode_extended_pas(non_secure, nse)
    }

    fn encode_table_pas(pas: Self::TableAttr) -> Result<bool, AttrError> {
        encode_regime_or_non_secure_pas(pas, OutputAddressSpace::Root)
    }

    fn decode_table_pas(non_secure: bool) -> Self::TableAttr {
        decode_regime_or_non_secure_pas(non_secure, OutputAddressSpace::Root)
    }
}

fn encode_two_privilege_leaf_permissions(
    permissions: TwoPrivilegeLeafPermissions,
) -> Result<LeafPermissionBits, AttrError> {
    let ap = encode_two_privilege_data(permissions.privileged_data, permissions.unprivileged_data)?;
    Ok(LeafPermissionBits {
        ap,
        pxn: !permissions.privileged_execute,
        uxn: !permissions.unprivileged_execute,
    })
}

fn decode_two_privilege_leaf_permissions(
    lower: RawFieldBlock<10>,
    upper: RawFieldBlock<3>,
) -> TwoPrivilegeLeafPermissions {
    let (privileged_data, unprivileged_data) = decode_two_privilege_data(lower.bits() >> 4);
    TwoPrivilegeLeafPermissions {
        privileged_data,
        unprivileged_data,
        privileged_execute: upper.bits() & (1 << 1) == 0,
        unprivileged_execute: upper.bits() & (1 << 2) == 0,
    }
}

fn encode_two_privilege_table_permissions(
    permissions: TwoPrivilegeTablePermissions,
) -> Result<TablePermissionBits, AttrError> {
    let ap_table = encode_two_privilege_data(
        permissions.privileged_data_limit,
        permissions.unprivileged_data_limit,
    )?;
    Ok(TablePermissionBits {
        ap_table,
        pxn_table: !permissions.privileged_execute,
        uxn_table: !permissions.unprivileged_execute,
    })
}

fn decode_two_privilege_table_permissions(upper: RawFieldBlock<5>) -> TwoPrivilegeTablePermissions {
    let (privileged_data_limit, unprivileged_data_limit) =
        decode_two_privilege_data(upper.bits() >> 2);
    TwoPrivilegeTablePermissions {
        privileged_data_limit,
        unprivileged_data_limit,
        privileged_execute: upper.bits() & 1 == 0,
        unprivileged_execute: upper.bits() & (1 << 1) == 0,
    }
}

fn encode_two_privilege_data(
    privileged: DataAccess,
    unprivileged: DataAccess,
) -> Result<u128, AttrError> {
    match (privileged, unprivileged) {
        (DataAccess::ReadWrite, DataAccess::None) => Ok(0b00),
        (DataAccess::ReadWrite, DataAccess::ReadWrite) => Ok(0b01),
        (DataAccess::ReadOnly, DataAccess::None) => Ok(0b10),
        (DataAccess::ReadOnly, DataAccess::ReadOnly) => Ok(0b11),
        _ => Err(AttrError::UnencodablePermissions),
    }
}

fn decode_two_privilege_data(ap: u128) -> (DataAccess, DataAccess) {
    match ap & 0b11 {
        0b00 => (DataAccess::ReadWrite, DataAccess::None),
        0b01 => (DataAccess::ReadWrite, DataAccess::ReadWrite),
        0b10 => (DataAccess::ReadOnly, DataAccess::None),
        _ => (DataAccess::ReadOnly, DataAccess::ReadOnly),
    }
}

fn encode_single_privilege_leaf_permissions(
    permissions: SinglePrivilegeLeafPermissions,
) -> Result<LeafPermissionBits, AttrError> {
    Ok(LeafPermissionBits {
        ap: encode_single_privilege_data(permissions.data)?,
        pxn: false,
        uxn: !permissions.execute,
    })
}

fn decode_single_privilege_leaf_permissions(
    lower: RawFieldBlock<10>,
    upper: RawFieldBlock<3>,
) -> SinglePrivilegeLeafPermissions {
    SinglePrivilegeLeafPermissions {
        data: decode_single_privilege_data(lower.bits() >> 4),
        execute: upper.bits() & (1 << 2) == 0,
    }
}

fn encode_single_privilege_table_permissions(
    permissions: SinglePrivilegeTablePermissions,
) -> Result<TablePermissionBits, AttrError> {
    Ok(TablePermissionBits {
        ap_table: encode_single_privilege_data(permissions.data_limit)?,
        pxn_table: false,
        uxn_table: !permissions.execute,
    })
}

fn decode_single_privilege_table_permissions(
    upper: RawFieldBlock<5>,
) -> SinglePrivilegeTablePermissions {
    SinglePrivilegeTablePermissions {
        data_limit: decode_single_privilege_data(upper.bits() >> 2),
        execute: upper.bits() & (1 << 1) == 0,
    }
}

fn encode_single_privilege_data(access: DataAccess) -> Result<u128, AttrError> {
    match access {
        DataAccess::ReadWrite => Ok(0b00),
        DataAccess::ReadOnly => Ok(0b10),
        DataAccess::None => Err(AttrError::UnencodablePermissions),
    }
}

fn decode_single_privilege_data(ap: u128) -> DataAccess {
    if ap & 0b10 == 0 {
        DataAccess::ReadWrite
    } else {
        DataAccess::ReadOnly
    }
}

fn encode_secure_pas(pas: OutputAddressSpace) -> Result<bool, AttrError> {
    match pas {
        OutputAddressSpace::Secure => Ok(false),
        OutputAddressSpace::NonSecure => Ok(true),
        OutputAddressSpace::Realm | OutputAddressSpace::Root => {
            Err(AttrError::InvalidOutputAddressSpace)
        }
    }
}

const fn decode_secure_pas(non_secure: bool) -> OutputAddressSpace {
    if non_secure {
        OutputAddressSpace::NonSecure
    } else {
        OutputAddressSpace::Secure
    }
}

const fn encode_extended_pas(pas: OutputAddressSpace) -> (bool, bool) {
    match pas {
        OutputAddressSpace::Secure => (false, false),
        OutputAddressSpace::NonSecure => (true, false),
        OutputAddressSpace::Root => (false, true),
        OutputAddressSpace::Realm => (true, true),
    }
}

const fn decode_extended_pas(non_secure: bool, nse: bool) -> OutputAddressSpace {
    match (non_secure, nse) {
        (false, false) => OutputAddressSpace::Secure,
        (true, false) => OutputAddressSpace::NonSecure,
        (false, true) => OutputAddressSpace::Root,
        (true, true) => OutputAddressSpace::Realm,
    }
}

fn encode_regime_or_non_secure_pas(
    pas: OutputAddressSpace,
    regime: OutputAddressSpace,
) -> Result<bool, AttrError> {
    if pas == regime {
        Ok(false)
    } else if pas == OutputAddressSpace::NonSecure {
        Ok(true)
    } else {
        Err(AttrError::InvalidOutputAddressSpace)
    }
}

const fn decode_regime_or_non_secure_pas(
    non_secure: bool,
    regime: OutputAddressSpace,
) -> OutputAddressSpace {
    if non_secure {
        OutputAddressSpace::NonSecure
    } else {
        regime
    }
}

pub(super) fn encode_stage2_data(access: DataAccess) -> Result<u128, AttrError> {
    match access {
        DataAccess::None => Ok(0b00),
        DataAccess::ReadOnly => Ok(0b01),
        DataAccess::ReadWrite => Ok(0b11),
    }
}

pub(super) fn decode_stage2_data(bits: u128) -> Result<DataAccess, AttrError> {
    match bits & 0b11 {
        0b00 => Ok(DataAccess::None),
        0b01 => Ok(DataAccess::ReadOnly),
        0b11 => Ok(DataAccess::ReadWrite),
        _ => Err(AttrError::UnencodablePermissions),
    }
}

pub(super) fn require_unrestricted_stage2_table(
    permissions: Stage2TablePermissions,
) -> Result<(), AttrError> {
    if permissions == unrestricted_stage2_table_permissions() {
        Ok(())
    } else {
        Err(AttrError::UnencodablePermissions)
    }
}

pub(super) const fn unrestricted_stage2_table_permissions() -> Stage2TablePermissions {
    Stage2TablePermissions {
        data_limit: DataAccess::ReadWrite,
        privileged_execute: true,
        unprivileged_execute: true,
    }
}
