use crate::attrs::{
    AttrError, AttributeResolver, DataAccess, El1And0Permissions, El2And0Permissions,
    El2Permissions, El3Permissions, FixedNonSecurePas, LiveAttributeConfiguration,
    NonSecureIpaContext, OutputAddressSpace, PermissionModel, RealmIpaContext, RealmPas, RootPas,
    SecureIpaContext, SecureNonSecureIpaContext, SecureSelectablePas,
    SinglePrivilegeLeafPermissions, SinglePrivilegeTablePermissions, Stage1PasModel,
    Stage2LeafPermissions, Stage2PasContext, Stage2PermissionModel, Stage2Permissions,
    Stage2TablePermissions, Stage2XnxPermissions, TwoPrivilegeLeafPermissions,
    TwoPrivilegeTablePermissions,
};
use crate::descriptor::RawFieldBlock;

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

#[derive(Clone, Copy)]
pub(super) struct Stage2LeafPermissionBits {
    pub(super) s2ap: u128,
    pub(super) xn: u128,
}

pub(super) trait Stage2PermissionCodec: Stage2PermissionModel {
    const SUPPORTS_XNX: bool;

    fn encode_leaf_permissions(
        permissions: Self::LeafPermissions,
    ) -> Result<Stage2LeafPermissionBits, AttrError> {
        Ok(Stage2LeafPermissionBits {
            s2ap: encode_stage2_data(permissions.data)?,
            xn: encode_stage2_execute(
                permissions.privileged_execute,
                permissions.unprivileged_execute,
                Self::SUPPORTS_XNX,
            )?,
        })
    }

    fn decode_leaf_permissions(s2ap: u128, xn: u128) -> Result<Self::LeafPermissions, AttrError> {
        let (privileged_execute, unprivileged_execute) =
            decode_stage2_execute(xn, Self::SUPPORTS_XNX)?;
        Ok(Stage2LeafPermissions {
            data: decode_stage2_data(s2ap)?,
            privileged_execute,
            unprivileged_execute,
        })
    }

    fn require_unrestricted_table(permissions: Self::TablePermissions) -> Result<(), AttrError> {
        if permissions == Self::unrestricted_table_permissions() {
            Ok(())
        } else {
            Err(AttrError::UnencodablePermissions)
        }
    }

    fn unrestricted_table_permissions() -> Self::TablePermissions {
        Stage2TablePermissions {
            data_limit: DataAccess::ReadWrite,
            privileged_execute: true,
            unprivileged_execute: true,
        }
    }
}

pub(super) trait Stage2PasCodec: Stage2PasContext {
    const USES_DESCRIPTOR_NS: bool;

    fn encode_leaf_output_address_space<C>(
        resolver: &AttributeResolver<C>,
        space: Self::OutputAddressSpaceAttr,
    ) -> Result<bool, AttrError>
    where
        C: LiveAttributeConfiguration;

    fn decode_leaf_output_address_space<C>(
        resolver: &AttributeResolver<C>,
        non_secure: bool,
    ) -> Self::OutputAddressSpaceAttr
    where
        C: LiveAttributeConfiguration;

    fn encode_table_address_space<C>(
        resolver: &AttributeResolver<C>,
        space: Self::OutputAddressSpaceAttr,
    ) -> Result<bool, AttrError>
    where
        C: LiveAttributeConfiguration,
    {
        Self::encode_leaf_output_address_space(resolver, space)
    }

    fn decode_table_address_space<C>(
        resolver: &AttributeResolver<C>,
        non_secure: bool,
    ) -> Self::OutputAddressSpaceAttr
    where
        C: LiveAttributeConfiguration,
    {
        Self::decode_leaf_output_address_space(resolver, non_secure)
    }
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

impl Stage2PermissionCodec for Stage2Permissions {
    const SUPPORTS_XNX: bool = false;
}

impl Stage2PermissionCodec for Stage2XnxPermissions {
    const SUPPORTS_XNX: bool = true;
}

impl Stage2PasCodec for NonSecureIpaContext {
    const USES_DESCRIPTOR_NS: bool = false;

    fn encode_leaf_output_address_space<C>(
        _resolver: &AttributeResolver<C>,
        _space: Self::OutputAddressSpaceAttr,
    ) -> Result<bool, AttrError>
    where
        C: LiveAttributeConfiguration,
    {
        Ok(false)
    }

    fn decode_leaf_output_address_space<C>(
        _resolver: &AttributeResolver<C>,
        _non_secure: bool,
    ) -> Self::OutputAddressSpaceAttr
    where
        C: LiveAttributeConfiguration,
    {
    }
}

impl Stage2PasCodec for SecureIpaContext {
    const USES_DESCRIPTOR_NS: bool = false;

    fn encode_leaf_output_address_space<C>(
        resolver: &AttributeResolver<C>,
        space: Self::OutputAddressSpaceAttr,
    ) -> Result<bool, AttrError>
    where
        C: LiveAttributeConfiguration,
    {
        encode_secure_stage2_output_address_space(resolver, space)
    }

    fn decode_leaf_output_address_space<C>(
        resolver: &AttributeResolver<C>,
        _non_secure: bool,
    ) -> Self::OutputAddressSpaceAttr
    where
        C: LiveAttributeConfiguration,
    {
        resolver.configuration().output_address_space()
    }
}

impl Stage2PasCodec for SecureNonSecureIpaContext {
    const USES_DESCRIPTOR_NS: bool = false;

    fn encode_leaf_output_address_space<C>(
        resolver: &AttributeResolver<C>,
        space: Self::OutputAddressSpaceAttr,
    ) -> Result<bool, AttrError>
    where
        C: LiveAttributeConfiguration,
    {
        encode_secure_stage2_output_address_space(resolver, space)
    }

    fn decode_leaf_output_address_space<C>(
        resolver: &AttributeResolver<C>,
        _non_secure: bool,
    ) -> Self::OutputAddressSpaceAttr
    where
        C: LiveAttributeConfiguration,
    {
        resolver.configuration().output_address_space()
    }
}

impl Stage2PasCodec for RealmIpaContext {
    const USES_DESCRIPTOR_NS: bool = true;

    fn encode_leaf_output_address_space<C>(
        _resolver: &AttributeResolver<C>,
        space: Self::OutputAddressSpaceAttr,
    ) -> Result<bool, AttrError>
    where
        C: LiveAttributeConfiguration,
    {
        encode_regime_or_non_secure_pas(space, OutputAddressSpace::Realm)
    }

    fn decode_leaf_output_address_space<C>(
        _resolver: &AttributeResolver<C>,
        non_secure: bool,
    ) -> Self::OutputAddressSpaceAttr
    where
        C: LiveAttributeConfiguration,
    {
        decode_regime_or_non_secure_pas(non_secure, OutputAddressSpace::Realm)
    }

    fn encode_table_address_space<C>(
        _resolver: &AttributeResolver<C>,
        space: Self::OutputAddressSpaceAttr,
    ) -> Result<bool, AttrError>
    where
        C: LiveAttributeConfiguration,
    {
        if space == OutputAddressSpace::Realm {
            Ok(false)
        } else {
            Err(AttrError::InvalidOutputAddressSpace)
        }
    }

    fn decode_table_address_space<C>(
        _resolver: &AttributeResolver<C>,
        _non_secure: bool,
    ) -> Self::OutputAddressSpaceAttr
    where
        C: LiveAttributeConfiguration,
    {
        OutputAddressSpace::Realm
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

fn encode_secure_stage2_output_address_space<C>(
    resolver: &AttributeResolver<C>,
    space: OutputAddressSpace,
) -> Result<bool, AttrError>
where
    C: LiveAttributeConfiguration,
{
    let configured = resolver.configuration().output_address_space();
    if !matches!(
        configured,
        OutputAddressSpace::Secure | OutputAddressSpace::NonSecure
    ) || space != configured
    {
        return Err(AttrError::InvalidOutputAddressSpace);
    }

    Ok(false)
}

fn encode_stage2_execute(
    privileged_execute: bool,
    unprivileged_execute: bool,
    supports_xnx: bool,
) -> Result<u128, AttrError> {
    if supports_xnx {
        return Ok(match (privileged_execute, unprivileged_execute) {
            (true, true) => 0b00,
            (false, true) => 0b01,
            (false, false) => 0b10,
            (true, false) => 0b11,
        });
    }

    if privileged_execute != unprivileged_execute {
        return Err(AttrError::UnencodablePermissions);
    }

    Ok(if privileged_execute { 0b00 } else { 0b10 })
}

fn decode_stage2_execute(xn: u128, supports_xnx: bool) -> Result<(bool, bool), AttrError> {
    let xn = xn & 0b11;

    if !supports_xnx && xn & 0b01 != 0 {
        return Err(AttrError::InvalidStage2ExecuteNever);
    }

    Ok(if supports_xnx {
        match xn {
            0b00 => (true, true),
            0b01 => (false, true),
            0b10 => (false, false),
            _ => (true, false),
        }
    } else {
        let execute = xn & 0b10 == 0;
        (execute, execute)
    })
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
