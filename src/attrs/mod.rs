mod pas;
mod permissions;
pub(crate) mod raw;
mod resolve;
mod schema;
mod semantic;

pub(crate) use pas::{
    FixedNonSecurePas, FixedRealmIpaPas, NonSecureIpaContext, PasModel, RealmIpaContext,
    RealmOrNonSecurePaPas, RootExtendedPas, SecureIpaContext, SecureNonSecureIpaContext,
    SecureSelectablePas, Stage1PasModel, Stage2PasContext,
};
pub use pas::{RealmOrNonSecurePa, RootExtendedPa, SecureSelectablePa};
pub use permissions::{
    DataAccess, MostlyReadOnly, SinglePrivilegeTablePermissionLimits, Stage1EffectivePermissions,
    Stage2Permission, TwoPrivilegeTablePermissionLimits,
};
pub(crate) use permissions::{
    El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions, PrivilegeModel,
    Stage2PermissionModel,
};
pub(crate) use raw::*;
pub use resolve::{
    AttributeCodec, D128AliasConfig, LiveVmsaConfig, PasConfig, ShareabilityConfig,
    Stage1BasePermissions, Stage1MemoryConfig, Stage1PermissionConfig, Stage1PermissionOverlays,
    Stage1PermissionRegisters, Stage1PermissionSettings, Stage2BasePermissions, Stage2MemoryConfig,
    Stage2MemoryMode, Stage2PermissionConfig, Stage2PermissionRegisters, Stage2PermissionSettings,
};
pub use schema::{SemanticAttributeTypes, SemanticLeafAttrs, SemanticTableAttrs};
pub use semantic::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttrError {
    RawFieldOutOfRange,
    UnencodablePermissions,
    InvalidLeafAp(u8),
    InvalidTableAp(u8),
    InvalidStage2Permission(u8),
    InvalidStage2ExecuteNever,
    InvalidOutputAddressSpace,
    InvalidShareability,
    ShareabilityMismatch {
        requested: Shareability,
        effective: Shareability,
    },
    MemoryAttributeNotConfigured,
    Mair2Unavailable,
    UnencodableMemoryAttribute,
    WrongStage2MemoryMode,
    MtePermissionUnavailable,
    PermissionIndirectionUnavailable,
    PermissionCombinationNotConfigured,
    PermissionModeMismatch,
    InvalidD128Alias,
    InvalidD128Configuration,
    ConflictingSemanticAttributes,
}
