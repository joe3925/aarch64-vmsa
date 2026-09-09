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
    DataRights, ExecuteRights, PrivilegePair, SinglePrivilegeTableRestrictions, Stage1Permissions,
    Stage2Permissions, TableAccessPermissions, TopLevelRequirements, TwoPrivilegeTableRestrictions,
};
pub(crate) use permissions::{
    El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions, PrivilegeModel,
    SmmuPrivilegedStreamPermissions, SmmuStreamPermissions, Stage2PermissionModel,
};
pub(crate) use raw::*;
pub use resolve::{
    AttributeCodec, D128AliasConfig, LiveVmsaConfig, PasConfig, PeStage1PermissionCodec,
    PeStage2PermissionCodec, PermissionCodec, RawStage1DirectLeafPermissions, ShareabilityConfig,
    SmmuV2Stage1PermissionCodec, SmmuV2Stage2PermissionCodec, SmmuV3Stage1PermissionCodec,
    SmmuV3Stage2PermissionCodec, Stage1BasePermissions, Stage1DirectEncoding, Stage1MemoryConfig,
    Stage1PermissionCodec, Stage1PermissionConfig, Stage1PermissionEncoding,
    Stage1PermissionOverlays, Stage1PermissionRegisters, Stage1PermissionSettings,
    Stage2BasePermissions, Stage2DirectEncoding, Stage2MemoryConfig, Stage2MemoryMode,
    Stage2PermissionCodec, Stage2PermissionConfig, Stage2PermissionEncoding,
    Stage2PermissionRegisters, Stage2PermissionSettings,
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
    InvalidSmmuV2AllocationHint,
    ConflictingSemanticAttributes,
}
