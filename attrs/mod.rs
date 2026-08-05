mod pas;
mod permissions;
pub(crate) mod raw;
mod resolve;
mod semantic;

pub use pas::*;
pub use permissions::*;
pub(crate) use raw::*;
pub use resolve::{
    AttributeCodec, D128AliasConfig, LiveVmsaConfig, PasConfig, ShareabilityConfig,
    Stage1MemoryConfig, Stage1PermissionConfig, Stage1PermissionRegisterPair,
    Stage1PermissionRegisters, Stage2MemoryConfig, Stage2MemoryMode, Stage2PermissionConfig,
    Stage2PermissionRegisters,
};
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
    InvalidD128Alias,
    InvalidD128Configuration,
    ConflictingSemanticAttributes,
}
