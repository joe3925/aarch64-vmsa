use super::{Stage1NotDirty, Stage2Dirty};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Shareability {
    NonShareable = 0b00,
    OuterShareable = 0b10,
    InnerShareable = 0b11,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DeviceMemoryType {
    NonGatheringNonReorderingNoEarlyAck,
    NonGatheringNonReorderingEarlyAck,
    NonGatheringReorderingEarlyAck,
    GatheringReorderingEarlyAck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CachePolicy {
    WriteThrough,
    WriteBack,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AllocationHints {
    None,
    WriteAllocate,
    ReadAllocate,
    ReadWriteAllocate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum MemoryTransience {
    Transient,
    NonTransient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Cacheability {
    NonCacheable,
    Cacheable {
        policy: CachePolicy,
        transience: MemoryTransience,
        allocation: AllocationHints,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum MemoryAttributes {
    Device(DeviceMemoryType),
    Normal {
        inner: Cacheability,
        outer: Cacheability,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FwbStage2Memory {
    Device(DeviceMemoryType),
    ForceNormalNonCacheable,
    ForceNormalWriteBack,
    UseStage1,
    ForceNormalWriteBackNoTagAccess,
    UseStage1NoTagAccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Stage2MemoryAttributes {
    Combined(MemoryAttributes),
    Fwb(FwbStage2Memory),
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SoftwareMetadata(u16);

impl SoftwareMetadata {
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum D128Stage1AliasKind {
    NonGlobal,
    NonSecureExtension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DirtyState {
    Dirty,
    Clean,
}

impl From<DirtyState> for Stage1NotDirty {
    fn from(value: DirtyState) -> Self {
        Stage1NotDirty::new(matches!(value, DirtyState::Clean))
    }
}

impl From<Stage1NotDirty> for DirtyState {
    fn from(value: Stage1NotDirty) -> Self {
        if value.bit() {
            Self::Clean
        } else {
            Self::Dirty
        }
    }
}

impl From<DirtyState> for Stage2Dirty {
    fn from(value: DirtyState) -> Self {
        Stage2Dirty::new(matches!(value, DirtyState::Dirty))
    }
}

impl From<Stage2Dirty> for DirtyState {
    fn from(value: Stage2Dirty) -> Self {
        if value.bit() {
            Self::Dirty
        } else {
            Self::Clean
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DirtyBitManagement {
    SoftwareManaged,
    HardwareManaged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticStage1LeafAttrs<P, Pas, C> {
    pub memory: MemoryAttributes,
    pub permissions: P,
    pub pas: Pas,
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedStage1LeafAttrs<M, P, Pas, C> {
    pub memory: M,
    pub permissions: P,
    pub pas: Pas,
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticStage1TableAttrs<P, Pas, C> {
    pub permission_limits: P,
    pub pas: Pas,
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedStage1TableAttrs<P, Pas, C> {
    pub permission_limits: P,
    pub pas: Pas,
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticStage2LeafAttrs<P, Pas, C> {
    pub memory: Stage2MemoryAttributes,
    pub permissions: P,
    pub output_address_space: Pas,
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedStage2LeafAttrs<M, P, Pas, C> {
    pub memory: M,
    pub permissions: P,
    pub output_address_space: Pas,
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticStage2TableAttrs<C> {
    pub controls: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticVmsa64Stage1LeafControls {
    pub shareability: Shareability,
    pub access_flag: bool,
    pub global: bool,
    pub dirty_management: DirtyBitManagement,
    pub contiguous: bool,
    pub guarded: bool,
    pub software: SoftwareMetadata,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SemanticVmsa64Stage1TableControls {
    pub software: SoftwareMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticVmsa64Stage2LeafControls {
    pub shareability: Shareability,
    pub access_flag: bool,
    pub dirty_management: DirtyBitManagement,
    pub contiguous: bool,
    pub software: SoftwareMetadata,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SemanticVmsa64Stage2TableAttrs {
    pub software: SoftwareMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticVmsa128Stage1LeafControls {
    pub bbm_nt: bool,
    pub dirty_state: DirtyState,
    pub shareability: Shareability,
    pub access_flag: bool,
    pub global: bool,
    pub contiguous: bool,
    pub guarded: bool,
    pub protected: bool,
    pub software: SoftwareMetadata,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SemanticVmsa128Stage1TableAttrs<Pas = ()> {
    pub table_nt: bool,
    pub access_flag: bool,
    pub disch: bool,
    pub protected: bool,
    pub pas: Pas,
    pub software: SoftwareMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticVmsa128Stage2LeafControls {
    pub bbm_nt: bool,
    pub dirty_state: DirtyState,
    pub shareability: Shareability,
    pub access_flag: bool,
    pub force_no_execute: bool,
    pub contiguous: bool,
    pub assured_only: bool,
    pub software: SoftwareMetadata,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SemanticVmsa128Stage2TableAttrs {
    pub table_nt: bool,
    pub access_flag: bool,
    pub software: SoftwareMetadata,
}
