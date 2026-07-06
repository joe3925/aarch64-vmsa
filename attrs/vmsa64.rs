use super::{DirtyBitManagement, Shareability, SoftwareDefinedBits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Stage1LeafControls {
    pub shareability: Shareability,
    pub access_flag: bool,
    pub global: bool,
    pub dirty_management: DirtyBitManagement,
    pub contiguous: bool,
    pub guarded: bool,
    pub software: SoftwareDefinedBits,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Vmsa64Stage1TableControls {
    pub software: SoftwareDefinedBits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Stage2LeafControls {
    pub shareability: Shareability,
    pub access_flag: bool,
    pub dirty_management: DirtyBitManagement,
    pub contiguous: bool,
    pub software: SoftwareDefinedBits,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Vmsa64Stage2TableControls {
    pub software: SoftwareDefinedBits,
}
