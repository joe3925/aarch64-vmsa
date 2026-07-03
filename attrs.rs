use crate::format::DescriptorFormat;
use crate::format::FormatFeatures;
use crate::granule::Level;
use crate::granule::TranslationGranule;
use crate::translation_regime::TranslationRegime;

#[repr(transparent)]
#[derive(Eq, PartialEq)]
pub struct EncodedLeafAttrs<F: DescriptorFormat> {
    raw: F::Raw,
}

impl<F: DescriptorFormat> Copy for EncodedLeafAttrs<F> {}

impl<F: DescriptorFormat> Clone for EncodedLeafAttrs<F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: DescriptorFormat> EncodedLeafAttrs<F> {
    pub const unsafe fn from_raw_unchecked(raw: F::Raw) -> Self {
        Self { raw }
    }

    pub const fn bits(self) -> F::Raw {
        self.raw
    }
}
#[repr(transparent)]
#[derive(Debug, Eq, PartialEq)]
pub struct EncodedTableAttrs<F: DescriptorFormat> {
    raw: F::Raw,
}

impl<F: DescriptorFormat> Copy for EncodedTableAttrs<F> {}

impl<F: DescriptorFormat> Clone for EncodedTableAttrs<F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: DescriptorFormat> EncodedTableAttrs<F> {
    pub const unsafe fn from_raw_unchecked(raw: F::Raw) -> Self {
        Self { raw }
    }

    pub const fn bits(self) -> F::Raw {
        self.raw
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttrError {
    InvalidForLevel { attr: AttrKind, level: Level },

    ConflictingAttributes { first: AttrKind, second: AttrKind },

    SoftwareBitsOutOfRange { requested: u64, allowed_mask: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttrKind {
    Memory,
    Access,
    Execute,
    Shareability,
    AccessFlag,
    Global,
    Dirty,
    Contiguous,
    Security,
    Software,
    TableAccessLimit,
    TableExecuteLimit,
}
pub trait RegimeFor<F, G>: TranslationRegime
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    type LeafAttrs;
    type TableAttrs;

    fn encode_leaf_attrs(
        attrs: Self::LeafAttrs,
        level: Level,
        features: FormatFeatures,
    ) -> Result<EncodedLeafAttrs<F>, AttrError>;

    fn encode_table_attrs(
        attrs: Self::TableAttrs,
        level: Level,
        features: FormatFeatures,
    ) -> Result<EncodedTableAttrs<F>, AttrError>;
}
