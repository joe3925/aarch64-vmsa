use crate::address::{Level, PhysAddr, TranslationGranule};
use crate::descriptor::{DescriptorFormat, HasLayout};
use crate::regime::{LeafFieldsOf, StageOf, TranslationRegime};
use crate::translation::walk::{WalkInputAddr, WalkLeafKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapLeafOutcome {
    pub(super) tables_allocated: u8,
    pub(super) level: Level,
    pub(super) kind: WalkLeafKind,
    pub(super) covered_size: u64,
}

impl MapLeafOutcome {
    pub const fn tables_allocated(&self) -> u8 {
        self.tables_allocated
    }

    pub const fn level(&self) -> Level {
        self.level
    }

    pub const fn kind(&self) -> WalkLeafKind {
        self.kind
    }

    pub const fn covered_size(&self) -> u64 {
        self.covered_size
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapRangeOutcome {
    pub(super) mappings_created: u64,
    pub(super) bytes_mapped: u64,
    pub(super) tables_allocated: u64,
}

impl MapRangeOutcome {
    pub const fn mappings_created(&self) -> u64 {
        self.mappings_created
    }

    pub const fn bytes_mapped(&self) -> u64 {
        self.bytes_mapped
    }

    pub const fn tables_allocated(&self) -> u64 {
        self.tables_allocated
    }
}

pub struct UnmapOutcome<F, R, G>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub(super) old: Mapping<F, R, G>,
}

impl<F, R, G> UnmapOutcome<F, R, G>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub const fn old(&self) -> &Mapping<F, R, G> {
        &self.old
    }
}

pub struct UnmapReclaimOutcome<F, R, G>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub(super) old: Mapping<F, R, G>,
    pub(super) tables_freed: u8,
    pub(super) root_now_empty: bool,
}

impl<F, R, G> UnmapReclaimOutcome<F, R, G>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub const fn old(&self) -> &Mapping<F, R, G> {
        &self.old
    }

    pub const fn tables_freed(&self) -> u8 {
        self.tables_freed
    }

    pub const fn root_now_empty(&self) -> bool {
        self.root_now_empty
    }
}

pub struct Mapping<F, R, G>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub(super) input: WalkInputAddr,
    pub(super) output: PhysAddr,
    pub(super) output_base: PhysAddr,
    pub(super) covered_input_base: u64,
    pub(super) covered_size: u64,
    pub(super) level: Level,
    pub(super) entry_index: usize,
    pub(super) raw: F::Raw,
    pub(super) kind: WalkLeafKind,
    pub(super) fields: LeafFieldsOf<F, R, G>,
}

impl<F, R, G> Mapping<F, R, G>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub const fn input(&self) -> WalkInputAddr {
        self.input
    }

    pub const fn output(&self) -> PhysAddr {
        self.output
    }

    pub const fn output_base(&self) -> PhysAddr {
        self.output_base
    }

    pub const fn covered_input_base(&self) -> u64 {
        self.covered_input_base
    }

    pub const fn covered_size(&self) -> u64 {
        self.covered_size
    }

    pub const fn level(&self) -> Level {
        self.level
    }

    pub const fn entry_index(&self) -> usize {
        self.entry_index
    }

    pub const fn raw(&self) -> F::Raw {
        self.raw
    }

    pub const fn kind(&self) -> WalkLeafKind {
        self.kind
    }

    pub const fn fields(&self) -> &LeafFieldsOf<F, R, G> {
        &self.fields
    }
}
