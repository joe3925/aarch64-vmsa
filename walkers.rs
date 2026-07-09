use core::marker::PhantomData;

use crate::addr::PhysAddr;
use crate::format::{DescriptorFormat, DescriptorKind, HasLayout};
use crate::granule::{Level, TranslationGranule};
use crate::layout::DescriptorLayout;
use crate::table::{
    AccessError, TableAccess, TableAccessLocation, TableAddressError, TableGeometry, TablePhysAddr,
    TableWalkPath,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TranslationStageKind {
    Stage1,
    Stage2,
}

pub trait TranslationStage: Copy + 'static {
    const KIND: TranslationStageKind;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2;

impl TranslationStage for Stage1 {
    const KIND: TranslationStageKind = TranslationStageKind::Stage1;
}

impl TranslationStage for Stage2 {
    const KIND: TranslationStageKind = TranslationStageKind::Stage2;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WalkProfileKind {
    Stage1,
    Stage2,
}

pub trait TranslationWalkProfile: Copy + 'static {
    type Stage: TranslationStage;

    const KIND: WalkProfileKind;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1Walk;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Walk;

impl TranslationWalkProfile for Stage1Walk {
    type Stage = Stage1;

    const KIND: WalkProfileKind = WalkProfileKind::Stage1;
}

impl TranslationWalkProfile for Stage2Walk {
    type Stage = Stage2;

    const KIND: WalkProfileKind = WalkProfileKind::Stage2;
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct WalkInputAddr(u64);

impl WalkInputAddr {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

pub type WalkLayoutOf<F, P, G> = <F as HasLayout<<P as TranslationWalkProfile>::Stage, G>>::Layout;

pub type WalkLeafFieldsOf<F, P, G> = <WalkLayoutOf<F, P, G> as DescriptorLayout<
    F,
    <P as TranslationWalkProfile>::Stage,
    G,
>>::LeafFields;

pub type WalkTableFieldsOf<F, P, G> = <WalkLayoutOf<F, P, G> as DescriptorLayout<
    F,
    <P as TranslationWalkProfile>::Stage,
    G,
>>::TableFields;

#[derive(Clone, Copy)]
pub enum WalkLeafKind {
    Block,
    Page,
}

#[derive(Clone, Copy)]
pub struct WalkLeaf<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    raw: F::Raw,
    level: Level,
    entry_index: usize,
    output_base: PhysAddr,
    output: PhysAddr,
    kind: WalkLeafKind,
    fields: WalkLeafFieldsOf<F, P, G>,
}

impl<F, P, G> WalkLeaf<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    pub const fn raw(&self) -> F::Raw {
        self.raw
    }

    pub const fn level(&self) -> Level {
        self.level
    }

    pub const fn entry_index(&self) -> usize {
        self.entry_index
    }

    pub const fn output_base(&self) -> PhysAddr {
        self.output_base
    }

    pub const fn output(&self) -> PhysAddr {
        self.output
    }

    pub const fn kind(&self) -> WalkLeafKind {
        self.kind
    }

    pub const fn fields(&self) -> &WalkLeafFieldsOf<F, P, G> {
        &self.fields
    }
}

#[derive(Clone, Copy)]
pub struct WalkInvalid {
    level: Level,
    entry_index: usize,
}

impl WalkInvalid {
    pub const fn level(self) -> Level {
        self.level
    }

    pub const fn entry_index(self) -> usize {
        self.entry_index
    }
}

#[derive(Clone, Copy)]
pub struct WalkTable<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    raw: F::Raw,
    level: Level,
    entry_index: usize,
    next: TablePhysAddr<G>,
    next_location: TableAccessLocation<F, G>,
    fields: WalkTableFieldsOf<F, P, G>,
}

impl<F, P, G> WalkTable<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    pub const fn raw(&self) -> F::Raw {
        self.raw
    }

    pub const fn level(&self) -> Level {
        self.level
    }

    pub const fn entry_index(&self) -> usize {
        self.entry_index
    }

    pub const fn next(&self) -> TablePhysAddr<G> {
        self.next
    }

    pub const fn next_location(&self) -> TableAccessLocation<F, G> {
        self.next_location
    }

    pub const fn fields(&self) -> &WalkTableFieldsOf<F, P, G> {
        &self.fields
    }
}

#[derive(Clone, Copy)]
pub enum WalkStep<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    Invalid(WalkInvalid),
    Leaf(WalkLeaf<F, P, G>),
    Table(WalkTable<F, P, G>),
}

#[derive(Clone, Copy)]
pub enum WalkOutcome<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    Invalid(WalkInvalid),
    Leaf(WalkLeaf<F, P, G>),
}

#[derive(Clone, Copy)]
pub struct WalkState<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    input: WalkInputAddr,
    root: TablePhysAddr<G>,
    root_level: Level,
    current: TablePhysAddr<G>,
    level: Level,
    path: TableWalkPath<F, G>,
}

impl<F, G> WalkState<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub fn new(
        input: WalkInputAddr,
        root: TablePhysAddr<G>,
        root_level: Level,
    ) -> Result<Self, WalkStateError> {
        validate_root_level::<F>(root_level)?;

        Ok(Self {
            input,
            root,
            root_level,
            current: root,
            level: root_level,
            path: TableWalkPath::root(),
        })
    }

    pub const fn input(self) -> WalkInputAddr {
        self.input
    }

    pub const fn root(self) -> TablePhysAddr<G> {
        self.root
    }

    pub const fn root_level(self) -> Level {
        self.root_level
    }

    pub const fn current(self) -> TablePhysAddr<G> {
        self.current
    }

    pub const fn level(self) -> Level {
        self.level
    }

    pub const fn path(self) -> TableWalkPath<F, G> {
        self.path
    }

    pub fn location(self) -> Result<TableAccessLocation<F, G>, AccessError> {
        TableAccessLocation::child(self.current, self.root_level, self.level, self.path)
    }

    pub fn entry_index(self) -> Result<usize, WalkStateError> {
        TableGeometry::<F, G>::index_at_level_raw(self.input.raw(), self.level)
            .ok_or(WalkStateError::InvalidLevel { level: self.level })
    }

    pub fn descend(
        &mut self,
        entry_index: usize,
        next: TablePhysAddr<G>,
    ) -> Result<(), AccessError> {
        if self.level == F::FINAL_LEVEL {
            return Err(AccessError::InvalidTableLevel {
                root_level: self.root_level,
                level: self.level,
                final_level: F::FINAL_LEVEL,
            });
        }

        self.path.push(self.root_level, self.level, entry_index)?;

        self.level = self.level.next();
        self.current = next;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkStateError {
    InvalidRootLevel {
        root_level: Level,
        lowest_level: Level,
        final_level: Level,
    },
    InvalidLevel {
        level: Level,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkError<A> {
    Access(A),
    AccessLocation(AccessError),
    State(WalkStateError),
    InvalidTableAddress(TableAddressError),
    TableDescriptorAtFinalLevel { level: Level },
    OutputAddressOverflow { base: PhysAddr, offset: u64 },
}

impl<A> From<AccessError> for WalkError<A> {
    fn from(error: AccessError) -> Self {
        Self::AccessLocation(error)
    }
}

impl<A> From<TableAddressError> for WalkError<A> {
    fn from(error: TableAddressError) -> Self {
        Self::InvalidTableAddress(error)
    }
}

impl<A> From<WalkStateError> for WalkError<A> {
    fn from(error: WalkStateError) -> Self {
        Self::State(error)
    }
}

pub struct Walker<F, P, G, A>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    root: TablePhysAddr<G>,
    root_level: Level,
    access: A,
    _marker: PhantomData<(F, P, G)>,
}

impl<F, P, G, A> Walker<F, P, G, A>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    pub fn new(
        root: TablePhysAddr<G>,
        root_level: Level,
        access: A,
    ) -> Result<Self, WalkStateError> {
        validate_root_level::<F>(root_level)?;

        Ok(Self {
            root,
            root_level,
            access,
            _marker: PhantomData,
        })
    }

    pub const fn root(&self) -> TablePhysAddr<G> {
        self.root
    }

    pub const fn root_level(&self) -> Level {
        self.root_level
    }

    pub const fn access(&self) -> &A {
        &self.access
    }

    pub fn access_mut(&mut self) -> &mut A {
        &mut self.access
    }

    pub fn into_access(self) -> A {
        self.access
    }

    pub fn initial_state(&self, input: WalkInputAddr) -> Result<WalkState<F, G>, WalkStateError> {
        WalkState::new(input, self.root, self.root_level)
    }

    pub fn walk(&self, input: WalkInputAddr) -> Result<WalkOutcome<F, P, G>, WalkError<A::Error>> {
        let mut state = self.initial_state(input)?;

        loop {
            match self.walk_step(state)? {
                WalkStep::Invalid(invalid) => return Ok(WalkOutcome::Invalid(invalid)),
                WalkStep::Leaf(leaf) => return Ok(WalkOutcome::Leaf(leaf)),
                WalkStep::Table(table) => state.descend(table.entry_index(), table.next())?,
            }
        }
    }

    pub fn walk_step(
        &self,
        state: WalkState<F, G>,
    ) -> Result<WalkStep<F, P, G>, WalkError<A::Error>> {
        let location = state.location()?;
        let table = self.access.table_at(location).map_err(WalkError::Access)?;

        let entry_index = state.entry_index()?;
        let raw = match table.read(entry_index) {
            Some(raw) => raw,
            None => {
                return Ok(WalkStep::Invalid(WalkInvalid {
                    level: state.level(),
                    entry_index,
                }));
            }
        };

        match <WalkLayoutOf<F, P, G> as DescriptorLayout<F, P::Stage, G>>::kind(raw, state.level())
        {
            DescriptorKind::Invalid => Ok(WalkStep::Invalid(WalkInvalid {
                level: state.level(),
                entry_index,
            })),
            DescriptorKind::Block => self.decode_leaf_step(
                state.input(),
                raw,
                state.level(),
                entry_index,
                WalkLeafKind::Block,
            ),
            DescriptorKind::Page => self.decode_leaf_step(
                state.input(),
                raw,
                state.level(),
                entry_index,
                WalkLeafKind::Page,
            ),
            DescriptorKind::Table => self.decode_table_step(state, raw, entry_index),
        }
    }

    fn decode_leaf_step(
        &self,
        input: WalkInputAddr,
        raw: F::Raw,
        level: Level,
        entry_index: usize,
        kind: WalkLeafKind,
    ) -> Result<WalkStep<F, P, G>, WalkError<A::Error>> {
        let output_base =
            <WalkLayoutOf<F, P, G> as DescriptorLayout<F, P::Stage, G>>::output_address(raw, level);
        let offset = TableGeometry::<F, G>::offset_at_level_raw(input.raw(), level)
            .ok_or(WalkStateError::InvalidLevel { level })?;
        let output = PhysAddr(output_base.0.checked_add(offset).ok_or(
            WalkError::OutputAddressOverflow {
                base: output_base,
                offset,
            },
        )?);
        let fields =
            <WalkLayoutOf<F, P, G> as DescriptorLayout<F, P::Stage, G>>::decode_leaf_fields(
                raw, level,
            );

        Ok(WalkStep::Leaf(WalkLeaf {
            raw,
            level,
            entry_index,
            output_base,
            output,
            kind,
            fields,
        }))
    }

    fn decode_table_step(
        &self,
        state: WalkState<F, G>,
        raw: F::Raw,
        entry_index: usize,
    ) -> Result<WalkStep<F, P, G>, WalkError<A::Error>> {
        if state.level() == F::FINAL_LEVEL {
            return Err(WalkError::TableDescriptorAtFinalLevel {
                level: state.level(),
            });
        }

        let next = TablePhysAddr::<G>::new(<WalkLayoutOf<F, P, G> as DescriptorLayout<
            F,
            P::Stage,
            G,
        >>::output_address(raw, state.level()))?;
        let fields =
            <WalkLayoutOf<F, P, G> as DescriptorLayout<F, P::Stage, G>>::decode_table_fields(
                raw,
                state.level(),
            );

        let mut next_state = state;
        next_state.descend(entry_index, next)?;
        let next_location = next_state.location()?;

        Ok(WalkStep::Table(WalkTable {
            raw,
            level: state.level(),
            entry_index,
            next,
            next_location,
            fields,
        }))
    }
}

fn validate_root_level<F>(root_level: Level) -> Result<(), WalkStateError>
where
    F: DescriptorFormat,
{
    if root_level.is_before(F::EXTENDED_LOWEST_ROOT_LEVEL) || root_level.is_after(F::FINAL_LEVEL) {
        Err(WalkStateError::InvalidRootLevel {
            root_level,
            lowest_level: F::EXTENDED_LOWEST_ROOT_LEVEL,
            final_level: F::FINAL_LEVEL,
        })
    } else {
        Ok(())
    }
}

pub type Stage1Walker<F, G, A> = Walker<F, Stage1Walk, G, A>;
pub type Stage2Walker<F, G, A> = Walker<F, Stage2Walk, G, A>;
