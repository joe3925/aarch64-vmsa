use core::marker::PhantomData;

use crate::address::PhysAddr;
use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorLayout;
use crate::descriptor::{DescriptorFormat, DescriptorKind, HasLayout};
use crate::table::{
    AccessError, TableAccess, TableAccessLocation, TableAddressError, TableGeometry, TablePhysAddr,
    TableWalkPath, TranslationTable,
};

unsafe impl<'access, F, G, A> TableAccess<F, G> for &'access A
where
    F: DescriptorFormat,
    G: TranslationGranule,
    A: TableAccess<F, G> + ?Sized,
{
    type Error = A::Error;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        (**self).table_at(location)
    }
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkLeafKind {
    Block,
    Page,
}

#[derive(Clone, Copy)]
pub struct WalkCursor<F, G>
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

impl<F, G> WalkCursor<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub fn new(
        input: WalkInputAddr,
        root: TablePhysAddr<G>,
        root_level: Level,
    ) -> Result<Self, WalkCursorError> {
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

    pub fn entry_index(self) -> Result<usize, WalkCursorError> {
        TableGeometry::<F, G>::index_at_level_raw(self.input.raw(), self.level)
            .ok_or(WalkCursorError::InvalidLevel { level: self.level })
    }

    pub fn descend(self, entry_index: usize, next: TablePhysAddr<G>) -> Result<Self, AccessError> {
        if self.level == F::FINAL_LEVEL {
            return Err(AccessError::InvalidTableLevel {
                root_level: self.root_level,
                level: self.level,
                final_level: F::FINAL_LEVEL,
            });
        }

        let mut path = self.path;
        path.push(self.root_level, self.level, entry_index)?;

        Ok(Self {
            input: self.input,
            root: self.root,
            root_level: self.root_level,
            current: next,
            level: self.level.next(),
            path,
        })
    }
}

#[derive(Clone, Copy)]
pub struct WalkInvalid<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    cursor: WalkCursor<F, G>,
    location: TableAccessLocation<F, G>,
    level: Level,
    entry_index: usize,
}

impl<F, G> WalkInvalid<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn cursor(self) -> WalkCursor<F, G> {
        self.cursor
    }

    pub const fn location(self) -> TableAccessLocation<F, G> {
        self.location
    }

    pub const fn input(self) -> WalkInputAddr {
        self.cursor.input()
    }

    pub const fn level(self) -> Level {
        self.level
    }

    pub const fn entry_index(self) -> usize {
        self.entry_index
    }
}

#[derive(Clone, Copy)]
pub struct WalkLeaf<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    cursor: WalkCursor<F, G>,
    location: TableAccessLocation<F, G>,
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
    pub const fn cursor(&self) -> WalkCursor<F, G> {
        self.cursor
    }

    pub const fn location(&self) -> TableAccessLocation<F, G> {
        self.location
    }

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
pub struct WalkTable<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    cursor: WalkCursor<F, G>,
    location: TableAccessLocation<F, G>,
    raw: F::Raw,
    level: Level,
    entry_index: usize,
    next: TablePhysAddr<G>,
    next_cursor: WalkCursor<F, G>,
    next_location: TableAccessLocation<F, G>,
    fields: WalkTableFieldsOf<F, P, G>,
}

impl<F, P, G> WalkTable<F, P, G>
where
    F: DescriptorFormat + HasLayout<P::Stage, G>,
    P: TranslationWalkProfile,
    G: TranslationGranule,
{
    pub const fn cursor(&self) -> WalkCursor<F, G> {
        self.cursor
    }

    pub const fn location(&self) -> TableAccessLocation<F, G> {
        self.location
    }

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

    pub const fn next_cursor(&self) -> WalkCursor<F, G> {
        self.next_cursor
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
    Invalid(WalkInvalid<F, G>),
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
    Invalid(WalkInvalid<F, G>),
    Leaf(WalkLeaf<F, P, G>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkCursorError {
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
    Cursor(WalkCursorError),
    InvalidTableAddress(TableAddressError),
    EntryIndexOutOfRange { index: usize, entries: usize },
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

impl<A> From<WalkCursorError> for WalkError<A> {
    fn from(error: WalkCursorError) -> Self {
        Self::Cursor(error)
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
    ) -> Result<Self, WalkCursorError> {
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

    pub fn cursor(&self, input: WalkInputAddr) -> Result<WalkCursor<F, G>, WalkCursorError> {
        WalkCursor::new(input, self.root, self.root_level)
    }

    pub fn step(&self, cursor: WalkCursor<F, G>) -> Result<WalkStep<F, P, G>, WalkError<A::Error>> {
        let location = cursor.location()?;
        let table = self.access.table_at(location).map_err(WalkError::Access)?;
        let entry_index = cursor.entry_index()?;
        let raw = table
            .read(entry_index)
            .ok_or(WalkError::EntryIndexOutOfRange {
                index: entry_index,
                entries: table.entries(),
            })?;

        match <WalkLayoutOf<F, P, G> as DescriptorLayout<F, P::Stage, G>>::kind(raw, cursor.level())
        {
            DescriptorKind::Invalid => Ok(WalkStep::Invalid(WalkInvalid {
                cursor,
                location,
                level: cursor.level(),
                entry_index,
            })),
            DescriptorKind::Block => {
                self.decode_leaf_step(cursor, location, raw, entry_index, WalkLeafKind::Block)
            }
            DescriptorKind::Page => {
                self.decode_leaf_step(cursor, location, raw, entry_index, WalkLeafKind::Page)
            }
            DescriptorKind::Table => self.decode_table_step(cursor, location, raw, entry_index),
        }
    }

    pub fn walk(&self, input: WalkInputAddr) -> Result<WalkOutcome<F, P, G>, WalkError<A::Error>> {
        let cursor = self.cursor(input)?;

        self.walk_from_cursor(cursor)
    }

    pub fn walk_from_cursor(
        &self,
        mut cursor: WalkCursor<F, G>,
    ) -> Result<WalkOutcome<F, P, G>, WalkError<A::Error>> {
        loop {
            match self.step(cursor)? {
                WalkStep::Invalid(invalid) => return Ok(WalkOutcome::Invalid(invalid)),
                WalkStep::Leaf(leaf) => return Ok(WalkOutcome::Leaf(leaf)),
                WalkStep::Table(table) => cursor = table.next_cursor(),
            }
        }
    }

    pub fn translate(
        &self,
        input: WalkInputAddr,
    ) -> Result<Option<WalkLeaf<F, P, G>>, WalkError<A::Error>> {
        match self.walk(input)? {
            WalkOutcome::Invalid(_) => Ok(None),
            WalkOutcome::Leaf(leaf) => Ok(Some(leaf)),
        }
    }

    fn decode_leaf_step(
        &self,
        cursor: WalkCursor<F, G>,
        location: TableAccessLocation<F, G>,
        raw: F::Raw,
        entry_index: usize,
        kind: WalkLeafKind,
    ) -> Result<WalkStep<F, P, G>, WalkError<A::Error>> {
        let level = cursor.level();

        let output_base =
            <WalkLayoutOf<F, P, G> as DescriptorLayout<F, P::Stage, G>>::output_address(raw, level);
        let offset = TableGeometry::<F, G>::offset_at_level_raw(cursor.input().raw(), level)
            .ok_or(WalkCursorError::InvalidLevel { level })?;
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
            cursor,
            location,
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
        cursor: WalkCursor<F, G>,
        location: TableAccessLocation<F, G>,
        raw: F::Raw,
        entry_index: usize,
    ) -> Result<WalkStep<F, P, G>, WalkError<A::Error>> {
        let level = cursor.level();

        if level == F::FINAL_LEVEL {
            return Err(WalkError::TableDescriptorAtFinalLevel { level });
        }

        let next = TablePhysAddr::<G>::new(<WalkLayoutOf<F, P, G> as DescriptorLayout<
            F,
            P::Stage,
            G,
        >>::output_address(raw, level))?;
        let fields =
            <WalkLayoutOf<F, P, G> as DescriptorLayout<F, P::Stage, G>>::decode_table_fields(
                raw, level,
            );
        let next_cursor = cursor.descend(entry_index, next)?;
        let next_location = next_cursor.location()?;

        Ok(WalkStep::Table(WalkTable {
            cursor,
            location,
            raw,
            level,
            entry_index,
            next,
            next_cursor,
            next_location,
            fields,
        }))
    }
}

fn validate_root_level<F>(root_level: Level) -> Result<(), WalkCursorError>
where
    F: DescriptorFormat,
{
    if root_level.is_before(F::EXTENDED_LOWEST_ROOT_LEVEL) || root_level.is_after(F::FINAL_LEVEL) {
        Err(WalkCursorError::InvalidRootLevel {
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
