use crate::address::PhysAddr;
use crate::address::{Level, TranslationGranule};
use crate::descriptor::{DescriptorFormat, DescriptorKind, DescriptorLayout, HasLayout};
use crate::regime::{RegimeLayout, RegimeLeafFields, RegimeTableFields, TranslationRegime};
use crate::table::{
    AccessError, NextTable, RootTable, TableAccess, TableAccessLocation, TableAddr,
    TableAddressError, TableCursor, TableGeometry, TableWalkPath, TranslationTable,
};

// SAFETY: This implementation preserves the source accessor's borrow and contract.
unsafe impl<F, G, A> TableAccess<F, G> for &A
where
    F: DescriptorFormat,
    G: TranslationGranule,
    A: TableAccess<F, G> + ?Sized,
{
    type Error = A::Error;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<'a, F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        (**self).table_at(location)
    }
}

mod stage_private {
    pub trait Sealed {}
}

pub trait TranslationStage: stage_private::Sealed + Copy + 'static {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct Stage1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct Stage2;

impl stage_private::Sealed for Stage1 {}
impl stage_private::Sealed for Stage2 {}

impl TranslationStage for Stage1 {}

impl TranslationStage for Stage2 {}

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
    table: TableCursor<F, G>,
}

impl<F, G> WalkCursor<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub(crate) fn new(
        input: WalkInputAddr,
        root: TableAddr<G>,
        root_level: Level,
    ) -> Result<Self, WalkCursorError> {
        validate_root_level::<F>(root_level)?;

        Ok(Self {
            input,
            table: TableCursor::root(root, root_level),
        })
    }

    pub const fn input(self) -> WalkInputAddr {
        self.input
    }

    pub const fn root(self) -> TableAddr<G> {
        self.table.root_addr()
    }

    pub const fn root_level(self) -> Level {
        self.table.root_level()
    }

    pub const fn current(self) -> TableAddr<G> {
        self.table.current()
    }

    pub const fn level(self) -> Level {
        self.table.level()
    }

    pub const fn table(self) -> TableCursor<F, G> {
        self.table
    }

    pub const fn path(self) -> TableWalkPath<F, G> {
        self.table.path()
    }

    pub fn entry_index(self) -> Result<usize, WalkCursorError> {
        self.table
            .entry_index(self.input.raw())
            .map_err(|_| WalkCursorError::InvalidLevel {
                level: self.level(),
            })
    }

    pub fn next_table(
        self,
        entry_index: usize,
        next: NextTable<F, G>,
    ) -> Result<Self, AccessError> {
        Ok(Self {
            input: self.input,
            table: self.table.next_table(entry_index, next)?,
        })
    }

    pub(crate) const fn with_table(self, table: TableCursor<F, G>) -> Self {
        Self {
            input: self.input,
            table,
        }
    }
}

#[derive(Clone, Copy)]
pub struct ResolvedWalkInvalid<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    cursor: WalkCursor<F, G>,
    entry: WalkInvalid<F, G>,
}

impl<F, G> ResolvedWalkInvalid<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn cursor(self) -> WalkCursor<F, G> {
        self.cursor
    }

    pub const fn input(self) -> WalkInputAddr {
        self.cursor.input()
    }

    pub const fn level(self) -> Level {
        self.entry.info().level()
    }

    pub const fn entry_index(self) -> usize {
        self.entry.info().entry_index()
    }
}

#[derive(Clone, Copy)]
pub struct ResolvedWalkLeaf<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    cursor: WalkCursor<F, G>,
    entry: WalkLeaf<F, R, G>,
    output: PhysAddr,
}

impl<F, R, G> ResolvedWalkLeaf<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub(crate) fn from_entry<A>(
        cursor: WalkCursor<F, G>,
        entry: WalkLeaf<F, R, G>,
    ) -> Result<Self, WalkError<A>> {
        let output = resolve_output::<F, R, G, A>(cursor.input(), &entry)?;

        Ok(Self {
            cursor,
            entry,
            output,
        })
    }

    pub const fn cursor(&self) -> WalkCursor<F, G> {
        self.cursor
    }

    pub(crate) fn location<'a>(&self) -> TableAccessLocation<'a, F, G> {
        TableAccessLocation::from_cursor(self.entry.info().cursor())
            .expect("validated walk location")
    }

    pub const fn raw(&self) -> F::Raw {
        self.entry.info().raw()
    }

    pub const fn level(&self) -> Level {
        self.entry.info().level()
    }

    pub const fn entry_index(&self) -> usize {
        self.entry.info().entry_index()
    }

    pub const fn output_base(&self) -> PhysAddr {
        self.entry.output_base()
    }

    pub const fn output(&self) -> PhysAddr {
        self.output
    }

    pub const fn kind(&self) -> WalkLeafKind {
        self.entry.kind()
    }

    pub const fn fields(&self) -> &crate::regime::RegimeLeafFields<F, R, G> {
        self.entry.fields()
    }
}

#[derive(Clone, Copy)]
pub enum WalkOutcome<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    Invalid(ResolvedWalkInvalid<F, G>),
    Leaf(ResolvedWalkLeaf<F, R, G>),
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
    InputAddressOutOfRange {
        addr: u64,
        addr_bits: u8,
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
    PathEntryNotTable { level: Level, entry_index: usize },
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

pub struct Walker<F, R, G, A>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    root: RootTable<F, R, G>,
    access: A,
}

impl<F, R, G, A> Walker<F, R, G, A>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    pub fn new(root: RootTable<F, R, G>, access: A) -> Result<Self, WalkCursorError> {
        validate_root_level::<F>(root.level())?;
        Ok(Self { root, access })
    }

    pub const fn root(&self) -> TableAddr<G> {
        self.root.addr()
    }

    pub const fn root_level(&self) -> Level {
        self.root.level()
    }

    pub const fn table_geometry(&self) -> TableGeometry<F, G> {
        TableGeometry::new()
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

    pub(crate) fn cursor(&self, input: WalkInputAddr) -> Result<WalkCursor<F, G>, WalkCursorError> {
        let addr_bits = self.root.addr_bits();
        if addr_bits < u64::BITS as u8 && input.raw() >> addr_bits != 0 {
            return Err(WalkCursorError::InputAddressOutOfRange {
                addr: input.raw(),
                addr_bits,
            });
        }

        WalkCursor::new(input, self.root.addr(), self.root.level())
    }

    pub(crate) fn step(
        &self,
        cursor: WalkCursor<F, G>,
    ) -> Result<WalkEntry<F, R, G>, WalkError<A::Error>> {
        let entry_index = cursor.entry_index()?;
        self.entry_at(cursor.table(), entry_index)
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

pub type WalkResult<T, A> = Result<T, WalkError<A>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalkNavigationError {
    EntryNotInCurrentTable,
}

#[derive(Clone, Copy)]
pub struct WalkEntryInfo<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    cursor: TableCursor<F, G>,
    raw: F::Raw,
    entry_index: usize,
}

impl<F, G> WalkEntryInfo<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn raw(&self) -> F::Raw {
        self.raw
    }

    pub const fn level(&self) -> Level {
        self.cursor.level()
    }

    pub const fn entry_index(&self) -> usize {
        self.entry_index
    }

    pub const fn table(&self) -> TableAddr<G> {
        self.cursor.current()
    }

    pub const fn cursor(&self) -> TableCursor<F, G> {
        self.cursor
    }
}

#[derive(Clone, Copy)]
pub struct WalkInvalid<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    info: WalkEntryInfo<F, G>,
}

impl<F, G> WalkInvalid<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn info(&self) -> &WalkEntryInfo<F, G> {
        &self.info
    }

    pub(crate) fn location<'a>(&self) -> TableAccessLocation<'a, F, G> {
        TableAccessLocation::from_cursor(self.info.cursor()).expect("validated walk location")
    }

    pub const fn level(&self) -> Level {
        self.info.level()
    }

    pub const fn entry_index(&self) -> usize {
        self.info.entry_index()
    }
}

#[derive(Clone, Copy)]
pub struct WalkLeaf<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    info: WalkEntryInfo<F, G>,
    output_base: PhysAddr,
    kind: WalkLeafKind,
    fields: RegimeLeafFields<F, R, G>,
}

impl<F, R, G> WalkLeaf<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub const fn info(&self) -> &WalkEntryInfo<F, G> {
        &self.info
    }

    pub const fn raw(&self) -> F::Raw {
        self.info.raw()
    }

    pub const fn level(&self) -> Level {
        self.info.level()
    }

    pub const fn entry_index(&self) -> usize {
        self.info.entry_index()
    }

    pub const fn output_base(&self) -> PhysAddr {
        self.output_base
    }

    pub const fn kind(&self) -> WalkLeafKind {
        self.kind
    }

    pub const fn fields(&self) -> &RegimeLeafFields<F, R, G> {
        &self.fields
    }
}

#[derive(Clone, Copy)]
pub struct WalkTable<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    info: WalkEntryInfo<F, G>,
    next: NextTable<F, G>,
    next_cursor: TableCursor<F, G>,
    fields: RegimeTableFields<F, R, G>,
}

impl<F, R, G> WalkTable<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub const fn info(&self) -> &WalkEntryInfo<F, G> {
        &self.info
    }

    pub(crate) fn location<'a>(&self) -> TableAccessLocation<'a, F, G> {
        TableAccessLocation::from_cursor(self.info.cursor()).expect("validated walk location")
    }

    pub const fn raw(&self) -> F::Raw {
        self.info.raw()
    }

    pub const fn level(&self) -> Level {
        self.info.level()
    }

    pub const fn entry_index(&self) -> usize {
        self.info.entry_index()
    }

    pub const fn next(&self) -> TableAddr<G> {
        self.next.addr()
    }

    pub const fn next_table(&self) -> NextTable<F, G> {
        self.next
    }

    pub const fn next_cursor(&self) -> TableCursor<F, G> {
        self.next_cursor
    }

    pub const fn fields(&self) -> &RegimeTableFields<F, R, G> {
        &self.fields
    }
}

#[derive(Clone, Copy)]
pub enum WalkEntry<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    Invalid(WalkInvalid<F, G>),
    Leaf(WalkLeaf<F, R, G>),
    Table(WalkTable<F, R, G>),
}

impl<F, R, G> WalkEntry<F, R, G>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub const fn info(&self) -> &WalkEntryInfo<F, G> {
        match self {
            Self::Invalid(entry) => entry.info(),
            Self::Leaf(entry) => entry.info(),
            Self::Table(entry) => entry.info(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Free;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Addressed {
    input: WalkInputAddr,
}

pub struct Walk<'a, F, R, G, A, M = Free>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    walker: &'a Walker<F, R, G, A>,
    current: TableCursor<F, G>,
    next_index: usize,
    mode: M,
}

impl<'a, F, R, G, A, M> Walk<'a, F, R, G, A, M>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    fn new(walker: &'a Walker<F, R, G, A>, current: TableCursor<F, G>, mode: M) -> Self {
        Self {
            walker,
            current,
            next_index: 0,
            mode,
        }
    }

    pub fn next_entry(&mut self) -> WalkResult<Option<WalkEntry<F, R, G>>, A::Error> {
        if self.next_index >= self.entry_count() {
            return Ok(None);
        }

        self.step_to(self.next_index).map(Some)
    }

    pub fn step_to(&mut self, entry_index: usize) -> WalkResult<WalkEntry<F, R, G>, A::Error> {
        let entry = self.walker.entry_at(self.current, entry_index)?;
        self.next_index = entry_index + 1;
        Ok(entry)
    }

    pub fn step_in(&mut self, table: WalkTable<F, R, G>) -> Result<(), WalkNavigationError> {
        if !table.info.cursor.same_location(self.current) {
            return Err(WalkNavigationError::EntryNotInCurrentTable);
        }

        self.current = table.next_cursor;
        self.next_index = 0;
        Ok(())
    }

    pub fn step_out(&mut self) -> WalkResult<bool, A::Error> {
        let path = self.current.path();
        let Some(parent_depth) = path.len().checked_sub(1) else {
            return Ok(false);
        };

        let root_level = self.current.root_level();
        let mut parent = TableCursor::root(self.current.root_addr(), root_level);
        for depth in 0..parent_depth {
            let edge = path
                .entry(root_level, depth)
                .expect("a validated table cursor has a valid path");
            parent = match self.walker.entry_at(parent, edge.index())? {
                WalkEntry::Table(table) => table.next_cursor(),
                _ => {
                    return Err(WalkError::PathEntryNotTable {
                        level: parent.level(),
                        entry_index: edge.index(),
                    });
                }
            };
        }

        let parent_edge = path
            .entry(root_level, parent_depth)
            .expect("a validated table cursor has a valid parent edge");
        self.current = parent;
        self.next_index = parent_edge.index() + 1;
        Ok(true)
    }

    pub const fn current(&self) -> TableCursor<F, G> {
        self.current
    }

    pub const fn current_table(&self) -> TableAddr<G> {
        self.current.current()
    }

    pub const fn level(&self) -> Level {
        self.current.level()
    }

    pub fn entry_count(&self) -> usize {
        self.current.shape().entries()
    }

    pub const fn next_index(&self) -> usize {
        self.next_index
    }

    pub const fn depth(&self) -> usize {
        self.current.path().len() as usize
    }
}

impl<F, R, G, A> Walk<'_, F, R, G, A, Addressed>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    pub const fn input(&self) -> WalkInputAddr {
        self.mode.input
    }

    pub fn step(&mut self) -> WalkResult<WalkEntry<F, R, G>, A::Error> {
        let entry_index = self
            .current
            .entry_index(self.mode.input.raw())
            .map_err(|_| WalkCursorError::InvalidLevel {
                level: self.level(),
            })?;
        self.step_to(entry_index)
    }

    pub fn output(&self, leaf: &WalkLeaf<F, R, G>) -> WalkResult<PhysAddr, A::Error> {
        resolve_output(self.mode.input, leaf)
    }

    pub fn finish(&mut self) -> WalkResult<WalkOutcome<F, R, G>, A::Error> {
        loop {
            match self.step()? {
                WalkEntry::Invalid(entry) => {
                    return Ok(WalkOutcome::Invalid(ResolvedWalkInvalid {
                        cursor: self.cursor(),
                        entry,
                    }));
                }
                WalkEntry::Leaf(entry) => {
                    return Ok(WalkOutcome::Leaf(ResolvedWalkLeaf::from_entry(
                        self.cursor(),
                        entry,
                    )?));
                }
                WalkEntry::Table(entry) => self
                    .step_in(entry)
                    .expect("the entry returned by this walk belongs to its current table"),
            }
        }
    }

    const fn cursor(&self) -> WalkCursor<F, G> {
        WalkCursor {
            input: self.mode.input,
            table: self.current,
        }
    }
}

fn resolve_output<F, R, G, A>(
    input: WalkInputAddr,
    leaf: &WalkLeaf<F, R, G>,
) -> WalkResult<PhysAddr, A>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    let base = leaf.output_base();
    let level = leaf.level();
    let offset = TableGeometry::<F, G>::offset_at_level_raw(input.raw(), level)
        .ok_or(WalkCursorError::InvalidLevel { level })?;
    Ok(PhysAddr(base.0.checked_add(offset).ok_or(
        WalkError::OutputAddressOverflow { base, offset },
    )?))
}

impl<F, R, G, A> Walker<F, R, G, A>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    pub fn start(&self) -> Walk<'_, F, R, G, A> {
        Walk::new(
            self,
            TableCursor::root(self.root(), self.root_level()),
            Free,
        )
    }

    pub fn start_at(
        &self,
        input: WalkInputAddr,
    ) -> Result<Walk<'_, F, R, G, A, Addressed>, WalkCursorError> {
        let cursor = self.cursor(input)?;
        Ok(Walk::new(self, cursor.table(), Addressed { input }))
    }

    pub fn translate(
        &self,
        input: WalkInputAddr,
    ) -> WalkResult<Option<ResolvedWalkLeaf<F, R, G>>, A::Error> {
        match self.start_at(input)?.finish()? {
            WalkOutcome::Invalid(_) => Ok(None),
            WalkOutcome::Leaf(leaf) => Ok(Some(leaf)),
        }
    }
}

impl<F, R, G, A> Walker<F, R, G, A>
where
    F: DescriptorFormat + HasLayout<R::Stage, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccess<F, G>,
{
    pub(crate) fn entry_at(
        &self,
        cursor: TableCursor<F, G>,
        entry_index: usize,
    ) -> WalkResult<WalkEntry<F, R, G>, A::Error> {
        let location = cursor.location()?;
        let table = self
            .access()
            .table_at(location)
            .map_err(WalkError::Access)?;
        let raw = table
            .read(entry_index)
            .ok_or(WalkError::EntryIndexOutOfRange {
                index: entry_index,
                entries: table.entries(),
            })?;
        let level = cursor.level();
        let info = WalkEntryInfo {
            cursor,
            raw,
            entry_index,
        };

        let kind = <RegimeLayout<F, R, G> as DescriptorLayout<R::Stage, G>>::kind(raw, level);
        match kind {
            DescriptorKind::Invalid => Ok(WalkEntry::Invalid(WalkInvalid { info })),
            DescriptorKind::Block | DescriptorKind::Page => {
                let kind = if kind == DescriptorKind::Block {
                    WalkLeafKind::Block
                } else {
                    WalkLeafKind::Page
                };
                let output_base =
                    <RegimeLayout<F, R, G> as DescriptorLayout<R::Stage, G>>::output_address(
                        raw, level,
                    );
                let fields =
                    <RegimeLayout<F, R, G> as DescriptorLayout<R::Stage, G>>::decode_leaf_fields(
                        raw, level,
                    );
                Ok(WalkEntry::Leaf(WalkLeaf {
                    info,
                    output_base,
                    kind,
                    fields,
                }))
            }
            DescriptorKind::Table => {
                if level == F::FINAL_LEVEL {
                    return Err(WalkError::TableDescriptorAtFinalLevel { level });
                }
                let fields =
                    <RegimeLayout<F, R, G> as DescriptorLayout<R::Stage, G>>::decode_table_fields(
                        raw, level,
                    );
                let descriptor =
                    <RegimeLayout<F, R, G> as DescriptorLayout<R::Stage, G>>::next_table(
                        raw, level,
                    )
                    .ok_or(WalkError::TableDescriptorAtFinalLevel { level })?;
                let next = NextTable::<F, G>::from_descriptor(descriptor)?;
                let next_cursor = cursor.next_table(entry_index, next)?;
                Ok(WalkEntry::Table(WalkTable {
                    info,
                    next,
                    next_cursor,
                    fields,
                }))
            }
        }
    }
}
