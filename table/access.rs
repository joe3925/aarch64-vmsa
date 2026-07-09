use core::marker::PhantomData;

use crate::address::{Level, PhysAddr, TranslationGranule};
use crate::descriptor::{DescriptorFormat, NextTableDescriptor};

use super::{AccessError, TableGeometry, TablePhysAddr, TranslationTable, TranslationTableMut};

const PATH_STRIDE_BITS: u8 = 2;
const PATH_STRIDE_MASK: u128 = (1 << PATH_STRIDE_BITS) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableAllocLayout {
    bytes: u64,
    align: u64,
}

impl TableAllocLayout {
    pub const fn new(bytes: u64, align: u64) -> Self {
        Self { bytes, align }
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    pub const fn align(self) -> u64 {
        self.align
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableStrideCount(u8);

impl TableStrideCount {
    pub const ONE: Self = Self(1);

    pub fn new<F, G>(stride_count: u8) -> Result<Self, AccessError>
    where
        F: DescriptorFormat,
        G: TranslationGranule,
    {
        if stride_count == 0 || stride_count > Self::MAX_ENCODED {
            return Err(AccessError::InvalidTableStrideCount { stride_count });
        }

        if TableGeometry::<F, G>::checked_entries_for_stride_count(stride_count).is_none() {
            return Err(AccessError::InvalidTableStrideCount { stride_count });
        }

        Ok(Self(stride_count))
    }

    pub const fn raw(self) -> u8 {
        self.0
    }

    const MAX_ENCODED: u8 = 1 + PATH_STRIDE_MASK as u8;

    const unsafe fn new_unchecked(stride_count: u8) -> Self {
        Self(stride_count)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableShape<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    level: Level,
    stride_count: TableStrideCount,
    _marker: PhantomData<(F, G)>,
}

impl<F, G> TableShape<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn root(level: Level) -> Self {
        Self {
            level,
            stride_count: TableStrideCount::ONE,
            _marker: PhantomData,
        }
    }

    pub fn new(level: Level, stride_count: u8) -> Result<Self, AccessError> {
        if level.is_after(F::FINAL_LEVEL) {
            return Err(AccessError::InvalidTableLevel {
                root_level: level,
                level,
                final_level: F::FINAL_LEVEL,
            });
        }

        Ok(Self {
            level,
            stride_count: TableStrideCount::new::<F, G>(stride_count)?,
            _marker: PhantomData,
        })
    }

    pub const fn level(self) -> Level {
        self.level
    }

    pub const fn stride_count(self) -> TableStrideCount {
        self.stride_count
    }

    pub fn entries(self) -> usize {
        TableGeometry::<F, G>::entries_for_stride_count(self.stride_count.raw())
    }

    pub fn alloc_layout(self) -> Result<TableAllocLayout, AccessError> {
        let entries = self.entries();
        let bytes = (entries as u64)
            .checked_mul(F::DESCRIPTOR_BYTES as u64)
            .ok_or(AccessError::TableAllocationLayoutOverflow {
                entries,
                descriptor_bytes: F::DESCRIPTOR_BYTES,
            })?;

        Ok(TableAllocLayout::new(bytes, bytes))
    }

    pub fn validate_base(self, addr: PhysAddr) -> Result<(), AccessError> {
        let layout = self.alloc_layout()?;

        if addr.0 & (layout.align() - 1) == 0 {
            Ok(())
        } else {
            Err(AccessError::UnalignedTableAddress {
                addr,
                align: layout.align(),
            })
        }
    }

    pub fn index_for_input(self, input: u64) -> Option<usize> {
        TableGeometry::<F, G>::index_at_level_raw_strides(
            input,
            self.level,
            self.stride_count.raw(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NextTable<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    addr: TablePhysAddr<G>,
    shape: TableShape<F, G>,
}

impl<F, G> NextTable<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub fn new(
        addr: TablePhysAddr<G>,
        level: Level,
        stride_count: u8,
    ) -> Result<Self, AccessError> {
        let shape = TableShape::new(level, stride_count)?;
        shape.validate_base(addr.phys())?;

        Ok(Self { addr, shape })
    }

    pub fn from_descriptor(descriptor: NextTableDescriptor) -> Result<Self, AccessError> {
        Ok(Self {
            addr: TablePhysAddr::new(descriptor.address)?,
            shape: TableShape::new(descriptor.level, descriptor.stride_count)?,
        })
    }

    pub const fn addr(self) -> TablePhysAddr<G> {
        self.addr
    }

    pub const fn shape(self) -> TableShape<F, G> {
        self.shape
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableTransition<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    parent: TableShape<F, G>,
    child: TableShape<F, G>,
}

impl<F, G> TableTransition<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub fn new(parent: TableShape<F, G>, child: TableShape<F, G>) -> Result<Self, AccessError> {
        if !parent.level().is_before(child.level()) || child.level().is_after(F::FINAL_LEVEL) {
            return Err(AccessError::InvalidTableTransition {
                parent_level: parent.level(),
                child_level: child.level(),
                stride_count: child.stride_count().raw(),
            });
        }

        let level_step = child.level().distance_from(parent.level()).ok_or(
            AccessError::InvalidTableTransition {
                parent_level: parent.level(),
                child_level: child.level(),
                stride_count: child.stride_count().raw(),
            },
        )?;

        if level_step == 0 || child.stride_count().raw() != level_step {
            return Err(AccessError::InvalidTableTransition {
                parent_level: parent.level(),
                child_level: child.level(),
                stride_count: child.stride_count().raw(),
            });
        }

        Ok(Self { parent, child })
    }

    pub const fn parent(self) -> TableShape<F, G> {
        self.parent
    }

    pub const fn child(self) -> TableShape<F, G> {
        self.child
    }

    pub const fn parent_level(self) -> Level {
        self.parent.level()
    }

    pub const fn child_level(self) -> Level {
        self.child.level()
    }

    pub fn level_step(self) -> u8 {
        self.child
            .level()
            .distance_from(self.parent.level())
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableWalkPathEntry<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    parent: TableShape<F, G>,
    child_level: Level,
    index: usize,
}

impl<F, G> TableWalkPathEntry<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn parent(self) -> TableShape<F, G> {
        self.parent
    }

    pub const fn parent_level(self) -> Level {
        self.parent.level()
    }

    pub const fn child_level(self) -> Level {
        self.child_level
    }

    pub const fn index(self) -> usize {
        self.index
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableWalkPath<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    bits: u128,
    index_strides: u128,
    level_steps: u128,
    len: u8,
    _marker: PhantomData<(F, G)>,
}

impl<F, G> TableWalkPath<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn root() -> Self {
        Self {
            bits: 0,
            index_strides: 0,
            level_steps: 0,
            len: 0,
            _marker: PhantomData,
        }
    }

    pub const fn len(&self) -> u8 {
        self.len
    }

    pub const fn is_root(&self) -> bool {
        self.len == 0
    }

    pub const fn bits(&self) -> u128 {
        self.bits
    }

    pub fn push(
        &mut self,
        root_level: Level,
        parent: TableShape<F, G>,
        child: TableShape<F, G>,
        index: usize,
    ) -> Result<(), AccessError> {
        let parent_level = parent.level();
        let child_level = child.level();
        if root_level.is_after(parent_level)
            || !parent_level.is_before(F::FINAL_LEVEL)
            || !parent_level.is_before(child_level)
            || child_level.is_after(F::FINAL_LEVEL)
        {
            return Err(AccessError::InvalidTableLevel {
                root_level,
                level: parent_level,
                final_level: F::FINAL_LEVEL,
            });
        }

        if self.terminal_level(root_level)? != parent_level {
            return Err(AccessError::TablePathTerminalLevelMismatch {
                expected: parent_level,
                actual: self.terminal_level(root_level)?,
            });
        }

        let level_step =
            child_level
                .distance_from(parent_level)
                .ok_or(AccessError::InvalidTableLevel {
                    root_level,
                    level: child_level,
                    final_level: F::FINAL_LEVEL,
                })?;

        if Self::checked_encoded_stride_count(level_step).is_none() {
            return Err(AccessError::InvalidTableLevelStep { step: level_step });
        }

        let stride_count = parent.stride_count();
        let entries = parent.entries();

        if index >= entries {
            return Err(AccessError::TablePathIndexOutOfRange { index, entries });
        }

        let index_bits = TableGeometry::<F, G>::index_bits() * stride_count.raw();
        let new_len = self.len + 1;

        if self
            .bits_len()
            .checked_add(index_bits)
            .is_none_or(|bits| bits > u128::BITS as u8)
        {
            return Err(AccessError::TablePathCapacityExceeded {
                len: new_len,
                index_bits,
            });
        }
        let stride_shift = self.len.checked_mul(PATH_STRIDE_BITS).ok_or(
            AccessError::TablePathStrideCapacityExceeded {
                len: new_len,
                stride_bits: PATH_STRIDE_BITS,
            },
        )?;
        if stride_shift >= u128::BITS as u8 {
            return Err(AccessError::TablePathStrideCapacityExceeded {
                len: new_len,
                stride_bits: PATH_STRIDE_BITS,
            });
        }

        let shift = self.bits_len() as u32;
        self.bits |= (index as u128) << shift;
        self.index_strides |= ((stride_count.raw() - 1) as u128) << stride_shift;
        self.level_steps |= ((level_step - 1) as u128) << stride_shift;
        self.len = new_len;

        Ok(())
    }

    pub fn entry(&self, root_level: Level, depth: u8) -> Option<TableWalkPathEntry<F, G>> {
        if depth >= self.len {
            return None;
        }

        let mut parent = root_level;
        let mut bit_offset = 0u8;
        for cursor in 0..depth {
            let level_step = self.level_step(cursor)?;
            let index_stride_count = self.index_stride_count(cursor)?;
            parent = Level::new(parent.as_i8() + level_step as i8);
            bit_offset =
                bit_offset.checked_add(TableGeometry::<F, G>::index_bits() * index_stride_count)?;
        }

        let index_stride_count = self.index_stride_count(depth)?;
        let level_step = self.level_step(depth)?;
        let child = Level::new(parent.as_i8() + level_step as i8);
        let mask =
            TableGeometry::<F, G>::checked_index_mask_for_stride_count(index_stride_count)? as u128;
        let index = ((self.bits >> bit_offset) & mask) as usize;
        let parent = TableShape {
            level: parent,
            stride_count: unsafe { TableStrideCount::new_unchecked(index_stride_count) },
            _marker: PhantomData,
        };

        Some(TableWalkPathEntry {
            parent,
            child_level: child,
            index,
        })
    }

    pub fn index(&self, depth: u8) -> Option<usize> {
        let mut bit_offset = 0u8;
        for cursor in 0..depth {
            let index_stride_count = self.index_stride_count(cursor)?;
            bit_offset =
                bit_offset.checked_add(TableGeometry::<F, G>::index_bits() * index_stride_count)?;
        }

        let index_stride_count = self.index_stride_count(depth)?;
        let mask =
            TableGeometry::<F, G>::checked_index_mask_for_stride_count(index_stride_count)? as u128;
        Some(((self.bits >> bit_offset) & mask) as usize)
    }

    pub fn level_index(&self, root_level: Level, level: Level) -> Result<usize, AccessError> {
        if level.is_after(F::FINAL_LEVEL) {
            return Err(AccessError::InvalidTableLevel {
                root_level,
                level,
                final_level: F::FINAL_LEVEL,
            });
        }

        for depth in 0..self.len {
            let entry =
                self.entry(root_level, depth)
                    .ok_or(AccessError::TablePathLevelUnavailable {
                        root_level,
                        level,
                        len: self.len,
                    })?;
            if entry.parent_level() == level {
                return Ok(entry.index());
            }
        }

        Err(AccessError::TablePathLevelUnavailable {
            root_level,
            level,
            len: self.len,
        })
    }

    pub fn terminal_level(&self, root_level: Level) -> Result<Level, AccessError> {
        let mut level = root_level;
        for depth in 0..self.len {
            let entry =
                self.entry(root_level, depth)
                    .ok_or(AccessError::TablePathLevelUnavailable {
                        root_level,
                        level,
                        len: self.len,
                    })?;
            if entry.parent_level() != level {
                return Err(AccessError::TablePathTerminalLevelMismatch {
                    expected: entry.parent_level(),
                    actual: level,
                });
            }
            level = entry.child_level();
        }
        Ok(level)
    }

    fn bits_len(&self) -> u8 {
        let mut bits = 0u8;
        for depth in 0..self.len {
            if let Some(index_stride_count) = self.index_stride_count(depth) {
                bits =
                    bits.saturating_add(TableGeometry::<F, G>::index_bits() * index_stride_count);
            }
        }
        bits
    }

    fn index_stride_count(&self, depth: u8) -> Option<u8> {
        self.stride_count_from(self.index_strides, depth)
    }

    fn level_step(&self, depth: u8) -> Option<u8> {
        self.stride_count_from(self.level_steps, depth)
    }

    fn stride_count_from(&self, stride_counts: u128, depth: u8) -> Option<u8> {
        if depth >= self.len {
            return None;
        }

        let shift = depth.checked_mul(PATH_STRIDE_BITS)?;
        if shift >= u128::BITS as u8 {
            return None;
        }

        let encoded = ((stride_counts >> shift) & PATH_STRIDE_MASK) as u8;
        Some(encoded + 1)
    }

    fn checked_encoded_stride_count(stride_count: u8) -> Option<u8> {
        if stride_count == 0 || stride_count > TableStrideCount::MAX_ENCODED {
            return None;
        }

        Some(stride_count)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableCursor<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    root: TablePhysAddr<G>,
    root_level: Level,
    current: TablePhysAddr<G>,
    shape: TableShape<F, G>,
    path: TableWalkPath<F, G>,
}

impl<F, G> TableCursor<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn root(addr: TablePhysAddr<G>, root_level: Level) -> Self {
        Self {
            root: addr,
            root_level,
            current: addr,
            shape: TableShape::root(root_level),
            path: TableWalkPath::root(),
        }
    }

    pub fn new(
        root: TablePhysAddr<G>,
        root_level: Level,
        current: TablePhysAddr<G>,
        shape: TableShape<F, G>,
        path: TableWalkPath<F, G>,
    ) -> Result<Self, AccessError> {
        if root_level.is_after(shape.level()) || shape.level().is_after(F::FINAL_LEVEL) {
            return Err(AccessError::InvalidTableLevel {
                root_level,
                level: shape.level(),
                final_level: F::FINAL_LEVEL,
            });
        }

        let actual = path.terminal_level(root_level)?;
        if actual != shape.level() {
            return Err(AccessError::TablePathTerminalLevelMismatch {
                expected: shape.level(),
                actual,
            });
        }

        Ok(Self {
            root,
            root_level,
            current,
            shape,
            path,
        })
    }

    pub const fn root_addr(self) -> TablePhysAddr<G> {
        self.root
    }

    pub const fn root_level(self) -> Level {
        self.root_level
    }

    pub const fn current(self) -> TablePhysAddr<G> {
        self.current
    }

    pub const fn shape(self) -> TableShape<F, G> {
        self.shape
    }

    pub const fn level(self) -> Level {
        self.shape.level()
    }

    pub const fn path(self) -> TableWalkPath<F, G> {
        self.path
    }

    pub fn location(self) -> Result<TableAccessLocation<F, G>, AccessError> {
        TableAccessLocation::from_cursor(self)
    }

    pub fn entry_index(self, input: u64) -> Result<usize, AccessError> {
        self.shape
            .index_for_input(input)
            .ok_or(AccessError::InvalidTableLevel {
                root_level: self.root_level,
                level: self.level(),
                final_level: F::FINAL_LEVEL,
            })
    }

    pub fn next_table(
        self,
        entry_index: usize,
        next: NextTable<F, G>,
    ) -> Result<Self, AccessError> {
        if self.level() == F::FINAL_LEVEL {
            return Err(AccessError::InvalidTableLevel {
                root_level: self.root_level,
                level: self.level(),
                final_level: F::FINAL_LEVEL,
            });
        }

        let mut path = self.path;
        path.push(self.root_level, self.shape, next.shape(), entry_index)?;

        Self::new(self.root, self.root_level, next.addr(), next.shape(), path)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableAccessLocation<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    cursor: TableCursor<F, G>,
}

impl<F, G> TableAccessLocation<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn root(addr: TablePhysAddr<G>, root_level: Level) -> Self {
        Self {
            cursor: TableCursor::root(addr, root_level),
        }
    }

    pub fn from_cursor(cursor: TableCursor<F, G>) -> Result<Self, AccessError> {
        TableCursor::new(
            cursor.root_addr(),
            cursor.root_level(),
            cursor.current(),
            cursor.shape(),
            cursor.path(),
        )
        .map(|cursor| Self { cursor })
    }

    pub const fn cursor(self) -> TableCursor<F, G> {
        self.cursor
    }

    pub const fn addr(self) -> TablePhysAddr<G> {
        self.cursor.current()
    }

    pub const fn root_level(self) -> Level {
        self.cursor.root_level()
    }

    pub const fn level(self) -> Level {
        self.cursor.level()
    }

    pub const fn shape(self) -> TableShape<F, G> {
        self.cursor.shape()
    }

    pub const fn path(self) -> TableWalkPath<F, G> {
        self.cursor.path()
    }
}

pub unsafe trait TableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    type Error;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error>;
}

pub unsafe trait TableAccessMut<F, G>: TableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error>;
}
