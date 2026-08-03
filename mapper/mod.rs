mod error;
mod invalidation;
mod plan;
mod reclaim;
mod semantic;
mod types;
mod validate;

pub use self::error::MapperError;
pub use self::invalidation::{Live, MapperInvalidation, MapperMode, Offline};
pub use self::plan::{
    BoundedSklTablePlan, MaxSklTablePlan, StepByOneTablePlan, TablePlan, TablePlanContext,
    TablePlanProvider,
};
pub use self::semantic::{
    SemanticMapperError, decode_semantic_leaf, decode_semantic_table, map_semantic_leaf,
};
pub use self::types::{
    MapLeafOutcome, MapRangeOutcome, Mapping, UnmapOutcome, UnmapReclaimOutcome,
};

use core::marker::PhantomData;

use crate::address::{Level, PhysAddr, TranslationGranule};
use crate::descriptor::{DescriptorFormat, DescriptorKind, DescriptorLayout, HasLayout};
use crate::regime::{LayoutOf, LeafFieldsOf, StageOf, TableFieldsOf, TranslationRegime};
use crate::table::{
    NextTable, RootTable, TableAccessLocation, TableAccessMut, TableError, TableFrame,
    TableFrameProvider, TableTransition,
};
use crate::translation::walk::{WalkCursor, WalkInputAddr, WalkLeaf, WalkStep, Walker};

use self::error::map_walk_error;
use self::validate::{
    add_output, leaf_kind, mapping_size, require_aligned_input, require_aligned_output,
    require_output_address, require_output_range, validate_root,
};

pub struct Mapper<F, R, G, A, P, M>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    root: RootTable<F, G>,
    access: A,
    frames: P,
    mode: M,
    _marker: PhantomData<R>,
}

impl<F, R, G, A, P> Mapper<F, R, G, A, P, Offline>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccessMut<F, G>,
    P: TableFrameProvider<G>,
{
    pub fn new_offline(
        root: RootTable<F, G>,
        access: A,
        frames: P,
    ) -> Result<Self, MapperError<A::Error, P::Error>> {
        validate_root::<F, G, A::Error, P::Error>(root)?;

        Ok(Self {
            root,
            access,
            frames,
            mode: Offline::new(),
            _marker: PhantomData,
        })
    }

    pub fn into_parts(self) -> (RootTable<F, G>, A, P) {
        (self.root, self.access, self.frames)
    }
}

impl<F, R, G, A, P, I> Mapper<F, R, G, A, P, Live<I>>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccessMut<F, G>,
    P: TableFrameProvider<G>,
    I: MapperInvalidation<F, G>,
{
    pub fn new_live(
        root: RootTable<F, G>,
        access: A,
        frames: P,
        invalidation: I,
    ) -> Result<Self, MapperError<A::Error, P::Error>> {
        validate_root::<F, G, A::Error, P::Error>(root)?;

        Ok(Self {
            root,
            access,
            frames,
            mode: Live::new(invalidation),
            _marker: PhantomData,
        })
    }

    pub const fn invalidation(&self) -> &I {
        self.mode.invalidation()
    }

    pub fn invalidation_mut(&mut self) -> &mut I {
        self.mode.invalidation_mut()
    }

    pub fn into_parts(self) -> (RootTable<F, G>, A, P, I) {
        (
            self.root,
            self.access,
            self.frames,
            self.mode.into_invalidation(),
        )
    }
}

impl<F, R, G, A, P, M> Mapper<F, R, G, A, P, M>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
    A: TableAccessMut<F, G>,
    P: TableFrameProvider<G>,
    M: MapperMode<F, G>,
    LeafFieldsOf<F, R, G>: Copy,
{
    pub const fn root(&self) -> RootTable<F, G> {
        self.root
    }

    pub const fn access(&self) -> &A {
        &self.access
    }

    pub fn access_mut(&mut self) -> &mut A {
        &mut self.access
    }

    pub const fn frames(&self) -> &P {
        &self.frames
    }

    pub fn frames_mut(&mut self) -> &mut P {
        &mut self.frames
    }

    pub fn translate(
        &self,
        input: WalkInputAddr,
    ) -> Result<Option<Mapping<F, R, G>>, MapperError<A::Error, P::Error>> {
        self.require_input_addr(input.raw())?;

        let leaf = {
            let walker = self.borrowed_walker()?;
            walker
                .translate(input)
                .map_err(map_walk_error::<A::Error, P::Error>)?
        };

        match leaf {
            Some(leaf) => self.decode_mapping(leaf).map(Some),
            None => Ok(None),
        }
    }

    pub fn map_leaf(
        &mut self,
        input: WalkInputAddr,
        output: PhysAddr,
        level: Level,
        leaf_fields: LeafFieldsOf<F, R, G>,
        table_fields: TableFieldsOf<F, R, G>,
    ) -> Result<MapLeafOutcome, MapperError<A::Error, P::Error>> {
        self.map_leaf_with_plan(
            input,
            output,
            level,
            leaf_fields,
            StepByOneTablePlan::new(table_fields),
        )
    }

    pub fn map_leaf_with_plan<T>(
        &mut self,
        input: WalkInputAddr,
        output: PhysAddr,
        level: Level,
        leaf_fields: LeafFieldsOf<F, R, G>,
        mut planner: T,
    ) -> Result<MapLeafOutcome, MapperError<A::Error, P::Error>>
    where
        T: TablePlanProvider<F, R, G>,
    {
        self.require_leaf_level(level)?;

        let covered_size = mapping_size::<F, G, A::Error, P::Error>(level)?;
        let kind = leaf_kind::<F>(level);

        require_aligned_input::<A::Error, P::Error>(input.raw(), covered_size)?;
        require_aligned_output::<A::Error, P::Error>(output, covered_size)?;
        self.require_input_range(input.raw(), covered_size)?;
        require_output_range::<A::Error, P::Error>(
            output,
            covered_size,
            self.root.output_addr_bits(),
        )?;

        let leaf_raw = <LayoutOf<F, R, G> as DescriptorLayout<F, StageOf<R>, G>>::leaf_descriptor(
            output,
            level,
            leaf_fields,
        )?;

        let mut cursor = self.cursor(input)?;
        let mut tables_allocated = 0u8;

        loop {
            let step = {
                let walker = self.borrowed_walker()?;
                walker
                    .step(cursor)
                    .map_err(map_walk_error::<A::Error, P::Error>)?
            };

            match step {
                WalkStep::Invalid(invalid) => {
                    if invalid.level().is_after(level) {
                        return Err(MapperError::InvalidLeafLevel {
                            level,
                            root_level: self.root.level(),
                            final_level: F::FINAL_LEVEL,
                        });
                    }

                    if invalid.level() == level {
                        let old = self.write_descriptor(
                            invalid.location(),
                            invalid.entry_index(),
                            leaf_raw,
                        )?;

                        self.mode.leaf_inserted(
                            invalid.location(),
                            invalid.entry_index(),
                            old,
                            leaf_raw,
                        );
                        self.mode.synchronize();

                        return Ok(MapLeafOutcome {
                            tables_allocated,
                            level,
                            kind,
                            covered_size,
                        });
                    }

                    let parent_shape = invalid.location().shape();
                    let plan =
                        planner.plan_table(TablePlanContext::new(parent_shape, level, input))?;
                    let child_shape = plan.child_shape();
                    let transition = TableTransition::new(parent_shape, child_shape)?;
                    let layout = child_shape.alloc_layout()?;

                    let frame = self
                        .frames
                        .allocate_zeroed_table(layout)
                        .map_err(MapperError::Frame)?;
                    child_shape.validate_base(frame.phys())?;
                    require_output_address::<A::Error, P::Error>(
                        frame.phys(),
                        self.root.output_addr_bits(),
                    )?;

                    let table_raw =
                        <LayoutOf<F, R, G> as DescriptorLayout<F, StageOf<R>, G>>::table_descriptor(
                            frame.phys(),
                            transition,
                            plan.into_fields(),
                        )?;
                    let next = NextTable::<F, G>::new(
                        frame.addr(),
                        child_shape.level(),
                        child_shape.stride_count().raw(),
                    )?;

                    let old = self.write_descriptor(
                        invalid.location(),
                        invalid.entry_index(),
                        table_raw,
                    )?;

                    self.mode.table_inserted(
                        invalid.location(),
                        invalid.entry_index(),
                        old,
                        table_raw,
                    );
                    self.mode.synchronize();

                    tables_allocated = tables_allocated
                        .checked_add(1)
                        .ok_or(MapperError::AddressOverflow)?;

                    cursor = invalid.cursor().next_table(invalid.entry_index(), next)?;
                }
                WalkStep::Table(table) => {
                    if table.level() == level {
                        return Err(MapperError::AlreadyMapped {
                            input,
                            level: table.level(),
                            entry_index: table.entry_index(),
                        });
                    }

                    cursor = table.next_cursor();
                }
                WalkStep::Leaf(leaf) => {
                    return Err(MapperError::AlreadyMapped {
                        input,
                        level: leaf.level(),
                        entry_index: leaf.entry_index(),
                    });
                }
            }
        }
    }

    pub fn map_range(
        &mut self,
        input_start: WalkInputAddr,
        output_start: PhysAddr,
        len: u64,
        level: Level,
        leaf_fields: LeafFieldsOf<F, R, G>,
        table_fields: TableFieldsOf<F, R, G>,
    ) -> Result<MapRangeOutcome, MapperError<A::Error, P::Error>> {
        self.require_leaf_level(level)?;

        if len == 0 {
            return Ok(MapRangeOutcome {
                mappings_created: 0,
                bytes_mapped: 0,
                tables_allocated: 0,
            });
        }

        let mapping_size = mapping_size::<F, G, A::Error, P::Error>(level)?;

        require_aligned_input::<A::Error, P::Error>(input_start.raw(), mapping_size)?;
        require_aligned_output::<A::Error, P::Error>(output_start, mapping_size)?;

        if len % mapping_size != 0 {
            return Err(MapperError::LengthNotMappingMultiple { len, mapping_size });
        }

        self.require_input_range(input_start.raw(), len)?;
        require_output_range::<A::Error, P::Error>(
            output_start,
            len,
            self.root.output_addr_bits(),
        )?;

        let mut input = input_start.raw();
        let mut output = output_start;
        let mut mappings_created = 0u64;
        let mut bytes_mapped = 0u64;
        let mut tables_allocated = 0u64;

        while bytes_mapped < len {
            let outcome = self.map_leaf(
                WalkInputAddr::new(input),
                output,
                level,
                leaf_fields,
                table_fields,
            )?;

            mappings_created = mappings_created
                .checked_add(1)
                .ok_or(MapperError::AddressOverflow)?;
            bytes_mapped = bytes_mapped
                .checked_add(mapping_size)
                .ok_or(MapperError::AddressOverflow)?;
            tables_allocated = tables_allocated
                .checked_add(u64::from(outcome.tables_allocated()))
                .ok_or(MapperError::AddressOverflow)?;
            input = input
                .checked_add(mapping_size)
                .ok_or(MapperError::AddressOverflow)?;
            output = add_output::<A::Error, P::Error>(output, mapping_size)?;
        }

        Ok(MapRangeOutcome {
            mappings_created,
            bytes_mapped,
            tables_allocated,
        })
    }

    pub fn unmap(
        &mut self,
        input: WalkInputAddr,
    ) -> Result<UnmapOutcome<F, R, G>, MapperError<A::Error, P::Error>> {
        self.require_input_addr(input.raw())?;

        let leaf = {
            let walker = self.borrowed_walker()?;
            let Some(leaf) = walker
                .translate(input)
                .map_err(map_walk_error::<A::Error, P::Error>)?
            else {
                return Err(MapperError::NotMapped { input });
            };

            leaf
        };

        self.require_leaf_base(input, leaf.level())?;

        let old_mapping = self.decode_mapping(leaf)?;
        let old = self.write_descriptor(leaf.location(), leaf.entry_index(), F::invalid())?;

        self.mode
            .leaf_removed(leaf.location(), leaf.entry_index(), old);
        self.mode.synchronize();

        Ok(UnmapOutcome { old: old_mapping })
    }

    pub fn unmap_reclaim(
        &mut self,
        input: WalkInputAddr,
    ) -> Result<UnmapReclaimOutcome<F, R, G>, MapperError<A::Error, P::Error>> {
        self.require_input_addr(input.raw())?;

        let cursor = self.cursor(input)?;
        let result = self.unmap_reclaim_at(input, cursor)?;

        Ok(UnmapReclaimOutcome {
            old: result.old,
            tables_freed: result.tables_freed,
            root_now_empty: result.current_table_empty,
        })
    }

    pub(super) fn borrowed_walker(
        &self,
    ) -> Result<Walker<F, R::WalkProfile, G, &A>, MapperError<A::Error, P::Error>> {
        Walker::<F, R::WalkProfile, G, _>::new(self.root.addr(), self.root.level(), &self.access)
            .map_err(Into::into)
    }

    fn cursor(
        &self,
        input: WalkInputAddr,
    ) -> Result<WalkCursor<F, G>, MapperError<A::Error, P::Error>> {
        self.borrowed_walker()?.cursor(input).map_err(Into::into)
    }

    pub(super) fn decode_mapping(
        &self,
        leaf: WalkLeaf<F, R::WalkProfile, G>,
    ) -> Result<Mapping<F, R, G>, MapperError<A::Error, P::Error>> {
        let input = leaf.cursor().input();
        let covered_size = mapping_size::<F, G, A::Error, P::Error>(leaf.level())?;
        let covered_input_base = input.raw() & !(covered_size - 1);

        Ok(Mapping {
            input,
            output: leaf.output(),
            output_base: leaf.output_base(),
            covered_input_base,
            covered_size,
            level: leaf.level(),
            entry_index: leaf.entry_index(),
            raw: leaf.raw(),
            kind: leaf.kind(),
            fields: *leaf.fields(),
        })
    }

    pub(super) fn write_descriptor(
        &mut self,
        location: TableAccessLocation<F, G>,
        index: usize,
        raw: F::Raw,
    ) -> Result<F::Raw, MapperError<A::Error, P::Error>> {
        let mut table = self
            .access
            .table_at_mut(location)
            .map_err(MapperError::Access)?;

        let old = table.read(index).ok_or(TableError::EntryIndexOutOfRange {
            index,
            entries: table.entries(),
        })?;

        table.write(index, raw)?;

        Ok(old)
    }

    pub(super) fn table_has_valid_entries_except(
        &self,
        location: TableAccessLocation<F, G>,
        level: Level,
        excluded_index: usize,
    ) -> Result<bool, MapperError<A::Error, P::Error>> {
        let table = self
            .access
            .table_at(location)
            .map_err(MapperError::Access)?;

        let entries = table.entries();

        if excluded_index >= entries {
            return Err(MapperError::Table(TableError::EntryIndexOutOfRange {
                index: excluded_index,
                entries,
            }));
        }

        for index in 0..entries {
            if index == excluded_index {
                continue;
            }

            let raw = table
                .read(index)
                .ok_or(TableError::EntryIndexOutOfRange { index, entries })?;

            if <LayoutOf<F, R, G> as DescriptorLayout<F, StageOf<R>, G>>::kind(raw, level)
                != DescriptorKind::Invalid
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn require_input_addr(&self, addr: u64) -> Result<(), MapperError<A::Error, P::Error>> {
        validate::require_input_addr::<A::Error, P::Error>(addr, self.root.addr_bits())
    }

    fn require_input_range(
        &self,
        start: u64,
        len: u64,
    ) -> Result<(), MapperError<A::Error, P::Error>> {
        if len == 0 {
            return Ok(());
        }

        let end = start
            .checked_add(len - 1)
            .ok_or(MapperError::AddressOverflow)?;

        self.require_input_addr(start)?;
        self.require_input_addr(end)
    }

    fn require_leaf_level(&self, level: Level) -> Result<(), MapperError<A::Error, P::Error>> {
        if level.is_before(self.root.level())
            || level.is_after(F::FINAL_LEVEL)
            || !F::supports_leaf_level::<G>(level)
        {
            return Err(MapperError::InvalidLeafLevel {
                level,
                root_level: self.root.level(),
                final_level: F::FINAL_LEVEL,
            });
        }

        Ok(())
    }

    pub(super) fn require_leaf_base(
        &self,
        input: WalkInputAddr,
        level: Level,
    ) -> Result<(), MapperError<A::Error, P::Error>> {
        let covered_size = mapping_size::<F, G, A::Error, P::Error>(level)?;
        let covered_input_base = input.raw() & !(covered_size - 1);

        if input.raw() == covered_input_base {
            Ok(())
        } else {
            Err(MapperError::InputNotLeafBase {
                input,
                covered_input_base,
                covered_size,
                level,
            })
        }
    }
}
