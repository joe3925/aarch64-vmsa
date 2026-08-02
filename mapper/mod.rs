mod error;
mod invalidation;
mod types;
mod validate;

pub use self::error::MapperError;
pub use self::invalidation::{Live, MapperInvalidation, MapperMode, Offline};
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

    pub(super) fn borrowed_walker(
        &self,
    ) -> Result<Walker<F, R::WalkProfile, G, &A>, MapperError<A::Error, P::Error>> {
        Walker::<F, R::WalkProfile, G, _>::new(self.root.addr(), self.root.level(), &self.access)
            .map_err(Into::into)
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

    fn require_input_addr(&self, addr: u64) -> Result<(), MapperError<A::Error, P::Error>> {
        validate::require_input_addr::<A::Error, P::Error>(addr, self.root.addr_bits())
    }
}
