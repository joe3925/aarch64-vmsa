use crate::address::TranslationGranule;
use crate::descriptor::DescriptorFormat;
use crate::table::{TableAccessLocation, TableAllocLayout, TablePhysAddr};

pub trait MapperInvalidation<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn leaf_inserted(
        &mut self,
        location: TableAccessLocation<F, G>,
        index: usize,
        old: F::Raw,
        new: F::Raw,
    );

    fn leaf_removed(&mut self, location: TableAccessLocation<F, G>, index: usize, old: F::Raw);

    fn table_descriptor_inserted(
        &mut self,
        location: TableAccessLocation<F, G>,
        index: usize,
        old: F::Raw,
        new: F::Raw,
    );

    fn table_descriptor_removed(
        &mut self,
        location: TableAccessLocation<F, G>,
        index: usize,
        old: F::Raw,
    );

    fn before_table_frame_reclaim(&mut self, table: TablePhysAddr<G>, layout: TableAllocLayout);

    fn synchronize(&mut self);
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Offline {
    _private: (),
}

impl Offline {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Live<I> {
    invalidation: I,
}

impl<I> Live<I> {
    pub(crate) const fn new(invalidation: I) -> Self {
        Self { invalidation }
    }

    pub const fn invalidation(&self) -> &I {
        &self.invalidation
    }

    pub fn invalidation_mut(&mut self) -> &mut I {
        &mut self.invalidation
    }

    pub(crate) fn into_invalidation(self) -> I {
        self.invalidation
    }
}

mod private {
    pub trait Sealed {}
}

impl private::Sealed for Offline {}
impl<I> private::Sealed for Live<I> {}

#[doc(hidden)]
pub trait MapperMode<F, G>: private::Sealed
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn leaf_inserted(
        &mut self,
        location: TableAccessLocation<F, G>,
        index: usize,
        old: F::Raw,
        new: F::Raw,
    );
    fn leaf_removed(&mut self, location: TableAccessLocation<F, G>, index: usize, old: F::Raw);
    fn table_inserted(
        &mut self,
        location: TableAccessLocation<F, G>,
        index: usize,
        old: F::Raw,
        new: F::Raw,
    );
    fn table_removed(&mut self, location: TableAccessLocation<F, G>, index: usize, old: F::Raw);
    fn before_reclaim(&mut self, table: TablePhysAddr<G>, layout: TableAllocLayout);
    fn synchronize(&mut self);
}

impl<F, G> MapperMode<F, G> for Offline
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn leaf_inserted(
        &mut self,
        _location: TableAccessLocation<F, G>,
        _index: usize,
        _old: F::Raw,
        _new: F::Raw,
    ) {
    }

    fn leaf_removed(&mut self, _location: TableAccessLocation<F, G>, _index: usize, _old: F::Raw) {}

    fn table_inserted(
        &mut self,
        _location: TableAccessLocation<F, G>,
        _index: usize,
        _old: F::Raw,
        _new: F::Raw,
    ) {
    }

    fn table_removed(&mut self, _location: TableAccessLocation<F, G>, _index: usize, _old: F::Raw) {
    }

    fn before_reclaim(&mut self, _table: TablePhysAddr<G>, _layout: TableAllocLayout) {}
    fn synchronize(&mut self) {}
}

impl<F, G, I> MapperMode<F, G> for Live<I>
where
    F: DescriptorFormat,
    G: TranslationGranule,
    I: MapperInvalidation<F, G>,
{
    fn leaf_inserted(
        &mut self,
        location: TableAccessLocation<F, G>,
        index: usize,
        old: F::Raw,
        new: F::Raw,
    ) {
        self.invalidation.leaf_inserted(location, index, old, new);
    }

    fn leaf_removed(&mut self, location: TableAccessLocation<F, G>, index: usize, old: F::Raw) {
        self.invalidation.leaf_removed(location, index, old);
    }

    fn table_inserted(
        &mut self,
        location: TableAccessLocation<F, G>,
        index: usize,
        old: F::Raw,
        new: F::Raw,
    ) {
        self.invalidation
            .table_descriptor_inserted(location, index, old, new);
    }

    fn table_removed(&mut self, location: TableAccessLocation<F, G>, index: usize, old: F::Raw) {
        self.invalidation
            .table_descriptor_removed(location, index, old);
    }

    fn before_reclaim(&mut self, table: TablePhysAddr<G>, layout: TableAllocLayout) {
        self.invalidation.before_table_frame_reclaim(table, layout);
    }

    fn synchronize(&mut self) {
        self.invalidation.synchronize();
    }
}
