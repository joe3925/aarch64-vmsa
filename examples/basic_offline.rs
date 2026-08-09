use std::alloc::{Layout, LayoutError, alloc_zeroed, dealloc, handle_alloc_error};
use std::marker::PhantomData;
use std::ptr::NonNull;

use aarch64_vmsa::address::PhysAddr;
use aarch64_vmsa::attrs::{
    AllocationHints, CachePolicy, Cacheability, DataAccess, DirtyBitManagement, MemoryAttributes,
    MemoryTransience, SemanticLeafAttrs, SemanticTableAttrs, SemanticVmsa64Stage1LeafControls,
    SemanticVmsa64Stage1TableControls, Shareability, SoftwareMetadata, Stage1MemoryConfig,
    TwoPrivilegeLeafPermissions, TwoPrivilegeTablePermissionLimits,
};
use aarch64_vmsa::config::format::Vmsa64;
use aarch64_vmsa::config::granule::Granule4KiB;
use aarch64_vmsa::config::regime::NonSecureEl1Stage1;
use aarch64_vmsa::format::DescriptorFormat;
use aarch64_vmsa::granule::{Level, TranslationGranule};
use aarch64_vmsa::mapper;
use aarch64_vmsa::table::{
    AccessError, RootTable, RootTableGeometry, TableAccess, TableAccessLocation, TableAccessMut,
    TableAddr, TableAllocLayout, TableFrameProvider, TableReclaim, TableShape, TranslationTable,
    TranslationTableMut,
};

use aarch64_vmsa::translation::WalkInputAddr;

struct ExampleConfig;

impl Stage1MemoryConfig for ExampleConfig {
    fn mair(&self) -> u64 {
        0xff
    }
}

struct TableProvider<G: TranslationGranule>(PhantomData<G>);
struct TableAccessor<F: DescriptorFormat, G: TranslationGranule>(PhantomData<(F, G)>);

// SAFETY: Each table has the requested size and alignment. Its memory stays available while used.
unsafe impl<G: TranslationGranule> TableFrameProvider<G> for TableProvider<G> {
    type Error = LayoutError;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<G>, Self::Error> {
        let layout = Layout::from_size_align(layout.bytes() as usize, layout.align() as usize)?;
        // SAFETY: The size and alignment are valid.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            handle_alloc_error(layout);
        }
        Ok(TableAddr::new(ptr as u64).expect("allocator returned an unaligned table"))
    }

    fn reclaim_table(&mut self, reclaim: TableReclaim<G>) -> Result<(), Self::Error> {
        let layout = reclaim.layout();
        let layout = Layout::from_size_align(layout.bytes() as usize, layout.align() as usize)?;
        // SAFETY: The address, size, and alignment match the allocated memory.
        unsafe { dealloc(reclaim.addr().raw() as *mut u8, layout) };
        Ok(())
    }
}

// SAFETY: Each address points to table memory that stays available while the table is used.
unsafe impl<F: DescriptorFormat, G: TranslationGranule> TableAccess<F, G> for TableAccessor<F, G> {
    type Error = AccessError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        let ptr =
            NonNull::new(location.addr().raw() as *mut F::Raw).ok_or(AccessError::NullMapping)?;
        // SAFETY: The table memory stays available while the mapper uses it.
        Ok(unsafe { TranslationTable::from_raw_parts(ptr, location.shape()) })
    }
}

// SAFETY: No other software changes the table while the mapper changes it.
unsafe impl<F: DescriptorFormat, G: TranslationGranule> TableAccessMut<F, G>
    for TableAccessor<F, G>
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error> {
        let ptr =
            NonNull::new(location.addr().raw() as *mut F::Raw).ok_or(AccessError::NullMapping)?;
        // SAFETY: Only the mapper can change this table while it uses the returned value.
        Ok(unsafe { TranslationTableMut::from_raw_parts(ptr, location.shape()) })
    }
}

fn main() {
    let mut table_provider = TableProvider::<Granule4KiB>(PhantomData);
    let table_accessor = TableAccessor::<Vmsa64, Granule4KiB>(PhantomData);
    let geometry = RootTableGeometry::new(
        table_provider
            .allocate_zeroed_table(
                TableShape::<Vmsa64, Granule4KiB>::new(Level::L0, 1)
                    .expect("invalid root shape")
                    .alloc_layout()
                    .expect("invalid root layout"),
            )
            .expect("failed to heap alloc table"),
        48,
        48,
    )
    .expect("invalid root geometry");
    let root_table = RootTable::<_, NonSecureEl1Stage1, _>::from_geometry(geometry);
    let mut mapper = mapper::Mapper::new_offline(root_table, table_accessor, table_provider)
        .expect("failed to create basic mapper");

    let write_back = Cacheability::Cacheable {
        policy: CachePolicy::WriteBack,
        transience: MemoryTransience::NonTransient,
        allocation: AllocationHints::ReadWriteAllocate,
    };

    let leaf_attrs = SemanticLeafAttrs::<Vmsa64, NonSecureEl1Stage1> {
        memory: MemoryAttributes::Normal {
            inner: write_back,
            outer: write_back,
        },
        permissions: TwoPrivilegeLeafPermissions {
            privileged_data: DataAccess::ReadWrite,
            unprivileged_data: DataAccess::None,
            privileged_execute: false,
            unprivileged_execute: false,
        },
        pas: (),
        controls: SemanticVmsa64Stage1LeafControls {
            shareability: Shareability::InnerShareable,
            access_flag: true,
            global: true,
            dirty_management: DirtyBitManagement::SoftwareManaged,
            contiguous: false,
            guarded: false,
            software: SoftwareMetadata::new(0),
        },
    };

    let table_attrs = SemanticTableAttrs::<Vmsa64, NonSecureEl1Stage1> {
        permission_limits: TwoPrivilegeTablePermissionLimits {
            privileged_data_limit: DataAccess::ReadWrite,
            unprivileged_data_limit: DataAccess::ReadWrite,
            privileged_execute_limit: true,
            unprivileged_execute_limit: true,
        },
        pas: (),
        controls: SemanticVmsa64Stage1TableControls::default(),
    };

    mapper
        .map_semantic_leaf(
            &ExampleConfig,
            WalkInputAddr::new(0x100_000),
            PhysAddr(0x1000),
            Level::L3,
            leaf_attrs,
            table_attrs,
        )
        .expect("failed to map page");

    let mapping = mapper
        .translate(WalkInputAddr::new(0x100_000))
        .expect("failed to walk mapping")
        .expect("mapping was not found");
    let decoded_attrs = mapping
        .semantic_attrs(&ExampleConfig)
        .expect("failed to decode semantic attributes");
    assert!(decoded_attrs == leaf_attrs);
}
