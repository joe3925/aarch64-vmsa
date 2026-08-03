use crate::address::TranslationGranule;
use crate::descriptor::{DescriptorFormat, HasLayout};
use crate::regime::{LeafFieldsOf, StageOf, TranslationRegime};
use crate::table::{TableAccessMut, TableFrameProvider};
use crate::translation::walk::{WalkCursor, WalkInputAddr, WalkStep};

use super::error::map_walk_error;
use super::{Mapper, MapperError, MapperMode, Mapping};

pub(super) struct UnmapReclaimStep<F, R, G>
where
    F: DescriptorFormat + HasLayout<StageOf<R>, G>,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub(super) old: Mapping<F, R, G>,
    pub(super) current_table_empty: bool,
    pub(super) tables_freed: u8,
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
    pub(super) fn unmap_reclaim_at(
        &mut self,
        input: WalkInputAddr,
        cursor: WalkCursor<F, G>,
    ) -> Result<UnmapReclaimStep<F, R, G>, MapperError<A::Error, P::Error>> {
        let step = {
            let walker = self.borrowed_walker()?;
            walker
                .step(cursor)
                .map_err(map_walk_error::<A::Error, P::Error>)?
        };

        match step {
            WalkStep::Invalid(_) => Err(MapperError::NotMapped { input }),

            WalkStep::Leaf(leaf) => {
                self.require_leaf_base(input, leaf.level())?;

                let current_table_has_other_valid_entries = self.table_has_valid_entries_except(
                    leaf.location(),
                    leaf.level(),
                    leaf.entry_index(),
                )?;

                let old_mapping = self.decode_mapping(leaf)?;
                let old =
                    self.write_descriptor(leaf.location(), leaf.entry_index(), F::invalid())?;

                self.mode
                    .leaf_removed(leaf.location(), leaf.entry_index(), old);
                self.mode.synchronize();

                Ok(UnmapReclaimStep {
                    old: old_mapping,
                    current_table_empty: !current_table_has_other_valid_entries,
                    tables_freed: 0,
                })
            }

            WalkStep::Table(table) => {
                let current_table_has_other_valid_entries = self.table_has_valid_entries_except(
                    table.location(),
                    table.level(),
                    table.entry_index(),
                )?;

                let child = table.next_table();
                let mut child_result = self.unmap_reclaim_at(input, table.next_cursor())?;

                if child_result.current_table_empty {
                    let layout = child.shape().alloc_layout()?;
                    let old =
                        self.write_descriptor(table.location(), table.entry_index(), F::invalid())?;

                    self.mode
                        .table_removed(table.location(), table.entry_index(), old);
                    self.mode.synchronize();
                    self.mode.before_reclaim(child.addr(), layout);
                    self.mode.synchronize();

                    unsafe {
                        self.frames
                            .free_table(child.addr(), layout)
                            .map_err(MapperError::Frame)?;
                    }

                    child_result.tables_freed = child_result
                        .tables_freed
                        .checked_add(1)
                        .ok_or(MapperError::AddressOverflow)?;
                }

                Ok(UnmapReclaimStep {
                    old: child_result.old,
                    current_table_empty: !current_table_has_other_valid_entries
                        && child_result.current_table_empty,
                    tables_freed: child_result.tables_freed,
                })
            }
        }
    }
}
