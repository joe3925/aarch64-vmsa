use core::marker::PhantomData;

use crate::address::{Level, PhysAddr, TranslationGranule};
use crate::attrs::{
    FourBit, RawShareability, RawSmmuV2Stage2LeafAttrs, RawVmsa64Stage2TableAttrs, Stage2Ap, TwoBit,
};
use crate::config::format::{DescriptorEndian, Vmsa64};
use crate::descriptor::layout::smmu_v2 as bits;
use crate::table::{TableAddr, TableTransition};
use crate::translation::Stage2;

use super::{
    DescriptorError, DescriptorKind, DescriptorLayout, align_output, insert_address,
    require_step_by_one_transition,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmmuV2Vmsa64Stage2Layout<E, G>(PhantomData<(E, G)>);

impl<E, G> super::private::LayoutSealed for SmmuV2Vmsa64Stage2Layout<E, G> {}

impl<E: DescriptorEndian, G: TranslationGranule> DescriptorLayout<Stage2, G>
    for SmmuV2Vmsa64Stage2Layout<E, G>
{
    type Format = Vmsa64<E>;
    type LeafFields = RawSmmuV2Stage2LeafAttrs;
    type TableFields = RawVmsa64Stage2TableAttrs;

    const ADDRESS_FIELD_MASK: u128 = bits::ADDRESS_FIELD_MASK;

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        let kind = super::vmsa64::kind(G::KIND, raw, level);
        let raw = raw as u128;
        let valid = match kind {
            DescriptorKind::Block | DescriptorKind::Page => {
                raw & bits::stage2_leaf::RES0_MASK == 0
                    && bits::RACFG.extract(raw) != 0b01
                    && bits::WACFG.extract(raw) != 0b01
            }
            DescriptorKind::Table => {
                raw & bits::stage2_table::RES0_MASK == 0
                    && raw & bits::stage2_table::RES1_MASK == bits::stage2_table::RES1_MASK
            }
            DescriptorKind::Invalid => true,
        };
        if valid { kind } else { DescriptorKind::Invalid }
    }

    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let raw = raw as u128;
        RawSmmuV2Stage2LeafAttrs {
            mem_attr: FourBit::from_masked(bits::MEM_ATTR.extract(raw)),
            permissions: Stage2Ap::from_bits(bits::S2AP.extract(raw) as u8)
                .expect("masked S2AP is two bits"),
            shareability: RawShareability::from_masked(bits::SHAREABILITY.extract(raw)),
            access_flag: bits::ACCESS_FLAG.extract(raw) != 0,
            contiguous: bits::CONTIGUOUS.extract(raw) != 0,
            execute_never: bits::XN.extract(raw) != 0,
            software: FourBit::from_masked(bits::SOFTWARE.extract(raw)),
            read_allocate: TwoBit::from_masked(bits::RACFG.extract(raw)),
            write_allocate: TwoBit::from_masked(bits::WACFG.extract(raw)),
        }
    }

    fn decode_table_fields(raw: u64, _level: Level) -> Self::TableFields {
        let raw = raw as u128;
        RawVmsa64Stage2TableAttrs {
            access_flag: bits::ACCESS_FLAG.extract(raw) != 0,
            software: FourBit::from_masked(bits::SOFTWARE.extract(raw)),
        }
    }

    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        f: Self::LeafFields,
    ) -> Result<u64, DescriptorError> {
        if !super::vmsa64::supports_leaf_level(G::KIND, level) {
            return Err(DescriptorError::InvalidLeafLevel { level });
        }
        if f.read_allocate.bits() == 0b01 {
            return Err(DescriptorError::ReservedFieldSet { bit: 60 });
        }
        if f.write_allocate.bits() == 0b01 {
            return Err(DescriptorError::ReservedFieldSet { bit: 62 });
        }

        let mut raw = 0;
        raw = insert_address(raw, output_pa.0, Self::ADDRESS_FIELD_MASK);
        raw = bits::MEM_ATTR.insert(raw, f.mem_attr.bits().into());
        raw = bits::S2AP.insert(raw, f.permissions.bits().into());
        raw = bits::SHAREABILITY.insert(raw, f.shareability.bits().into());
        raw = bits::ACCESS_FLAG.insert(raw, f.access_flag.into());
        raw = bits::CONTIGUOUS.insert(raw, f.contiguous.into());
        raw = bits::XN.insert(raw, f.execute_never.into());
        raw = bits::SOFTWARE.insert(raw, f.software.bits().into());
        raw = bits::RACFG.insert(raw, f.read_allocate.bits().into());
        raw = bits::WACFG.insert(raw, f.write_allocate.bits().into());
        raw |= super::vmsa64::leaf_kind_bits(G::KIND, level) as u128;
        Ok(raw as u64)
    }

    fn table_descriptor(
        table_addr: TableAddr<G>,
        transition: TableTransition<Vmsa64<E>, G>,
        f: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let mut raw = 0;
        raw = insert_address(raw, table_addr.raw(), Self::ADDRESS_FIELD_MASK);
        raw = bits::ACCESS_FLAG.insert(raw, f.access_flag.into());
        raw = bits::SOFTWARE.insert(raw, f.software.bits().into());
        raw = bits::VALID.insert(raw, 1);
        raw = bits::TABLE_OR_PAGE.insert(raw, 1);
        Ok(raw as u64)
    }

    fn output_address(raw: u64, level: Level) -> PhysAddr {
        let address = (raw as u128 & Self::ADDRESS_FIELD_MASK) as u64;
        PhysAddr(align_output::<Vmsa64<E>, G>(address, level))
    }

    fn table_address(raw: u64, _level: Level) -> TableAddr<G> {
        let address = (raw as u128 & Self::ADDRESS_FIELD_MASK) as u64 & !(G::SIZE - 1);
        // SAFETY: the mask above clears every granule-offset bit.
        unsafe { TableAddr::new_unchecked(address) }
    }
}
