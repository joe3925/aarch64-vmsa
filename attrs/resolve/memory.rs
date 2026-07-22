use super::{Stage1MemoryConfig, Stage2MemoryConfig, Stage2MemoryMode};
use crate::attrs::{
    AllocationHints, AttrError, CachePolicy, Cacheability, DeviceMemoryType, FourBit,
    FwbStage2Memory, MemoryAttributes, MemoryTransience, Stage2MemoryAttributes, ThreeBit,
};

pub fn resolve_stage1_memory_3<C: Stage1MemoryConfig>(
    config: &C,
    attrs: MemoryAttributes,
) -> Result<ThreeBit, AttrError> {
    let wanted = encode_mair_attribute(attrs)?;
    for index in 0..8 {
        if mair_entry(config.mair(), index) == wanted {
            return ThreeBit::new(index);
        }
    }
    Err(AttrError::MemoryAttributeNotConfigured)
}

pub fn resolve_stage1_memory_4<C: Stage1MemoryConfig>(
    config: &C,
    attrs: MemoryAttributes,
) -> Result<FourBit, AttrError> {
    let wanted = encode_mair_attribute(attrs)?;
    for index in 0..8 {
        if mair_entry(config.mair(), index) == wanted {
            return FourBit::new(index);
        }
    }
    if let Some(mair2) = config.mair2() {
        for index in 0..8 {
            if mair_entry(mair2, index) == wanted {
                return FourBit::new(index + 8);
            }
        }
    }
    Err(AttrError::MemoryAttributeNotConfigured)
}

pub fn decode_stage1_memory_3<C: Stage1MemoryConfig>(
    config: &C,
    index: ThreeBit,
) -> Result<MemoryAttributes, AttrError> {
    decode_mair_attribute(mair_entry(config.mair(), index.bits()))
        .ok_or(AttrError::UnencodableMemoryAttribute)
}

pub fn decode_stage1_memory_4<C: Stage1MemoryConfig>(
    config: &C,
    index: FourBit,
) -> Result<MemoryAttributes, AttrError> {
    let entry = if index.bits() < 8 {
        mair_entry(config.mair(), index.bits())
    } else {
        mair_entry(
            config.mair2().ok_or(AttrError::Mair2Unavailable)?,
            index.bits() - 8,
        )
    };
    decode_mair_attribute(entry).ok_or(AttrError::UnencodableMemoryAttribute)
}

pub fn resolve_stage2_memory<C: Stage2MemoryConfig>(
    config: &C,
    attrs: Stage2MemoryAttributes,
) -> Result<FourBit, AttrError> {
    let bits = match (config.stage2_memory_mode(), attrs) {
        (Stage2MemoryMode::FwbDisabled, Stage2MemoryAttributes::Combined(attrs)) => {
            encode_stage2_combined(attrs)?
        }
        (Stage2MemoryMode::FwbEnabled { mte_permission }, Stage2MemoryAttributes::Fwb(attrs)) => {
            encode_stage2_fwb(attrs, mte_permission)?
        }
        _ => return Err(AttrError::WrongStage2MemoryMode),
    };
    FourBit::new(bits)
}

pub fn decode_stage2_memory<C: Stage2MemoryConfig>(
    config: &C,
    encoding: FourBit,
) -> Result<Stage2MemoryAttributes, AttrError> {
    match config.stage2_memory_mode() {
        Stage2MemoryMode::FwbDisabled => decode_stage2_combined(encoding.bits())
            .map(Stage2MemoryAttributes::Combined)
            .ok_or(AttrError::UnencodableMemoryAttribute),
        Stage2MemoryMode::FwbEnabled { mte_permission } => {
            decode_stage2_fwb(encoding.bits(), mte_permission)
                .map(Stage2MemoryAttributes::Fwb)
                .ok_or(AttrError::UnencodableMemoryAttribute)
        }
    }
}

fn mair_entry(register: u64, index: u8) -> u8 {
    debug_assert!(index < 8);
    (register >> (u32::from(index) * 8)) as u8
}

fn encode_mair_attribute(attrs: MemoryAttributes) -> Result<u8, AttrError> {
    match attrs {
        MemoryAttributes::Device(device) => Ok(encode_device(device) << 2),
        MemoryAttributes::Normal { inner, outer } => {
            Ok(encode_mair_cacheability(inner)? | encode_mair_cacheability(outer)? << 4)
        }
    }
}

fn encode_mair_cacheability(value: Cacheability) -> Result<u8, AttrError> {
    match value {
        Cacheability::NonCacheable => Ok(0b0100),
        Cacheability::Cacheable {
            policy,
            transience,
            allocation,
        } => {
            let high = match (policy, transience) {
                (CachePolicy::WriteThrough, MemoryTransience::Transient) => 0b0000,
                (CachePolicy::WriteBack, MemoryTransience::Transient) => 0b0100,
                (CachePolicy::WriteThrough, MemoryTransience::NonTransient) => 0b1000,
                (CachePolicy::WriteBack, MemoryTransience::NonTransient) => 0b1100,
            };
            let low = match allocation {
                AllocationHints::None => 0,
                AllocationHints::WriteAllocate => 1,
                AllocationHints::ReadAllocate => 2,
                AllocationHints::ReadWriteAllocate => 3,
            };
            if transience == MemoryTransience::Transient && low == 0 {
                Err(AttrError::UnencodableMemoryAttribute)
            } else {
                Ok(high | low)
            }
        }
    }
}

fn decode_mair_attribute(entry: u8) -> Option<MemoryAttributes> {
    if entry >> 4 == 0 {
        return decode_device(entry >> 2)
            .map(MemoryAttributes::Device)
            .filter(|_| entry & 0b11 == 0);
    }
    Some(MemoryAttributes::Normal {
        inner: decode_mair_cacheability(entry & 0xf)?,
        outer: decode_mair_cacheability(entry >> 4)?,
    })
}

fn decode_mair_cacheability(bits: u8) -> Option<Cacheability> {
    match bits & 0xf {
        0b0100 => Some(Cacheability::NonCacheable),
        value if value & 0b11 != 0 => {
            let (policy, transience) = match value >> 2 {
                0 => (CachePolicy::WriteThrough, MemoryTransience::Transient),
                1 => (CachePolicy::WriteBack, MemoryTransience::Transient),
                2 => (CachePolicy::WriteThrough, MemoryTransience::NonTransient),
                _ => (CachePolicy::WriteBack, MemoryTransience::NonTransient),
            };
            let allocation = match value & 3 {
                0 => AllocationHints::None,
                1 => AllocationHints::WriteAllocate,
                2 => AllocationHints::ReadAllocate,
                _ => AllocationHints::ReadWriteAllocate,
            };
            Some(Cacheability::Cacheable {
                policy,
                transience,
                allocation,
            })
        }
        _ => None,
    }
}

fn encode_stage2_combined(attrs: MemoryAttributes) -> Result<u8, AttrError> {
    match attrs {
        MemoryAttributes::Device(device) => Ok(encode_device(device)),
        MemoryAttributes::Normal { inner, outer } => {
            Ok(encode_stage2_cacheability(inner)? | encode_stage2_cacheability(outer)? << 2)
        }
    }
}

fn decode_stage2_combined(bits: u8) -> Option<MemoryAttributes> {
    match bits & 0xf {
        0..=3 => decode_device(bits).map(MemoryAttributes::Device),
        value if value & 3 != 0 && value >> 2 != 0 => Some(MemoryAttributes::Normal {
            inner: decode_stage2_cacheability(value & 3)?,
            outer: decode_stage2_cacheability(value >> 2)?,
        }),
        _ => None,
    }
}

fn encode_stage2_fwb(attrs: FwbStage2Memory, mte: bool) -> Result<u8, AttrError> {
    match attrs {
        FwbStage2Memory::Device(device) => Ok(encode_device(device)),
        FwbStage2Memory::ForceNormalNonCacheable => Ok(0b0101),
        FwbStage2Memory::ForceNormalWriteBack => Ok(0b0110),
        FwbStage2Memory::UseStage1 => Ok(0b0111),
        FwbStage2Memory::ForceNormalWriteBackNoTagAccess if mte => Ok(0b1110),
        FwbStage2Memory::UseStage1NoTagAccess if mte => Ok(0b1111),
        FwbStage2Memory::ForceNormalWriteBackNoTagAccess
        | FwbStage2Memory::UseStage1NoTagAccess => Err(AttrError::MtePermissionUnavailable),
    }
}

fn decode_stage2_fwb(bits: u8, mte: bool) -> Option<FwbStage2Memory> {
    match bits & 0xf {
        0..=3 => decode_device(bits).map(FwbStage2Memory::Device),
        0b0101 => Some(FwbStage2Memory::ForceNormalNonCacheable),
        0b0110 => Some(FwbStage2Memory::ForceNormalWriteBack),
        0b0111 => Some(FwbStage2Memory::UseStage1),
        0b1110 if mte => Some(FwbStage2Memory::ForceNormalWriteBackNoTagAccess),
        0b1111 if mte => Some(FwbStage2Memory::UseStage1NoTagAccess),
        _ => None,
    }
}

const fn encode_device(device: DeviceMemoryType) -> u8 {
    match device {
        DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck => 0,
        DeviceMemoryType::NonGatheringNonReorderingEarlyAck => 1,
        DeviceMemoryType::NonGatheringReorderingEarlyAck => 2,
        DeviceMemoryType::GatheringReorderingEarlyAck => 3,
    }
}

const fn decode_device(bits: u8) -> Option<DeviceMemoryType> {
    match bits {
        0 => Some(DeviceMemoryType::NonGatheringNonReorderingNoEarlyAck),
        1 => Some(DeviceMemoryType::NonGatheringNonReorderingEarlyAck),
        2 => Some(DeviceMemoryType::NonGatheringReorderingEarlyAck),
        3 => Some(DeviceMemoryType::GatheringReorderingEarlyAck),
        _ => None,
    }
}

fn encode_stage2_cacheability(value: Cacheability) -> Result<u8, AttrError> {
    match value {
        Cacheability::NonCacheable => Ok(1),
        Cacheability::Cacheable {
            policy,
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        } => Ok(match policy {
            CachePolicy::WriteThrough => 2,
            CachePolicy::WriteBack => 3,
        }),
        _ => Err(AttrError::UnencodableMemoryAttribute),
    }
}

fn decode_stage2_cacheability(bits: u8) -> Option<Cacheability> {
    match bits {
        1 => Some(Cacheability::NonCacheable),
        2 | 3 => Some(Cacheability::Cacheable {
            policy: if bits == 2 {
                CachePolicy::WriteThrough
            } else {
                CachePolicy::WriteBack
            },
            transience: MemoryTransience::NonTransient,
            allocation: AllocationHints::ReadWriteAllocate,
        }),
        _ => None,
    }
}
