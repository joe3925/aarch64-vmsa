use crate::attrs::{
    AttrError, DataAccess, FourBit, MostlyReadOnly, PermissionIndices, Stage2Ap,
    Stage2ExecuteNever, Stage2Permission,
};

use super::Stage2PermissionConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2PermissionRegisters {
    pub s2pir_el2: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2BasePermissions {
    Direct,
    Indirect(Stage2PermissionRegisters),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2PermissionSettings {
    pub base: Stage2BasePermissions,
    pub s2por_el1: Option<u64>,
}

impl Stage2PermissionSettings {
    pub const fn direct() -> Self {
        Self {
            base: Stage2BasePermissions::Direct,
            s2por_el1: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2PermissionEntry {
    Permission(Stage2Permission),
    ReservedTreatedAsNoAccess,
}

use MostlyReadOnly::*;
use Stage2Permission::*;
use Stage2PermissionEntry::{Permission as P, ReservedTreatedAsNoAccess as R};

pub const STAGE2_BASE_DECODE: [Stage2PermissionEntry; 16] = [
    P(NoAccess),
    R,
    P(MostlyReadOnly(Unqualified)),
    P(MostlyReadOnly(TopLevel1)),
    P(WriteOnly),
    R,
    P(MostlyReadOnly(TopLevel0)),
    P(MostlyReadOnly(TopLevels0And1)),
    P(ReadOnly {
        privileged_execute: false,
        unprivileged_execute: false,
    }),
    P(ReadOnly {
        privileged_execute: false,
        unprivileged_execute: true,
    }),
    P(ReadOnly {
        privileged_execute: true,
        unprivileged_execute: false,
    }),
    P(ReadOnly {
        privileged_execute: true,
        unprivileged_execute: true,
    }),
    P(ReadWrite {
        privileged_execute: false,
        unprivileged_execute: false,
    }),
    P(ReadWrite {
        privileged_execute: false,
        unprivileged_execute: true,
    }),
    P(ReadWrite {
        privileged_execute: true,
        unprivileged_execute: false,
    }),
    P(ReadWrite {
        privileged_execute: true,
        unprivileged_execute: true,
    }),
];

pub const STAGE2_OVERLAY_DECODE: [Stage2PermissionEntry; 16] = [
    P(NoAccess),
    R,
    P(MostlyReadOnly(Unqualified)),
    P(MostlyReadOnly(TopLevel1)),
    P(WriteOnly),
    R,
    P(MostlyReadOnly(TopLevel0)),
    P(MostlyReadOnly(TopLevels0And1)),
    P(ReadOnly {
        privileged_execute: false,
        unprivileged_execute: false,
    }),
    P(ReadOnly {
        privileged_execute: false,
        unprivileged_execute: true,
    }),
    P(ReadOnly {
        privileged_execute: true,
        unprivileged_execute: false,
    }),
    P(ReadOnly {
        privileged_execute: true,
        unprivileged_execute: true,
    }),
    P(ReadWrite {
        privileged_execute: false,
        unprivileged_execute: false,
    }),
    P(ReadWrite {
        privileged_execute: false,
        unprivileged_execute: true,
    }),
    P(ReadWrite {
        privileged_execute: true,
        unprivileged_execute: false,
    }),
    P(ReadWrite {
        privileged_execute: true,
        unprivileged_execute: true,
    }),
];

pub fn decode_stage2_direct_permissions(
    access: Stage2Ap,
    execute_never: Stage2ExecuteNever,
    xnx: bool,
) -> Result<Stage2Permission, AttrError> {
    let data = match access.bits() {
        0b00 => DataAccess::None,
        0b01 => DataAccess::ReadOnly,
        0b11 => DataAccess::ReadWrite,
        bits => return Err(AttrError::InvalidStage2Permission(bits)),
    };
    let (privileged_execute, unprivileged_execute) = if xnx {
        match execute_never.bits() {
            0b00 => (true, true),
            0b01 => (false, true),
            0b10 => (false, false),
            0b11 => (true, false),
            _ => return Err(AttrError::InvalidStage2ExecuteNever),
        }
    } else {
        match execute_never.bits() {
            0b00 => (true, true),
            0b10 => (false, false),
            _ => return Err(AttrError::InvalidStage2ExecuteNever),
        }
    };
    Ok(match data {
        DataAccess::None => Stage2Permission::NoAccess,
        DataAccess::ReadOnly => Stage2Permission::ReadOnly {
            privileged_execute,
            unprivileged_execute,
        },
        DataAccess::ReadWrite => Stage2Permission::ReadWrite {
            privileged_execute,
            unprivileged_execute,
        },
    })
}

pub struct Stage2PermissionResolver<'a, C: ?Sized, I = FourBit> {
    config: &'a C,
    index: core::marker::PhantomData<I>,
}

impl<'a, C: Stage2PermissionConfig + ?Sized, I: super::PermissionIndex>
    Stage2PermissionResolver<'a, C, I>
{
    pub const fn new(config: &'a C) -> Self {
        Self {
            config,
            index: core::marker::PhantomData,
        }
    }

    pub fn resolve(&self, wanted: Stage2Permission) -> Result<PermissionIndices<I>, AttrError> {
        let settings = self.config.stage2_permissions();
        let registers = match settings.base {
            Stage2BasePermissions::Indirect(registers) => registers,
            Stage2BasePermissions::Direct => {
                return Err(AttrError::PermissionIndirectionUnavailable);
            }
        };
        let po_count = if settings.s2por_el1.is_some() {
            I::COUNT
        } else {
            1
        };

        for pi in 0..16 {
            for po in 0..po_count {
                if decode_effective(registers, settings.s2por_el1, pi, po) == wanted {
                    return Ok(PermissionIndices {
                        pi: FourBit::new(pi)?,
                        po: I::new(po)?,
                    });
                }
            }
        }
        Err(AttrError::PermissionCombinationNotConfigured)
    }

    pub fn decode(&self, indices: PermissionIndices<I>) -> Result<Stage2Permission, AttrError> {
        let settings = self.config.stage2_permissions();
        let registers = match settings.base {
            Stage2BasePermissions::Indirect(registers) => registers,
            Stage2BasePermissions::Direct => {
                return Err(AttrError::PermissionIndirectionUnavailable);
            }
        };
        Ok(decode_effective(
            registers,
            settings.s2por_el1,
            indices.pi.bits(),
            indices.po.bits(),
        ))
    }
}

fn decode_effective(
    registers: Stage2PermissionRegisters,
    overlay: Option<u64>,
    pi: u8,
    po: u8,
) -> Stage2Permission {
    let base = decoded(STAGE2_BASE_DECODE[entry(registers.s2pir_el2, pi) as usize]);
    match overlay {
        Some(overlay) => combine_stage2_permissions(
            base,
            decoded(STAGE2_OVERLAY_DECODE[entry(overlay, po) as usize]),
        ),
        None => base,
    }
}

pub(crate) fn apply_stage2_overlay(
    base: Stage2Permission,
    overlay: Option<u64>,
    po: u8,
) -> Stage2Permission {
    overlay.map_or(base, |register| {
        combine_stage2_permissions(
            base,
            decoded(STAGE2_OVERLAY_DECODE[entry(register, po) as usize]),
        )
    })
}

const fn decoded(entry: Stage2PermissionEntry) -> Stage2Permission {
    match entry {
        P(value) => value,
        R => NoAccess,
    }
}

pub const fn combine_stage2_permissions(
    base: Stage2Permission,
    overlay: Stage2Permission,
) -> Stage2Permission {
    match (base, overlay) {
        (MostlyReadOnly(a), MostlyReadOnly(b)) => MostlyReadOnly(combine_mro(a, b)),
        (WriteOnly, WriteOnly) => WriteOnly,
        (WriteOnly, MostlyReadOnly(_)) | (MostlyReadOnly(_), WriteOnly) => NoAccess,

        (special @ MostlyReadOnly(_), general) | (general, special @ MostlyReadOnly(_)) => {
            combine_mro_with_general(special, general)
        }
        (WriteOnly, general) | (general, WriteOnly) => combine_wo_with_general(general),

        (general_a, general_b) => {
            let encoding = encode_general(general_a) & encode_general(general_b);
            decoded(STAGE2_BASE_DECODE[encoding as usize])
        }
    }
}

const fn combine_mro(a: MostlyReadOnly, b: MostlyReadOnly) -> MostlyReadOnly {
    match mro_mask(a) | mro_mask(b) {
        0b00 => Unqualified,
        0b01 => TopLevel0,
        0b10 => TopLevel1,
        _ => TopLevels0And1,
    }
}

const fn mro_mask(value: MostlyReadOnly) -> u8 {
    match value {
        Unqualified => 0b00,
        TopLevel0 => 0b01,
        TopLevel1 => 0b10,
        TopLevels0And1 => 0b11,
    }
}

const fn combine_mro_with_general(
    special: Stage2Permission,
    general: Stage2Permission,
) -> Stage2Permission {
    match general {
        NoAccess => NoAccess,
        ReadOnly { .. } => ReadOnly {
            privileged_execute: false,
            unprivileged_execute: false,
        },
        ReadWrite { .. } => special,
        _ => NoAccess,
    }
}

const fn combine_wo_with_general(general: Stage2Permission) -> Stage2Permission {
    match general {
        ReadWrite { .. } => WriteOnly,
        NoAccess | ReadOnly { .. } => NoAccess,
        _ => NoAccess,
    }
}

const fn encode_general(value: Stage2Permission) -> u8 {
    match value {
        NoAccess => 0,
        ReadOnly {
            privileged_execute,
            unprivileged_execute,
        } => 0b1000 | (privileged_execute as u8) << 1 | unprivileged_execute as u8,
        ReadWrite {
            privileged_execute,
            unprivileged_execute,
        } => 0b1100 | (privileged_execute as u8) << 1 | unprivileged_execute as u8,
        _ => 0,
    }
}

fn entry(register: u64, index: u8) -> u8 {
    ((register >> (u32::from(index) * 4)) & 0xf) as u8
}
