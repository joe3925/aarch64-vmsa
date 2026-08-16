use crate::attrs::{
    AttrError, DataAccess, El1And0Permissions, El2And0Permissions, El2Permissions, El3Permissions,
    FourBit, LeafAp, PermissionIndices, PrivilegeModel, SinglePrivilegeTablePermissionLimits,
    Stage1EffectivePermissions, TableAp, TwoPrivilegeTablePermissionLimits,
};

use super::Stage1PermissionConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1PermissionRegisters {
    pub privileged: u64,
    pub unprivileged: Option<u64>,
    pub gcs_implemented: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1BasePermissions {
    Direct,
    Indirect(Stage1PermissionRegisters),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stage1PermissionOverlays {
    pub privileged: Option<u64>,
    pub unprivileged: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage1PermissionSettings {
    pub base: Stage1BasePermissions,
    pub overlays: Stage1PermissionOverlays,
}

impl Stage1PermissionSettings {
    pub const fn direct() -> Self {
        Self {
            base: Stage1BasePermissions::Direct,
            overlays: Stage1PermissionOverlays {
                privileged: None,
                unprivileged: None,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1BasePermission {
    NoAccessApplyOverlay,
    ReadApplyOverlay,
    ExecuteApplyOverlay,
    ReadExecuteApplyOverlay,
    ReservedNoAccessApplyOverlay,
    ReadWriteApplyOverlay,
    ReadWriteExecuteApplyOverlayWithWxn,
    ReadWriteExecuteApplyOverlay,
    ReadNoOverlay,
    ReadGcsNoOverlay,
    ReadExecuteNoOverlay,
    ReservedNoAccessNoOverlay,
    ReadWriteNoOverlay,
    ReadWriteExecuteNoOverlay,
}

pub const STAGE1_BASE_DECODE: [Stage1BasePermission; 16] = [
    Stage1BasePermission::NoAccessApplyOverlay,
    Stage1BasePermission::ReadApplyOverlay,
    Stage1BasePermission::ExecuteApplyOverlay,
    Stage1BasePermission::ReadExecuteApplyOverlay,
    Stage1BasePermission::ReservedNoAccessApplyOverlay,
    Stage1BasePermission::ReadWriteApplyOverlay,
    Stage1BasePermission::ReadWriteExecuteApplyOverlayWithWxn,
    Stage1BasePermission::ReadWriteExecuteApplyOverlay,
    Stage1BasePermission::ReadNoOverlay,
    Stage1BasePermission::ReadGcsNoOverlay,
    Stage1BasePermission::ReadExecuteNoOverlay,
    Stage1BasePermission::ReservedNoAccessNoOverlay,
    Stage1BasePermission::ReadWriteNoOverlay,
    Stage1BasePermission::ReservedNoAccessNoOverlay,
    Stage1BasePermission::ReadWriteExecuteNoOverlay,
    Stage1BasePermission::ReservedNoAccessNoOverlay,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage1OverlayPermission {
    NoAccess,
    Read,
    Execute,
    ReadExecute,
    Write,
    ReadWrite,
    WriteExecute,
    ReadWriteExecute,
    ReservedNoAccess,
}

pub const STAGE1_OVERLAY_DECODE: [Stage1OverlayPermission; 16] = [
    Stage1OverlayPermission::NoAccess,
    Stage1OverlayPermission::Read,
    Stage1OverlayPermission::Execute,
    Stage1OverlayPermission::ReadExecute,
    Stage1OverlayPermission::Write,
    Stage1OverlayPermission::ReadWrite,
    Stage1OverlayPermission::WriteExecute,
    Stage1OverlayPermission::ReadWriteExecute,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
    Stage1OverlayPermission::ReservedNoAccess,
];

pub fn decode_single_el_leaf_ap(ap: LeafAp) -> Result<DataAccess, AttrError> {
    match ap.bits() {
        0b01 => Ok(DataAccess::ReadWrite),
        0b11 => Ok(DataAccess::ReadOnly),
        bits => Err(AttrError::InvalidLeafAp(bits)),
    }
}

pub fn decode_two_privilege_leaf_ap(ap: LeafAp) -> (DataAccess, DataAccess) {
    match ap.bits() {
        0b00 => (DataAccess::ReadWrite, DataAccess::None),
        0b01 => (DataAccess::ReadWrite, DataAccess::ReadWrite),
        0b10 => (DataAccess::ReadOnly, DataAccess::None),
        _ => (DataAccess::ReadOnly, DataAccess::ReadOnly),
    }
}

pub fn encode_single_privilege_table_ap(
    limits: SinglePrivilegeTablePermissionLimits,
) -> Result<TableAp, AttrError> {
    TableAp::from_bits(match limits.data_limit {
        DataAccess::ReadWrite => 0b00,
        DataAccess::ReadOnly => 0b10,
        DataAccess::None => return Err(AttrError::UnencodablePermissions),
    })
}

pub fn decode_single_privilege_table_ap(
    ap: TableAp,
    execute_limit: bool,
) -> Result<SinglePrivilegeTablePermissionLimits, AttrError> {
    let data_limit = match ap.bits() {
        0b00 => DataAccess::ReadWrite,
        0b10 => DataAccess::ReadOnly,
        bits => return Err(AttrError::InvalidTableAp(bits)),
    };
    Ok(SinglePrivilegeTablePermissionLimits {
        data_limit,
        execute_limit,
    })
}

pub fn encode_two_privilege_table_ap(
    limits: TwoPrivilegeTablePermissionLimits,
) -> Result<TableAp, AttrError> {
    TableAp::from_bits(
        match (limits.privileged_data_limit, limits.unprivileged_data_limit) {
            (DataAccess::ReadWrite, DataAccess::ReadWrite) => 0b00,
            (DataAccess::ReadWrite, DataAccess::None) => 0b01,
            (DataAccess::ReadOnly, DataAccess::ReadOnly) => 0b10,
            (DataAccess::ReadOnly, DataAccess::None) => 0b11,
            _ => return Err(AttrError::UnencodablePermissions),
        },
    )
}

pub fn decode_two_privilege_table_ap(
    ap: TableAp,
    privileged_execute_limit: bool,
    unprivileged_execute_limit: bool,
) -> TwoPrivilegeTablePermissionLimits {
    let (privileged_data_limit, unprivileged_data_limit) = match ap.bits() {
        0b00 => (DataAccess::ReadWrite, DataAccess::ReadWrite),
        0b01 => (DataAccess::ReadWrite, DataAccess::None),
        0b10 => (DataAccess::ReadOnly, DataAccess::ReadOnly),
        _ => (DataAccess::ReadOnly, DataAccess::None),
    };
    TwoPrivilegeTablePermissionLimits {
        privileged_data_limit,
        unprivileged_data_limit,
        privileged_execute_limit,
        unprivileged_execute_limit,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawStage1DirectLeafPermissions {
    pub ap: LeafAp,
    pub privileged_execute_never: bool,
    pub unprivileged_execute_never: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawStage1TablePermissionLimits {
    pub ap_table: TableAp,
    pub privileged_execute_never_limit: bool,
    pub unprivileged_execute_never_limit: bool,
}

pub trait Stage1DirectPermissionModel: PrivilegeModel {
    fn decode_leaf(
        raw: RawStage1DirectLeafPermissions,
    ) -> Result<Stage1EffectivePermissions, AttrError>;

    fn encode_table(
        limits: Self::TablePermissionLimits,
    ) -> Result<RawStage1TablePermissionLimits, AttrError>;

    fn decode_table(
        raw: RawStage1TablePermissionLimits,
    ) -> Result<Self::TablePermissionLimits, AttrError>;
}

macro_rules! single_privilege_model {
    ($model:ty) => {
        impl Stage1DirectPermissionModel for $model {
            fn decode_leaf(
                raw: RawStage1DirectLeafPermissions,
            ) -> Result<Stage1EffectivePermissions, AttrError> {
                if raw.privileged_execute_never {
                    return Err(AttrError::UnencodablePermissions);
                }
                Ok(Stage1EffectivePermissions {
                    privileged_data: decode_single_el_leaf_ap(raw.ap)?,
                    unprivileged_data: DataAccess::None,
                    privileged_execute: !raw.unprivileged_execute_never,
                    unprivileged_execute: false,
                    privileged_gcs: false,
                    unprivileged_gcs: false,
                })
            }

            fn encode_table(
                value: Self::TablePermissionLimits,
            ) -> Result<RawStage1TablePermissionLimits, AttrError> {
                Ok(RawStage1TablePermissionLimits {
                    ap_table: encode_single_privilege_table_ap(value)?,
                    privileged_execute_never_limit: false,
                    unprivileged_execute_never_limit: !value.execute_limit,
                })
            }

            fn decode_table(
                raw: RawStage1TablePermissionLimits,
            ) -> Result<Self::TablePermissionLimits, AttrError> {
                if raw.privileged_execute_never_limit {
                    return Err(AttrError::UnencodablePermissions);
                }
                decode_single_privilege_table_ap(
                    raw.ap_table,
                    !raw.unprivileged_execute_never_limit,
                )
            }
        }
    };
}

single_privilege_model!(El2Permissions);
single_privilege_model!(El3Permissions);

macro_rules! two_privilege_model {
    ($model:ty) => {
        impl Stage1DirectPermissionModel for $model {
            fn decode_leaf(
                raw: RawStage1DirectLeafPermissions,
            ) -> Result<Stage1EffectivePermissions, AttrError> {
                let (privileged_data, unprivileged_data) = decode_two_privilege_leaf_ap(raw.ap);
                Ok(Stage1EffectivePermissions {
                    privileged_data,
                    unprivileged_data,
                    privileged_execute: !raw.privileged_execute_never,
                    unprivileged_execute: !raw.unprivileged_execute_never,
                    privileged_gcs: false,
                    unprivileged_gcs: false,
                })
            }

            fn encode_table(
                value: Self::TablePermissionLimits,
            ) -> Result<RawStage1TablePermissionLimits, AttrError> {
                Ok(RawStage1TablePermissionLimits {
                    ap_table: encode_two_privilege_table_ap(value)?,
                    privileged_execute_never_limit: !value.privileged_execute_limit,
                    unprivileged_execute_never_limit: !value.unprivileged_execute_limit,
                })
            }

            fn decode_table(
                raw: RawStage1TablePermissionLimits,
            ) -> Result<Self::TablePermissionLimits, AttrError> {
                Ok(decode_two_privilege_table_ap(
                    raw.ap_table,
                    !raw.privileged_execute_never_limit,
                    !raw.unprivileged_execute_never_limit,
                ))
            }
        }
    };
}

two_privilege_model!(El1And0Permissions);
two_privilege_model!(El2And0Permissions);

pub struct Stage1PermissionResolver<'a, C: ?Sized, I = FourBit> {
    config: &'a C,
    index: core::marker::PhantomData<I>,
}

impl<'a, C: Stage1PermissionConfig + ?Sized, I: super::PermissionIndex>
    Stage1PermissionResolver<'a, C, I>
{
    pub const fn new(config: &'a C) -> Self {
        Self {
            config,
            index: core::marker::PhantomData,
        }
    }

    pub fn resolve(
        &self,
        wanted: Stage1EffectivePermissions,
    ) -> Result<PermissionIndices<I>, AttrError> {
        let settings = self.config.stage1_permissions();
        let registers = match settings.base {
            Stage1BasePermissions::Indirect(registers) => registers,
            Stage1BasePermissions::Direct => {
                return Err(AttrError::PermissionIndirectionUnavailable);
            }
        };
        let po_count =
            if settings.overlays.privileged.is_some() || settings.overlays.unprivileged.is_some() {
                I::COUNT
            } else {
                1
            };

        for pi in 0..16 {
            for po in 0..po_count {
                if decode_effective(registers, settings.overlays, pi, po) == Some(wanted) {
                    return Ok(PermissionIndices {
                        pi: FourBit::new(pi)?,
                        po: I::new(po)?,
                    });
                }
            }
        }
        Err(AttrError::PermissionCombinationNotConfigured)
    }

    pub fn decode(
        &self,
        indices: PermissionIndices<I>,
    ) -> Result<Stage1EffectivePermissions, AttrError> {
        let settings = self.config.stage1_permissions();
        let registers = match settings.base {
            Stage1BasePermissions::Indirect(registers) => registers,
            Stage1BasePermissions::Direct => {
                return Err(AttrError::PermissionIndirectionUnavailable);
            }
        };
        decode_effective(
            registers,
            settings.overlays,
            indices.pi.bits(),
            indices.po.bits(),
        )
        .ok_or(AttrError::UnencodablePermissions)
    }
}

#[derive(Clone, Copy)]
struct Bits {
    read: bool,
    write: bool,
    execute: bool,
    gcs: bool,
    apply_overlay: bool,
    wxn: bool,
}

fn decode_effective(
    registers: Stage1PermissionRegisters,
    overlays: Stage1PermissionOverlays,
    pi: u8,
    po: u8,
) -> Option<Stage1EffectivePermissions> {
    let privileged = decode_pair(
        registers.privileged,
        overlays.privileged,
        pi,
        po,
        registers.gcs_implemented,
    );
    let unprivileged = registers
        .unprivileged
        .map(|base| {
            decode_pair(
                base,
                overlays.unprivileged,
                pi,
                po,
                registers.gcs_implemented,
            )
        })
        .unwrap_or_else(no_bits);

    if (privileged.execute || privileged.gcs) && (unprivileged.write || unprivileged.gcs) {
        return None;
    }

    Some(Stage1EffectivePermissions {
        privileged_data: data_access(privileged)?,
        unprivileged_data: data_access(unprivileged)?,
        privileged_execute: privileged.execute,
        unprivileged_execute: unprivileged.execute,
        privileged_gcs: privileged.gcs,
        unprivileged_gcs: unprivileged.gcs,
    })
}

fn decode_pair(
    base_register: u64,
    overlay: Option<u64>,
    pi: u8,
    po: u8,
    gcs_implemented: bool,
) -> Bits {
    let base = decode_base(entry(base_register, pi), gcs_implemented);
    match overlay {
        Some(overlay) => apply_overlay(base, entry(overlay, po)),
        None => base,
    }
}

fn decode_base(raw: u8, gcs_implemented: bool) -> Bits {
    use Stage1BasePermission::*;

    let (read, write, execute, gcs, apply_overlay, wxn) = match STAGE1_BASE_DECODE[raw as usize] {
        NoAccessApplyOverlay | ReservedNoAccessApplyOverlay => {
            (false, false, false, false, true, false)
        }
        ReadApplyOverlay => (true, false, false, false, true, false),
        ExecuteApplyOverlay => (false, false, true, false, true, false),
        ReadExecuteApplyOverlay => (true, false, true, false, true, false),
        ReadWriteApplyOverlay => (true, true, false, false, true, false),
        ReadWriteExecuteApplyOverlayWithWxn => (true, true, true, false, true, true),
        ReadWriteExecuteApplyOverlay => (true, true, true, false, true, false),
        ReadNoOverlay => (true, false, false, false, false, false),
        ReadGcsNoOverlay if gcs_implemented => (true, false, false, true, false, false),
        ReadGcsNoOverlay => (false, false, false, false, false, false),
        ReadExecuteNoOverlay => (true, false, true, false, false, false),
        ReservedNoAccessNoOverlay => (false, false, false, false, false, false),
        ReadWriteNoOverlay => (true, true, false, false, false, false),
        ReadWriteExecuteNoOverlay => (true, true, true, false, false, false),
    };

    Bits {
        read,
        write,
        execute,
        gcs,
        apply_overlay,
        wxn,
    }
}

fn apply_overlay(base: Bits, raw: u8) -> Bits {
    if !base.apply_overlay {
        return base;
    }

    let (read, mut write, execute) = match STAGE1_OVERLAY_DECODE[raw as usize] {
        Stage1OverlayPermission::NoAccess | Stage1OverlayPermission::ReservedNoAccess => {
            (false, false, false)
        }
        Stage1OverlayPermission::Read => (true, false, false),
        Stage1OverlayPermission::Execute => (false, false, true),
        Stage1OverlayPermission::ReadExecute => (true, false, true),
        Stage1OverlayPermission::Write => (false, true, false),
        Stage1OverlayPermission::ReadWrite => (true, true, false),
        Stage1OverlayPermission::WriteExecute => (false, true, true),
        Stage1OverlayPermission::ReadWriteExecute => (true, true, true),
    };

    if base.wxn && execute {
        write = false;
    }

    Bits {
        read: base.read && read,
        write: base.write && write,
        execute: base.execute && execute,
        gcs: base.gcs,
        apply_overlay: false,
        wxn: false,
    }
}

pub(crate) fn apply_stage1_overlay(
    base: Stage1EffectivePermissions,
    overlays: Stage1PermissionOverlays,
    po: u8,
) -> Option<Stage1EffectivePermissions> {
    let privileged = apply_effective_overlay(
        Bits {
            read: base.privileged_data != DataAccess::None,
            write: base.privileged_data == DataAccess::ReadWrite,
            execute: base.privileged_execute,
            gcs: base.privileged_gcs,
            apply_overlay: true,
            wxn: false,
        },
        overlays.privileged,
        po,
    );
    let unprivileged = apply_effective_overlay(
        Bits {
            read: base.unprivileged_data != DataAccess::None,
            write: base.unprivileged_data == DataAccess::ReadWrite,
            execute: base.unprivileged_execute,
            gcs: base.unprivileged_gcs,
            apply_overlay: true,
            wxn: false,
        },
        overlays.unprivileged,
        po,
    );
    if (privileged.execute || privileged.gcs) && (unprivileged.write || unprivileged.gcs) {
        return None;
    }
    Some(Stage1EffectivePermissions {
        privileged_data: data_access(privileged)?,
        unprivileged_data: data_access(unprivileged)?,
        privileged_execute: privileged.execute,
        unprivileged_execute: unprivileged.execute,
        privileged_gcs: privileged.gcs,
        unprivileged_gcs: unprivileged.gcs,
    })
}

fn apply_effective_overlay(base: Bits, overlay: Option<u64>, po: u8) -> Bits {
    overlay.map_or(base, |register| apply_overlay(base, entry(register, po)))
}

const fn no_bits() -> Bits {
    Bits {
        read: false,
        write: false,
        execute: false,
        gcs: false,
        apply_overlay: false,
        wxn: false,
    }
}

const fn data_access(bits: Bits) -> Option<DataAccess> {
    match (bits.read, bits.write) {
        (false, false) => Some(DataAccess::None),
        (true, false) => Some(DataAccess::ReadOnly),
        (true, true) => Some(DataAccess::ReadWrite),
        (false, true) => None,
    }
}

fn entry(register: u64, index: u8) -> u8 {
    ((register >> (u32::from(index) * 4)) & 0xf) as u8
}
