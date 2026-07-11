#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FeatureStatus {
    NotImplemented,
    Implemented,
    Unknown(u8),
}

impl FeatureStatus {
    pub const fn is_implemented(self) -> bool {
        matches!(self, Self::Implemented)
    }

    pub const fn unknown_raw(self) -> Option<u8> {
        match self {
            Self::Unknown(raw) => Some(raw),
            _ => None,
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecurityStates(u8);

impl SecurityStates {
    pub const NONE: Self = Self(0);
    pub const NON_SECURE: Self = Self(1 << 0);
    pub const SECURE: Self = Self(1 << 1);
    pub const REALM: Self = Self(1 << 2);
    pub const ROOT: Self = Self(1 << 3);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, state: Self) -> bool {
        self.0 & state.0 == state.0
    }

    pub const fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdRegisterSnapshot {
    pub id_aa64pfr0_el1: u64,
    pub id_aa64mmfr0_el1: u64,
    pub id_aa64mmfr1_el1: u64,
    pub id_aa64mmfr2_el1: u64,
    pub id_aa64mmfr3_el1: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmsaFeatures {
    pub el2: FeatureStatus,
    pub el3: FeatureStatus,
    pub el2_and0: FeatureStatus,
    pub sel2: FeatureStatus,
    pub rme: FeatureStatus,
    pub stage2: FeatureStatus,
    pub xnx: FeatureStatus,
    pub lpa2: FeatureStatus,
    pub d128: FeatureStatus,
    pub d128_stage2: FeatureStatus,
    pub extended_input_address: FeatureStatus,
    pub extended_output_address: FeatureStatus,
    pub security_states: SecurityStates,
}

impl VmsaFeatures {
    pub const NONE: Self = Self {
        el2: FeatureStatus::NotImplemented,
        el3: FeatureStatus::NotImplemented,
        el2_and0: FeatureStatus::NotImplemented,
        sel2: FeatureStatus::NotImplemented,
        rme: FeatureStatus::NotImplemented,
        stage2: FeatureStatus::NotImplemented,
        xnx: FeatureStatus::NotImplemented,
        lpa2: FeatureStatus::NotImplemented,
        d128: FeatureStatus::NotImplemented,
        d128_stage2: FeatureStatus::NotImplemented,
        extended_input_address: FeatureStatus::NotImplemented,
        extended_output_address: FeatureStatus::NotImplemented,
        security_states: SecurityStates::NON_SECURE,
    };

    pub const fn verify(self, required: FeatureRequirements) -> bool {
        (!required.el2 || self.el2.is_implemented())
            && (!required.el3 || self.el3.is_implemented())
            && (!required.el2_and0 || self.el2_and0.is_implemented())
            && (!required.sel2 || self.sel2.is_implemented())
            && (!required.rme || self.rme.is_implemented())
            && (!required.stage2 || self.stage2.is_implemented())
            && (!required.xnx || self.xnx.is_implemented())
            && (!required.lpa2 || self.lpa2.is_implemented())
            && (!required.d128 || self.d128.is_implemented())
            && (!required.d128_stage2 || self.d128_stage2.is_implemented())
            && (!required.extended_input_address || self.extended_input_address.is_implemented())
            && (!required.extended_output_address || self.extended_output_address.is_implemented())
            && self.security_states.contains(required.security_states)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn current() -> Self {
        decode_features(IdRegisterSnapshot::current())
    }

    #[cfg(not(target_arch = "aarch64"))]
    pub const fn current() -> Self {
        Self::NONE
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FeatureRequirements {
    pub el2: bool,
    pub el3: bool,
    pub el2_and0: bool,
    pub sel2: bool,
    pub rme: bool,
    pub stage2: bool,
    pub xnx: bool,
    pub lpa2: bool,
    pub d128: bool,
    pub d128_stage2: bool,
    pub extended_input_address: bool,
    pub extended_output_address: bool,
    pub security_states: SecurityStates,
}

impl FeatureRequirements {
    pub const NONE: Self = Self {
        el2: false,
        el3: false,
        el2_and0: false,
        sel2: false,
        rme: false,
        stage2: false,
        xnx: false,
        lpa2: false,
        d128: false,
        d128_stage2: false,
        extended_input_address: false,
        extended_output_address: false,
        security_states: SecurityStates::NONE,
    };

    pub const fn union(self, other: Self) -> Self {
        Self {
            el2: self.el2 || other.el2,
            el3: self.el3 || other.el3,
            el2_and0: self.el2_and0 || other.el2_and0,
            sel2: self.sel2 || other.sel2,
            rme: self.rme || other.rme,
            stage2: self.stage2 || other.stage2,
            xnx: self.xnx || other.xnx,
            lpa2: self.lpa2 || other.lpa2,
            d128: self.d128 || other.d128,
            d128_stage2: self.d128_stage2 || other.d128_stage2,
            extended_input_address: self.extended_input_address || other.extended_input_address,
            extended_output_address: self.extended_output_address || other.extended_output_address,
            security_states: self.security_states.union(other.security_states),
        }
    }

    pub const fn with_el2(mut self) -> Self {
        self.el2 = true;
        self
    }
    pub const fn with_el3(mut self) -> Self {
        self.el3 = true;
        self
    }
    pub const fn with_el2_and0(mut self) -> Self {
        self.el2_and0 = true;
        self
    }
    pub const fn with_sel2(mut self) -> Self {
        self.sel2 = true;
        self
    }
    pub const fn with_rme(mut self) -> Self {
        self.rme = true;
        self
    }
    pub const fn with_stage2(mut self) -> Self {
        self.stage2 = true;
        self
    }
    pub const fn with_xnx(mut self) -> Self {
        self.xnx = true;
        self
    }
    pub const fn with_lpa2(mut self) -> Self {
        self.lpa2 = true;
        self
    }
    pub const fn with_d128(mut self) -> Self {
        self.d128 = true;
        self
    }
    pub const fn with_d128_stage2(mut self) -> Self {
        self.d128_stage2 = true;
        self
    }
    pub const fn with_extended_input_address(mut self) -> Self {
        self.extended_input_address = true;
        self
    }
    pub const fn with_extended_output_address(mut self) -> Self {
        self.extended_output_address = true;
        self
    }
    pub const fn with_security_state(mut self, state: SecurityStates) -> Self {
        self.security_states = self.security_states.union(state);
        self
    }
}

pub const fn decode_features(snapshot: IdRegisterSnapshot) -> VmsaFeatures {
    let pfr0 = snapshot.id_aa64pfr0_el1;
    let mmfr0 = snapshot.id_aa64mmfr0_el1;
    let mmfr1 = snapshot.id_aa64mmfr1_el1;
    let mmfr2 = snapshot.id_aa64mmfr2_el1;
    let mmfr3 = snapshot.id_aa64mmfr3_el1;

    let el2 = decode_exception_level(field(pfr0, 8));
    let el3 = decode_exception_level(field(pfr0, 12));
    let sel2 = decode_binary_feature(field(pfr0, 36));
    let rme = decode_rme(field(pfr0, 52));
    let el2_and0 = decode_binary_feature(field(mmfr1, 8));
    let xnx = decode_binary_feature(field(mmfr1, 28));
    let d128 = decode_binary_feature(field(mmfr3, 32));
    let d128_stage2 = decode_binary_feature(field(mmfr3, 36));
    let lpa2 = decode_lpa2(mmfr0);
    let extended_input_address = merge_derived(
        decode_varange(field(mmfr2, 16)),
        merge_derived(lpa2, merge_derived(d128, d128_stage2)),
    );
    let extended_output_address = merge_derived(
        decode_parange(field(mmfr0, 0)),
        merge_derived(d128, d128_stage2),
    );

    let mut security_states = SecurityStates::NON_SECURE;
    if sel2.is_implemented() {
        security_states = security_states.union(SecurityStates::SECURE);
    }
    if rme.is_implemented() {
        security_states = security_states.union(SecurityStates::REALM);
        if el3.is_implemented() {
            security_states = security_states.union(SecurityStates::ROOT);
        }
    } else if matches!(rme, FeatureStatus::NotImplemented) && el3.is_implemented() {
        security_states = security_states.union(SecurityStates::SECURE);
    }

    VmsaFeatures {
        el2,
        el3,
        el2_and0,
        sel2,
        rme,
        stage2: el2,
        xnx,
        lpa2,
        d128,
        d128_stage2,
        extended_input_address,
        extended_output_address,
        security_states,
    }
}

const fn field(register: u64, shift: u8) -> u8 {
    ((register >> shift) & 0xf) as u8
}

const fn decode_binary_feature(raw: u8) -> FeatureStatus {
    match raw {
        0 => FeatureStatus::NotImplemented,
        1 => FeatureStatus::Implemented,
        raw => FeatureStatus::Unknown(raw),
    }
}

const fn decode_exception_level(raw: u8) -> FeatureStatus {
    match raw {
        0 => FeatureStatus::NotImplemented,
        1 | 2 => FeatureStatus::Implemented,
        raw => FeatureStatus::Unknown(raw),
    }
}

const fn decode_rme(raw: u8) -> FeatureStatus {
    match raw {
        0 => FeatureStatus::NotImplemented,
        1..=3 => FeatureStatus::Implemented,
        raw => FeatureStatus::Unknown(raw),
    }
}

const fn decode_lpa2(mmfr0: u64) -> FeatureStatus {
    let tg4 = field(mmfr0, 28);
    let tg16 = field(mmfr0, 20);
    let tg4_2 = field(mmfr0, 40);
    let tg16_2 = field(mmfr0, 32);
    if tg4 == 1 || tg16 == 2 || tg4_2 == 3 || tg16_2 == 3 {
        FeatureStatus::Implemented
    } else if !matches!(tg4, 0 | 0xf)
        || !matches!(tg16, 0 | 1)
        || !matches!(tg4_2, 0..=3)
        || !matches!(tg16_2, 0..=3)
    {
        FeatureStatus::Unknown(if !matches!(tg4, 0 | 1 | 0xf) {
            tg4
        } else if !matches!(tg16, 0..=2) {
            tg16
        } else if tg4_2 > 3 {
            tg4_2
        } else {
            tg16_2
        })
    } else {
        FeatureStatus::NotImplemented
    }
}

const fn decode_varange(raw: u8) -> FeatureStatus {
    match raw {
        0 => FeatureStatus::NotImplemented,
        1 | 2 => FeatureStatus::Implemented,
        raw => FeatureStatus::Unknown(raw),
    }
}

const fn decode_parange(raw: u8) -> FeatureStatus {
    match raw {
        0..=5 => FeatureStatus::NotImplemented,
        6 | 7 => FeatureStatus::Implemented,
        raw => FeatureStatus::Unknown(raw),
    }
}

const fn merge_derived(primary: FeatureStatus, derived: FeatureStatus) -> FeatureStatus {
    if primary.is_implemented() || derived.is_implemented() {
        FeatureStatus::Implemented
    } else {
        match primary {
            FeatureStatus::Unknown(raw) => FeatureStatus::Unknown(raw),
            _ => derived,
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl IdRegisterSnapshot {
    pub fn current() -> Self {
        Self {
            id_aa64pfr0_el1: read_id_aa64pfr0_el1(),
            id_aa64mmfr0_el1: read_id_aa64mmfr0_el1(),
            id_aa64mmfr1_el1: read_id_aa64mmfr1_el1(),
            id_aa64mmfr2_el1: read_id_aa64mmfr2_el1(),
            id_aa64mmfr3_el1: read_id_aa64mmfr3_el1(),
        }
    }
}

#[cfg(target_arch = "aarch64")]
macro_rules! id_register_reader {
    ($function:ident, $register:literal) => {
        #[inline]
        fn $function() -> u64 {
            let value: u64;
            unsafe {
                core::arch::asm!(concat!("mrs {value}, ", $register), value = out(reg) value,
                    options(nomem, nostack, preserves_flags));
            }
            value
        }
    };
}

#[cfg(target_arch = "aarch64")]
id_register_reader!(read_id_aa64pfr0_el1, "ID_AA64PFR0_EL1");
#[cfg(target_arch = "aarch64")]
id_register_reader!(read_id_aa64mmfr0_el1, "ID_AA64MMFR0_EL1");
#[cfg(target_arch = "aarch64")]
id_register_reader!(read_id_aa64mmfr1_el1, "ID_AA64MMFR1_EL1");
#[cfg(target_arch = "aarch64")]
id_register_reader!(read_id_aa64mmfr2_el1, "ID_AA64MMFR2_EL1");
#[cfg(target_arch = "aarch64")]
id_register_reader!(read_id_aa64mmfr3_el1, "S3_0_C0_C7_3");
