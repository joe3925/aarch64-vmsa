use strum::EnumCount;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FeatureStatus {
    NotImplemented,
    Implemented,
    Unknown(u8),
}

#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, EnumCount, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    El2,
    El3,
    El2And0,
    Sel2,
    Rme,
    Stage2,
    Xnx,
    Lpa2,
    D128,
    D128Stage2,
    ExtendedInputAddress,
    ExtendedOutputAddress,
}

const _: () = assert!(Capability::COUNT <= u128::BITS as usize);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilitySet(u128);

impl CapabilitySet {
    pub const NONE: Self = Self(0);

    pub const fn with(self, capability: Capability) -> Self {
        Self(self.0 | capability_bit(capability))
    }

    pub const fn contains(self, capability: Capability) -> bool {
        self.0 & capability_bit(capability) != 0
    }

    pub const fn contains_all(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn bits(self) -> u128 {
        self.0
    }
}

const fn capability_bit(capability: Capability) -> u128 {
    1u128 << capability as u8
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
    statuses: [FeatureStatus; Capability::COUNT],
    security_states: SecurityStates,
}

impl VmsaFeatures {
    pub const NONE: Self = Self {
        statuses: [FeatureStatus::NotImplemented; Capability::COUNT],
        security_states: SecurityStates::NON_SECURE,
    };

    pub const fn status(self, capability: Capability) -> FeatureStatus {
        self.statuses[capability as usize]
    }

    pub const fn implemented_capabilities(self) -> CapabilitySet {
        let mut implemented = CapabilitySet::NONE;
        let mut index = 0;

        while index < Capability::COUNT {
            if self.statuses[index].is_implemented() {
                implemented.0 |= 1u128 << index;
            }
            index += 1;
        }

        implemented
    }

    pub const fn security_states(self) -> SecurityStates {
        self.security_states
    }

    pub const fn verify(self, required: FeatureRequirements) -> bool {
        self.implemented_capabilities()
            .contains_all(required.capabilities)
            && self.security_states.contains(required.security_states)
    }

    pub const fn with_status(mut self, capability: Capability, status: FeatureStatus) -> Self {
        self.statuses[capability as usize] = status;
        self
    }

    pub const fn with_security_states(mut self, security_states: SecurityStates) -> Self {
        self.security_states = security_states;
        self
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
    capabilities: CapabilitySet,
    security_states: SecurityStates,
}

impl FeatureRequirements {
    pub const NONE: Self = Self {
        capabilities: CapabilitySet::NONE,
        security_states: SecurityStates::NONE,
    };

    pub const fn union(self, other: Self) -> Self {
        Self {
            capabilities: self.capabilities.union(other.capabilities),
            security_states: self.security_states.union(other.security_states),
        }
    }

    pub const fn require(mut self, capability: Capability) -> Self {
        self.capabilities = self.capabilities.with(capability);
        self
    }

    pub const fn require_security_state(mut self, state: SecurityStates) -> Self {
        self.security_states = self.security_states.union(state);
        self
    }

    pub const fn capabilities(self) -> CapabilitySet {
        self.capabilities
    }

    pub const fn security_states(self) -> SecurityStates {
        self.security_states
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

    VmsaFeatures::NONE
        .with_status(Capability::El2, el2)
        .with_status(Capability::El3, el3)
        .with_status(Capability::El2And0, el2_and0)
        .with_status(Capability::Sel2, sel2)
        .with_status(Capability::Rme, rme)
        .with_status(Capability::Stage2, el2)
        .with_status(Capability::Xnx, xnx)
        .with_status(Capability::Lpa2, lpa2)
        .with_status(Capability::D128, d128)
        .with_status(Capability::D128Stage2, d128_stage2)
        .with_status(Capability::ExtendedInputAddress, extended_input_address)
        .with_status(Capability::ExtendedOutputAddress, extended_output_address)
        .with_security_states(security_states)
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
            // SAFETY: This instruction reads the specified system register.
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
