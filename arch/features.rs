#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VmsaFeatures {
    pub el2: bool,
    pub el3: bool,
    pub secure_state: bool,
    pub el2_and0: bool,
    pub sel2: bool,
    pub rme: bool,
    pub stage2: bool,
    pub xnx: bool,
    pub lpa2: bool,
    pub d128: bool,
    pub extended_input_address: bool,
    pub extended_output_address: bool,
}

impl VmsaFeatures {
    pub const NONE: Self = Self {
        el2: false,
        el3: false,
        secure_state: false,
        el2_and0: false,
        sel2: false,
        rme: false,
        stage2: false,
        xnx: false,
        lpa2: false,
        d128: false,
        extended_input_address: false,
        extended_output_address: false,
    };

    pub const D128: Self = Self::NONE.with_d128();

    pub const fn union(self, other: Self) -> Self {
        Self {
            el2: self.el2 || other.el2,
            el3: self.el3 || other.el3,
            secure_state: self.secure_state || other.secure_state,
            el2_and0: self.el2_and0 || other.el2_and0,
            sel2: self.sel2 || other.sel2,
            rme: self.rme || other.rme,
            stage2: self.stage2 || other.stage2,
            xnx: self.xnx || other.xnx,
            lpa2: self.lpa2 || other.lpa2,
            d128: self.d128 || other.d128,
            extended_input_address: self.extended_input_address || other.extended_input_address,
            extended_output_address: self.extended_output_address || other.extended_output_address,
        }
    }
    pub const fn verify(self, required: Self) -> bool {
        (!required.el2 || self.el2)
            && (!required.el3 || self.el3)
            && (!required.secure_state || self.secure_state)
            && (!required.el2_and0 || self.el2_and0)
            && (!required.sel2 || self.sel2)
            && (!required.rme || self.rme)
            && (!required.stage2 || self.stage2)
            && (!required.xnx || self.xnx)
            && (!required.lpa2 || self.lpa2)
            && (!required.d128 || self.d128)
            && (!required.extended_input_address || self.extended_input_address)
            && (!required.extended_output_address || self.extended_output_address)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn current() -> Self {
        let pfr0 = read_id_aa64pfr0_el1();
        let mmfr0 = read_id_aa64mmfr0_el1();
        let mmfr1 = read_id_aa64mmfr1_el1();
        let mmfr2 = read_id_aa64mmfr2_el1();
        let mmfr3 = read_id_aa64mmfr3_el1();

        Self::from_id_registers(pfr0, mmfr0, mmfr1, mmfr2, mmfr3)
    }

    #[cfg(target_arch = "aarch64")]
    const fn from_id_registers(pfr0: u64, mmfr0: u64, mmfr1: u64, mmfr2: u64, mmfr3: u64) -> Self {
        let el2 = field(pfr0, 8) != 0;
        let el3 = field(pfr0, 12) != 0;
        let d128 = field(mmfr3, 32) != 0;
        let lpa2 = field(mmfr0, 28) == 1
            || field(mmfr0, 20) == 2
            || field(mmfr0, 40) == 3
            || field(mmfr0, 32) == 3;

        Self {
            el2,
            el3,
            secure_state: el3,
            el2_and0: field(mmfr1, 8) != 0,
            sel2: field(pfr0, 36) != 0,
            rme: field(pfr0, 52) != 0,
            stage2: el2,
            xnx: field(mmfr1, 28) != 0,
            lpa2,
            d128,
            extended_input_address: field(mmfr2, 16) != 0 || lpa2 || d128,
            extended_output_address: field(mmfr0, 0) >= 6 || d128,
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    pub const fn current() -> Self {
        Self::NONE
    }

    pub const fn with_el2(mut self) -> Self {
        self.el2 = true;
        self
    }

    pub const fn with_el3(mut self) -> Self {
        self.el3 = true;
        self
    }

    pub const fn with_secure_state(mut self) -> Self {
        self.secure_state = true;
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

    pub const fn with_extended_input_address(mut self) -> Self {
        self.extended_input_address = true;
        self
    }

    pub const fn with_extended_output_address(mut self) -> Self {
        self.extended_output_address = true;
        self
    }
}

#[cfg(target_arch = "aarch64")]
const fn field(register: u64, shift: u8) -> u64 {
    (register >> shift) & 0xf
}

#[cfg(target_arch = "aarch64")]
macro_rules! id_register_reader {
    ($function:ident, $register:literal) => {
        #[inline]
        fn $function() -> u64 {
            let value: u64;
            unsafe {
                core::arch::asm!(
                    concat!("mrs {value}, ", $register),
                    value = out(reg) value,
                    options(nomem, nostack, preserves_flags),
                );
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
