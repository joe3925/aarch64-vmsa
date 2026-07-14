#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Field<const LSB: u32, const WIDTH: u32>;

impl<const LSB: u32, const WIDTH: u32> Field<LSB, WIDTH> {
    const VALID: () = {
        assert!(WIDTH != 0, "architectural fields must be non-empty");
        assert!(LSB <= u128::BITS, "field LSB exceeds descriptor width");
        assert!(WIDTH <= u128::BITS, "field width exceeds descriptor width");
        assert!(LSB + WIDTH <= u128::BITS, "field exceeds descriptor width");
    };

    pub const fn value_mask() -> u128 {
        let () = Self::VALID;
        if WIDTH == u128::BITS {
            u128::MAX
        } else {
            (1u128 << WIDTH) - 1
        }
    }

    pub const fn mask() -> u128 {
        let () = Self::VALID;
        Self::value_mask() << LSB
    }

    pub const fn extract(raw: u128) -> u128 {
        let () = Self::VALID;
        (raw >> LSB) & Self::value_mask()
    }

    pub const fn insert(raw: u128, value: u128) -> u128 {
        let () = Self::VALID;
        debug_assert!(
            value & !Self::value_mask() == 0,
            "field value is out of range"
        );
        (raw & !Self::mask()) | ((value & Self::value_mask()) << LSB)
    }
}
