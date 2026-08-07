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

pub(super) const fn word_mask(bits: u32) -> u128 {
    assert!(bits != 0, "descriptor width must be non-zero");
    assert!(bits <= u128::BITS, "descriptor width exceeds u128");

    if bits == u128::BITS {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

pub(super) const fn checked_field_mask(bits: u32, fields: &[u128]) -> u128 {
    let domain = word_mask(bits);
    let mut mask = 0;
    let mut index = 0;

    while index < fields.len() {
        let field = fields[index];
        assert!(field & !domain == 0, "field exceeds descriptor width");
        assert!(mask & field == 0, "fields overlap in descriptor view");
        mask |= field;
        index += 1;
    }

    mask
}

pub(super) const fn checked_view_mask(bits: u32, view: u128, fields: &[(u128, u128)]) -> u128 {
    assert!(
        view.is_power_of_two(),
        "descriptor view tag must contain one bit"
    );

    let domain = word_mask(bits);
    let mut mask = 0;
    let mut index = 0;

    while index < fields.len() {
        let (field, views) = fields[index];
        if views & view != 0 {
            assert!(field & !domain == 0, "field exceeds descriptor width");
            assert!(mask & field == 0, "fields overlap in descriptor view");
            mask |= field;
        }
        index += 1;
    }

    mask
}

pub(super) const fn validate_field(bits: u32, field: u128, views: u128, all_views: u128) {
    assert!(
        field & !word_mask(bits) == 0,
        "field exceeds descriptor width"
    );
    assert!(views != 0, "field is not used by any descriptor view");
    assert!(
        views & !all_views == 0,
        "field refers to an unknown descriptor view"
    );
}

pub(super) const fn checked_res1_mask(used: u128, bits: u32, fields: &[u128]) -> u128 {
    let mask = checked_field_mask(bits, fields);
    assert!(
        mask & !used == 0,
        "RES1 field is not used by descriptor view"
    );
    mask
}

// `descriptor_layout!` assigns one private bit to each descriptor view. Field
// membership is represented only while evaluating constants; no runtime layout
// value is generated.
macro_rules! descriptor_view_tags {
    ($first:ident $(, $rest:ident)* $(,)?) => {
        const $first: u128 = 1;
        $crate::descriptor::layout::descriptor_view_tags_after!($first; $($rest),*);
    };
}

macro_rules! descriptor_view_tags_after {
    ($previous:ident;) => {};
    ($previous:ident; $next:ident $(, $rest:ident)*) => {
        const $next: u128 = $previous << 1;
        $crate::descriptor::layout::descriptor_view_tags_after!($next; $($rest),*);
    };
}

macro_rules! descriptor_field_table {
    (
        bits: $bits:expr;
        all_views: $all_views:ident;
        fields {
            $(
                $field_vis:vis $field:ident: Field<$lsb:literal, $width:literal>
                    in $views:expr;
            )*
        }
    ) => {
        $(
            $field_vis type $field = $crate::descriptor::layout::Field<$lsb, $width>;
        )*

        const _: () = {
            $(
                $crate::descriptor::layout::validate_field(
                    $bits,
                    $crate::descriptor::layout::Field::<$lsb, $width>::mask(),
                    $views,
                    $all_views,
                );
            )*
        };
    };
}

macro_rules! descriptor_view {
    (
        bits: $bits:expr;
        $view_vis:vis $view:ident as $view_tag:ident {
            $(res1: [$($res1:ident),* $(,)?];)?
        }
        fields {
            $(
                $field_vis:vis $field:ident: Field<$lsb:literal, $width:literal>
                    in $views:expr;
            )*
        }
    ) => {
        $view_vis mod $view {
            use super::*;

            const USED_MASK: u128 = $crate::descriptor::layout::checked_view_mask(
                $bits,
                $view_tag,
                &[$(($field::mask(), $views)),*],
            );
            pub const RES0_MASK: u128 =
                $crate::descriptor::layout::word_mask($bits) & !USED_MASK;
            $(
                pub const RES1_MASK: u128 =
                    $crate::descriptor::layout::checked_res1_mask(
                        USED_MASK,
                        $bits,
                        &[$($res1::mask()),*],
                    );
            )?
        }
    };
}

/// Use `descriptor_layout!` to define bit fields for one descriptor word.
/// Different descriptor views can use the same bits.
///
/// Use this syntax:
///
/// ```text
/// descriptor_layout! {
///     bits: 128;
///     views {
///         pub stage1_leaf as STAGE1_LEAF {
///             res1: [VALID];
///         }
///         pub stage2_leaf as STAGE2_LEAF {}
///     }
///     fields {
///         pub VALID: Field<0, 1> in ALL;
///         pub ATTR_INDEX: Field<2, 4> in STAGE1_LEAF;
///         pub MEM_ATTR: Field<2, 4> in STAGE2_LEAF;
///         pub ACCESS_FLAG: Field<10, 1> in STAGE1_LEAF | STAGE2_LEAF;
///     }
/// }
/// ```
///
/// `bits` specifies the descriptor width. Use a value from 1 through 128.
/// Each field must be in the specified low bits of a `u128`.
///
/// A view is one interpretation of the descriptor word. Each item in `views`
/// makes one module. The name after `as` is the view tag.
///
/// The macro gives a different bit to each view tag. A view tag is only macro
/// data. A view tag is not part of the encoded descriptor.
///
/// The macro also makes the private `ALL` tag. Use `ALL` to select all the
/// specified views.
///
/// Each item in `fields` makes one [`Field<LSB, WIDTH>`] type alias. The first
/// number is the least-significant bit. The second number is the field width.
///
/// The expression after `in` selects the applicable views. Use one view tag for
/// one view. Use `|` to join two or more view tags.
///
/// Fields in the same view must not overlap. An overlap causes an error during
/// compilation. Fields in different views can overlap.
///
/// The `res1` list is optional. It refers to fields in the `fields` section.
/// All bits of each specified field must be one in that view. Each specified
/// field must apply to that view.
///
/// The macro makes `RES1_MASK` when a view has a `res1` list. Do not use a
/// `res1` list when descriptor data controls the required-one bits.
///
/// The macro makes these masks for each view:
///
/// - `RES0_MASK` contains each in-range bit that the view does not use.
/// - `RES1_MASK` contains each field in the optional `res1` list.
/// - A private mask contains each field that the view uses.
///
/// During compilation, the macro does these checks:
///
/// - Each field has a width greater than zero.
/// - Each field is in the descriptor word.
/// - Each field applies to one or more specified views.
/// - Fields in one view do not overlap.
/// - Fields in the `res1` list do not overlap.
/// - Each field in the `res1` list applies to its view.
///
/// [`Field<LSB, WIDTH>`]: Field
macro_rules! descriptor_layout {
    (
        bits: $bits:expr;
        views {
            $(
                $view_vis:vis $view:ident as $view_tag:ident {
                    $(res1: [$($res1:ident),* $(,)?];)?
                }
            )*
        }
        fields $fields:tt
    ) => {
        $crate::descriptor::layout::descriptor_view_tags!($($view_tag),*);
        const ALL: u128 = 0 $(| $view_tag)*;

        $crate::descriptor::layout::descriptor_field_table! {
            bits: $bits;
            all_views: ALL;
            fields $fields
        }

        $(
            $crate::descriptor::layout::descriptor_view! {
                bits: $bits;
                $view_vis $view as $view_tag {
                    $(res1: [$($res1),*];)?
                }
                fields $fields
            }
        )*
    };
}

pub(super) use {
    descriptor_field_table, descriptor_layout, descriptor_view, descriptor_view_tags,
    descriptor_view_tags_after,
};
