use crate::address::{GranuleKind, Level, TranslationGranule};
use crate::attrs::{
    AttrError, AttrKind, AttributeCodec, AttributeResolver, DirtyBitManagement,
    LiveAttributeConfiguration, MairIndex, MemoryAttributes, Shareability, SoftwareDefinedBits,
    Stage1LeafAttrs, Stage1Profile, Stage1TableAttrs, Stage2LeafAttrs, Stage2MemoryEncoding,
    Stage2Profile, Stage2TableAttrs, Vmsa64Stage1LeafControls, Vmsa64Stage1TableControls,
    Vmsa64Stage2LeafControls, Vmsa64Stage2TableControls,
};
use crate::descriptor::RawFieldBlock;
use crate::descriptor::Vmsa64Lpa2;
use crate::descriptor::{
    Vmsa64Lpa2Stage1LeafFields, Vmsa64Lpa2Stage2LeafFields, Vmsa64Stage1TableFields,
    Vmsa64Stage2TableFields,
};
use crate::translation::{Stage1, Stage2};

use super::common::{Stage1PasCodec, Stage1PermissionCodec, Stage2PasCodec, Stage2PermissionCodec};

impl<P, A, G, C> AttributeCodec<Vmsa64Lpa2, Stage1, G, C> for Stage1Profile<P, A>
where
    P: Stage1PermissionCodec,
    A: Stage1PasCodec,
    G: TranslationGranule,
    C: LiveAttributeConfiguration,
{
    type LeafAttrs = Stage1LeafAttrs<P, A, MemoryAttributes, Vmsa64Stage1LeafControls>;
    type TableAttrs = Stage1TableAttrs<P, A, Vmsa64Stage1TableControls>;

    fn encode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        attrs: Self::LeafAttrs,
        _level: Level,
    ) -> Result<Vmsa64Lpa2Stage1LeafFields, AttrError> {
        require_lpa2_shareability::<G, C>(resolver, attrs.controls.shareability)?;
        if A::USES_NSE && !attrs.controls.global {
            return Err(AttrError::ConflictingAttributes {
                first: AttrKind::Security,
                second: AttrKind::Global,
            });
        }
        let permissions = P::encode_leaf_permissions(attrs.permissions)?;
        let (non_secure, nse) = A::encode_leaf_pas(attrs.pas)?;
        let alias_bit = if A::USES_NSE {
            nse
        } else {
            !attrs.controls.global
        };
        let memory = resolver.resolve_stage1_memory::<3>(attrs.memory)?;
        let lower = encode_lpa2_stage1_lower::<G>(
            memory.bits(),
            non_secure,
            permissions.ap,
            attrs.controls.shareability,
            attrs.controls.access_flag,
            alias_bit,
        );
        let upper = attrs.controls.contiguous as u128
            | ((permissions.pxn as u128) << 1)
            | ((permissions.uxn as u128) << 2);

        Ok(Vmsa64Lpa2Stage1LeafFields {
            lower: RawFieldBlock::from_masked(lower),
            upper: RawFieldBlock::from_masked(upper),
            dirty_bit_modifier: attrs.controls.dirty_management.dbm_bit(),
            guarded: attrs.controls.guarded,
            software: RawFieldBlock::from_masked(attrs.controls.software.bits()),
        })
    }

    fn decode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        fields: Vmsa64Lpa2Stage1LeafFields,
        _level: Level,
    ) -> Result<Self::LeafAttrs, AttrError> {
        let lower = fields.lower.bits();
        let alias_bit = decode_lpa2_stage1_alias_bit::<G>(lower);
        Ok(Stage1LeafAttrs {
            memory: resolver.decode_stage1_memory(MairIndex::<3>::from_bits(lower)),
            permissions: P::decode_leaf_permissions(fields.lower, fields.upper),
            pas: A::decode_leaf_pas(lower & (1 << 3) != 0, alias_bit),
            controls: Vmsa64Stage1LeafControls {
                shareability: decode_lpa2_stage1_shareability::<G, C>(resolver, lower)?,
                access_flag: decode_lpa2_stage1_access_flag::<G>(lower),
                global: A::USES_NSE || !alias_bit,
                dirty_management: DirtyBitManagement::from_dbm_bit(fields.dirty_bit_modifier),
                contiguous: fields.upper.bits() & 1 != 0,
                guarded: fields.guarded,
                software: SoftwareDefinedBits::from_bits(fields.software.bits()),
            },
        })
    }

    fn encode_table_attrs(
        _resolver: &AttributeResolver<C>,
        attrs: Self::TableAttrs,
        _level: Level,
    ) -> Result<Vmsa64Stage1TableFields, AttrError> {
        let permissions = P::encode_table_permissions(attrs.permissions)?;
        let non_secure = A::encode_table_pas(attrs.pas)?;
        let upper = permissions.pxn_table as u128
            | ((permissions.uxn_table as u128) << 1)
            | (permissions.ap_table << 2)
            | ((non_secure as u128) << 4);
        Ok(Vmsa64Stage1TableFields {
            upper: RawFieldBlock::from_masked(upper),
            software: RawFieldBlock::from_masked(attrs.controls.software.bits()),
        })
    }

    fn decode_table_attrs(
        _resolver: &AttributeResolver<C>,
        fields: Vmsa64Stage1TableFields,
        _level: Level,
    ) -> Result<Self::TableAttrs, AttrError> {
        Ok(Stage1TableAttrs {
            permissions: P::decode_table_permissions(fields.upper),
            pas: A::decode_table_pas(fields.upper.bits() & (1 << 4) != 0),
            controls: Vmsa64Stage1TableControls {
                software: SoftwareDefinedBits::from_bits(fields.software.bits()),
            },
        })
    }
}

impl<P, X, G, C> AttributeCodec<Vmsa64Lpa2, Stage2, G, C> for Stage2Profile<P, X>
where
    P: Stage2PermissionCodec,
    X: Stage2PasCodec,
    G: TranslationGranule,
    C: LiveAttributeConfiguration,
{
    type LeafAttrs = Stage2LeafAttrs<P, X, MemoryAttributes, Vmsa64Stage2LeafControls>;
    type TableAttrs = Stage2TableAttrs<P, X, Vmsa64Stage2TableControls>;

    fn encode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        attrs: Self::LeafAttrs,
        _level: Level,
    ) -> Result<Vmsa64Lpa2Stage2LeafFields, AttrError> {
        require_lpa2_shareability::<G, C>(resolver, attrs.controls.shareability)?;
        let memory = resolver.resolve_stage2_memory(attrs.memory)?;
        let permissions = P::encode_leaf_permissions(attrs.permissions)?;
        let output_address_space =
            X::encode_leaf_output_address_space(resolver, attrs.output_address_space)?;
        if X::USES_DESCRIPTOR_NS && attrs.controls.software.bit0 {
            return Err(AttrError::ConflictingAttributes {
                first: AttrKind::Security,
                second: AttrKind::Software,
            });
        }
        let software = attrs.controls.software.bits()
            | ((output_address_space as u128) & u128::from(X::USES_DESCRIPTOR_NS));
        let lower = encode_lpa2_stage2_lower::<G>(
            memory.bits(),
            permissions.s2ap,
            attrs.controls.shareability,
            attrs.controls.access_flag,
        );
        let upper = attrs.controls.contiguous as u128 | (permissions.xn << 1);
        Ok(Vmsa64Lpa2Stage2LeafFields {
            lower: RawFieldBlock::from_masked(lower),
            upper: RawFieldBlock::from_masked(upper),
            dirty_bit_modifier: attrs.controls.dirty_management.dbm_bit(),
            software: RawFieldBlock::from_masked(software),
        })
    }

    fn decode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        fields: Vmsa64Lpa2Stage2LeafFields,
        _level: Level,
    ) -> Result<Self::LeafAttrs, AttrError> {
        let lower = fields.lower.bits();
        let upper = fields.upper.bits();
        let software = fields.software.bits();
        Ok(Stage2LeafAttrs::new(
            resolver.decode_stage2_memory(Stage2MemoryEncoding::from_bits(lower))?,
            P::decode_leaf_permissions(lower >> 4, upper >> 1)?,
            X::decode_leaf_output_address_space(resolver, software & 1 != 0),
            Vmsa64Stage2LeafControls {
                shareability: decode_lpa2_stage2_shareability::<G, C>(resolver, lower)?,
                access_flag: decode_lpa2_stage2_access_flag::<G>(lower),
                dirty_management: DirtyBitManagement::from_dbm_bit(fields.dirty_bit_modifier),
                contiguous: upper & 1 != 0,
                software: SoftwareDefinedBits::from_bits(if X::USES_DESCRIPTOR_NS {
                    software & !1
                } else {
                    software
                }),
            },
        ))
    }

    fn encode_table_attrs(
        _resolver: &AttributeResolver<C>,
        attrs: Self::TableAttrs,
        _level: Level,
    ) -> Result<Vmsa64Stage2TableFields, AttrError> {
        P::require_unrestricted_table(attrs.permissions)?;
        Ok(Vmsa64Stage2TableFields {
            software: RawFieldBlock::from_masked(attrs.controls.software.bits()),
        })
    }

    fn decode_table_attrs(
        _resolver: &AttributeResolver<C>,
        fields: Vmsa64Stage2TableFields,
        _level: Level,
    ) -> Result<Self::TableAttrs, AttrError> {
        Ok(Stage2TableAttrs::new(
            P::unrestricted_table_permissions(),
            Vmsa64Stage2TableControls {
                software: SoftwareDefinedBits::from_bits(fields.software.bits()),
            },
        ))
    }
}

fn require_effective_shareability<C>(
    resolver: &AttributeResolver<C>,
    requested: Shareability,
) -> Result<(), AttrError>
where
    C: LiveAttributeConfiguration,
{
    let effective = resolver.effective_shareability();
    if requested == effective {
        Ok(())
    } else {
        Err(AttrError::ShareabilityMismatch {
            requested,
            effective,
        })
    }
}

fn require_lpa2_shareability<G, C>(
    resolver: &AttributeResolver<C>,
    shareability: Shareability,
) -> Result<(), AttrError>
where
    G: TranslationGranule,
    C: LiveAttributeConfiguration,
{
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => {
            require_effective_shareability(resolver, shareability)
        }
        GranuleKind::Size64KiB => Ok(()),
    }
}

fn encode_lpa2_stage1_lower<G: TranslationGranule>(
    memory: u128,
    non_secure: bool,
    ap: u128,
    shareability: Shareability,
    access_flag: bool,
    alias_bit: bool,
) -> u128 {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => {
            memory
                | ((non_secure as u128) << 3)
                | (ap << 4)
                | ((access_flag as u128) << 6)
                | ((alias_bit as u128) << 7)
        }
        GranuleKind::Size64KiB => {
            memory
                | ((non_secure as u128) << 3)
                | (ap << 4)
                | (shareability.bits() << 6)
                | ((access_flag as u128) << 8)
                | ((alias_bit as u128) << 9)
        }
    }
}

fn decode_lpa2_stage1_shareability<G, C>(
    resolver: &AttributeResolver<C>,
    lower: u128,
) -> Result<Shareability, AttrError>
where
    G: TranslationGranule,
    C: LiveAttributeConfiguration,
{
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => Ok(resolver.effective_shareability()),
        GranuleKind::Size64KiB => Shareability::from_bits(lower >> 6),
    }
}

fn decode_lpa2_stage1_access_flag<G: TranslationGranule>(lower: u128) -> bool {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => lower & (1 << 6) != 0,
        GranuleKind::Size64KiB => lower & (1 << 8) != 0,
    }
}

fn decode_lpa2_stage1_alias_bit<G: TranslationGranule>(lower: u128) -> bool {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => lower & (1 << 7) != 0,
        GranuleKind::Size64KiB => lower & (1 << 9) != 0,
    }
}

fn encode_lpa2_stage2_lower<G: TranslationGranule>(
    memory: u128,
    s2ap: u128,
    shareability: Shareability,
    access_flag: bool,
) -> u128 {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => {
            memory | (s2ap << 4) | ((access_flag as u128) << 6)
        }
        GranuleKind::Size64KiB => {
            memory | (s2ap << 4) | (shareability.bits() << 6) | ((access_flag as u128) << 8)
        }
    }
}

fn decode_lpa2_stage2_shareability<G, C>(
    resolver: &AttributeResolver<C>,
    lower: u128,
) -> Result<Shareability, AttrError>
where
    G: TranslationGranule,
    C: LiveAttributeConfiguration,
{
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => Ok(resolver.effective_shareability()),
        GranuleKind::Size64KiB => Shareability::from_bits(lower >> 6),
    }
}

fn decode_lpa2_stage2_access_flag<G: TranslationGranule>(lower: u128) -> bool {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => lower & (1 << 6) != 0,
        GranuleKind::Size64KiB => lower & (1 << 8) != 0,
    }
}
