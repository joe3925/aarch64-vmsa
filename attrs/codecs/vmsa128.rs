use crate::address::{Level, TranslationGranule};
use crate::attrs::{
    AttrError, AttrKind, AttributeCodec, AttributeResolver, DirtyState, LiveAttributeConfiguration,
    MairIndex, MemoryTransience, PermissionIndirectionIndex, PermissionOverlayIndex,
    ResolvedD128Permissions, Shareability, Stage1Profile, Stage2MemoryEncoding, Stage2Profile,
    Stage2TablePermissions, Vmsa128Stage1LeafAttrs, Vmsa128Stage1TableAttrs,
    Vmsa128Stage2LeafAttrs, Vmsa128Stage2TableAttrs,
};
use crate::descriptor::RawFieldBlock;
use crate::descriptor::Vmsa128;
use crate::descriptor::layout::vmsa128_skl_supported;
use crate::descriptor::{
    Vmsa128Stage1LeafFields, Vmsa128Stage1TableFields, Vmsa128Stage2LeafFields,
    Vmsa128Stage2TableFields,
};
use crate::translation::{Stage1, Stage2};

use super::common::{
    Stage1PasCodec, Stage1PermissionCodec, Stage2PasCodec, Stage2PermissionCodec,
    decode_stage2_data, encode_stage2_data,
};

impl<P, A, G, C> AttributeCodec<Vmsa128, Stage1, G, C> for Stage1Profile<P, A>
where
    P: Stage1PermissionCodec,
    A: Stage1PasCodec,
    G: TranslationGranule,
    C: LiveAttributeConfiguration,
{
    type LeafAttrs = Vmsa128Stage1LeafAttrs<A>;
    type TableAttrs = Vmsa128Stage1TableAttrs<P, A>;

    fn encode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        attrs: Self::LeafAttrs,
        level: Level,
    ) -> Result<Vmsa128Stage1LeafFields, AttrError> {
        if A::USES_NSE && !attrs.global {
            return Err(AttrError::ConflictingAttributes {
                first: AttrKind::Security,
                second: AttrKind::Global,
            });
        }
        let (non_secure, nse) = A::encode_leaf_pas(attrs.pas)?;
        let alias_bit = if A::USES_NSE { nse } else { !attrs.global };
        let skip_levels = leaf_skip_levels::<G>(level)?;
        let memory = resolver.resolve_stage1_memory::<4>(attrs.memory)?;
        let permissions = resolver.resolve_d128_permissions(attrs.permissions)?;
        Ok(Vmsa128Stage1LeafFields::from_arch_fields(
            RawFieldBlock::from_masked(memory.bits()),
            attrs.transience.not_transient_bit(),
            attrs.dirty_state.not_dirty_bit(),
            RawFieldBlock::from_masked(attrs.shareability.bits()),
            attrs.access_flag,
            alias_bit,
            skip_levels,
            attrs.contiguous,
            attrs.guarded,
            attrs.protected,
            RawFieldBlock::from_masked(permissions.indirection.bits()),
            RawFieldBlock::from_masked(permissions.overlay.bits()),
            non_secure,
        ))
    }

    fn decode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        fields: Vmsa128Stage1LeafFields,
        _level: Level,
    ) -> Result<Self::LeafAttrs, AttrError> {
        Ok(Vmsa128Stage1LeafAttrs {
            memory: resolver
                .decode_stage1_memory(MairIndex::<4>::from_bits(fields.attr_index().bits())),
            permissions: resolver.decode_d128_permissions(ResolvedD128Permissions {
                indirection: PermissionIndirectionIndex::from_bits(fields.pii().bits()),
                overlay: PermissionOverlayIndex::from_bits(fields.poi().bits()),
            }),
            pas: A::decode_leaf_pas(fields.ns(), fields.alias_bit()),
            transience: MemoryTransience::from_not_transient_bit(fields.nt()),
            dirty_state: DirtyState::from_not_dirty_bit(fields.ndirty()),
            shareability: Shareability::from_bits(fields.shareability().bits())?,
            access_flag: fields.af(),
            global: A::USES_NSE || !fields.alias_bit(),
            contiguous: fields.contiguous(),
            guarded: fields.guarded(),
            protected: fields.protected(),
        })
    }

    fn encode_table_attrs(
        _resolver: &AttributeResolver<C>,
        attrs: Self::TableAttrs,
        _level: Level,
    ) -> Result<Vmsa128Stage1TableFields, AttrError> {
        let permissions = P::encode_table_permissions(attrs.permissions)?;
        Ok(Vmsa128Stage1TableFields::from_arch_fields(
            attrs.transience.not_transient_bit(),
            attrs.access_flag,
            RawFieldBlock::from_masked(0),
            attrs.discharge,
            attrs.protected,
            permissions.pxn_table,
            permissions.uxn_table,
            RawFieldBlock::from_masked(permissions.ap_table),
            A::encode_table_pas(attrs.pas)?,
        ))
    }

    fn decode_table_attrs(
        _resolver: &AttributeResolver<C>,
        fields: Vmsa128Stage1TableFields,
        _level: Level,
    ) -> Result<Self::TableAttrs, AttrError> {
        let permission_bits = RawFieldBlock::from_masked(
            fields.pxntable() as u128
                | ((fields.uxntable() as u128) << 1)
                | (fields.aptable().bits() << 2),
        );
        Ok(Vmsa128Stage1TableAttrs {
            permissions: P::decode_table_permissions(permission_bits),
            pas: A::decode_table_pas(fields.nstable()),
            transience: MemoryTransience::from_not_transient_bit(fields.nt()),
            access_flag: fields.a(),
            discharge: fields.disch(),
            protected: fields.protected(),
        })
    }
}

impl<P, X, G, C> AttributeCodec<Vmsa128, Stage2, G, C> for Stage2Profile<P, X>
where
    P: Stage2PermissionCodec,
    X: Stage2PasCodec,
    G: TranslationGranule,
    C: LiveAttributeConfiguration,
{
    type LeafAttrs = Vmsa128Stage2LeafAttrs<X>;
    type TableAttrs = Vmsa128Stage2TableAttrs<X>;

    fn encode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        attrs: Self::LeafAttrs,
        level: Level,
    ) -> Result<Vmsa128Stage2LeafFields, AttrError> {
        let memory = resolver.resolve_stage2_memory(attrs.memory)?;
        let permissions = resolver.resolve_d128_permissions(attrs.permissions)?;
        let alias = resolver.encode_d128_stage2_alias(attrs.alias)?;
        let output_address_space =
            X::encode_leaf_output_address_space(resolver, attrs.output_address_space)?;
        Ok(Vmsa128Stage2LeafFields::from_arch_fields(
            RawFieldBlock::from_masked(memory.bits()),
            attrs.transience.not_transient_bit(),
            attrs.dirty_state.not_dirty_bit(),
            RawFieldBlock::from_masked(attrs.shareability.bits()),
            attrs.access_flag,
            alias,
            leaf_skip_levels::<G>(level)?,
            attrs.contiguous,
            attrs.guarded,
            attrs.assured_only,
            RawFieldBlock::from_masked(permissions.indirection.bits()),
            RawFieldBlock::from_masked(permissions.overlay.bits()),
            output_address_space,
        ))
    }

    fn decode_leaf_attrs(
        resolver: &AttributeResolver<C>,
        fields: Vmsa128Stage2LeafFields,
        _level: Level,
    ) -> Result<Self::LeafAttrs, AttrError> {
        Ok(Vmsa128Stage2LeafAttrs::new(
            resolver.decode_stage2_memory(Stage2MemoryEncoding::from_bits(
                fields.attr_index().bits(),
            ))?,
            resolver.decode_d128_permissions(ResolvedD128Permissions {
                indirection: PermissionIndirectionIndex::from_bits(fields.pii().bits()),
                overlay: PermissionOverlayIndex::from_bits(fields.poi().bits()),
            }),
            MemoryTransience::from_not_transient_bit(fields.nt()),
            DirtyState::from_not_dirty_bit(fields.ndirty()),
            Shareability::from_bits(fields.shareability().bits())?,
            fields.af(),
            resolver.decode_d128_stage2_alias(fields.alias_bit()),
            fields.contiguous(),
            fields.guarded(),
            fields.assured_only(),
            X::decode_leaf_output_address_space(resolver, fields.ns()),
        ))
    }

    fn encode_table_attrs(
        resolver: &AttributeResolver<C>,
        attrs: Self::TableAttrs,
        _level: Level,
    ) -> Result<Vmsa128Stage2TableFields, AttrError> {
        let output_address_space =
            X::encode_table_address_space(resolver, attrs.output_address_space)?;
        Ok(Vmsa128Stage2TableFields::from_arch_fields(
            attrs.transience.not_transient_bit(),
            attrs.access_flag,
            RawFieldBlock::from_masked(0),
            attrs.discharge,
            attrs.assured_only,
            !attrs.permissions.privileged_execute,
            !attrs.permissions.unprivileged_execute,
            RawFieldBlock::from_masked(encode_stage2_data(attrs.permissions.data_limit)?),
            output_address_space,
        ))
    }

    fn decode_table_attrs(
        resolver: &AttributeResolver<C>,
        fields: Vmsa128Stage2TableFields,
        _level: Level,
    ) -> Result<Self::TableAttrs, AttrError> {
        Ok(Vmsa128Stage2TableAttrs::new(
            Stage2TablePermissions {
                data_limit: decode_stage2_data(fields.aptable().bits())?,
                privileged_execute: !fields.pxntable(),
                unprivileged_execute: !fields.xntable(),
            },
            MemoryTransience::from_not_transient_bit(fields.nt()),
            fields.a(),
            fields.disch(),
            fields.assured_only(),
            X::decode_table_address_space(resolver, fields.nstable()),
        ))
    }
}

fn leaf_skip_levels<G: TranslationGranule>(level: Level) -> Result<RawFieldBlock<2>, AttrError> {
    let skip = Level::L3.as_i8() - level.as_i8();
    if !(0..=3).contains(&skip) || !vmsa128_skl_supported(G::KIND, skip as u8) {
        return Err(AttrError::InvalidD128Configuration);
    }

    Ok(RawFieldBlock::from_masked(skip as u128))
}
