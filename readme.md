# AArch64-VMSA
An AArch64-VMSA crate with the goal of full coverage of the `AArch64-VMSA` spec.

## Why this exists
 
crates such as `aarch64-paging` only support sections of the `AArch64-VMSA` spec currently it doesn't support other granuales then 4k, nor does it support D128 or some translations regimes. 

The goal of this crate is to cover every portion of the spec and to do this with a generic and strongly typed approch. This is done so that mappers and walkers can be fully specialized at compile time on top of the idea is that adding new features becomes trivial in the face of the growing `AArch64` platform.

## Testing and Verification 
Testing and proving the impl is correct is probably the biggest issue facing a full AArch64-VMSA. 

We attempt to solve this by using FVP and a custom test harness (https://github.com/joe3925/aarch64-vmsa-test) to test every portion of the current crate. 
The harness launches a FVP instance for every translation regime that logic or semantics differ on. It then runs a catalog of tests for that instance, it properly hooks exceptions and has destructive tests (tests that will destroy the state of the instance so they are given there own instance) in order to confirm that everything always happens as expected. 

The known gaps that cant currently be proven by the harness are listed below.

### Testing gaps

- `Vmsa128` with every SMMUv3 stage 1 and stage 2 regime cant be tested because there is currently no FVP with a working SMMUv3 D128 translation path. This includes the non-secure, secure, realm, privileged, and both stage 2 permission model combinations advertised by the crate.
- Software metadata in translation descriptors cant be tested by the FVP.
- Cache allocation and transience hints cant be proven by the FVP because they are hints and the architecture does not require an observable cache allocation or replacement result.
- The exact cache level a normal-memory page is stored in, cache hit and miss behavior, eviction policy, and exact write-back timing cant be proven because these are microarchitectural rather than VMSA translation results.
- The contiguous and BBM `NT` hints cant be proven as individual descriptor values when the implementation is allowed to behave the same with or without the hint.
- Every inner and outer normal-memory cacheability or shareability encoding cant be uniquely proven when multiple legal encodings produce the same architecturally observable access behavior. Device versus normal memory and required coherency behavior can still be tested where they produce an architectural difference.
- 
## Examples
### examples\basic_offline.rs
basic offline shows the usage of the crate on a `Vmsa64`, `NonSecureEl1Stage1`, `Granule4KiB` offline table. It is intentionally simple it just heap allocates memory to use as the table and will then have the crate offline VMSA operations on that memory. 

It demonstrates:
- How to create `TableGeometry`
- How to create a `RootTable`
- The usage of the `Mapper` to create a `leaf` mapping and `block` mapping. 
- The usage of the `Walker` to walk all the tables and retrive semantic attributes from the `table`, `leaf`, and `block` entries. 

## TODO

- [ ] Support compact/partial SMMU root tables and their reduced input-address range; descendant tables already remain lazily allocated.
