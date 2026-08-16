# AArch64-VMSA
An AArch64-VMSA crate with the goal of full coverage of the `AArch64-VMSA` spec.

## Why this exists
 
crates such as `aarch64-paging` only support sections of the `AArch64-VMSA` spec currently it doesn't support other granuales then 4k, D128 or some translations regimes. 

The goal of this crate is to cover every portion of the spec and to do this with a generic and strongly typed approch. This is done so that mappers and walkers can be fully specialized at compile time on top of the idea is that adding new features becomes trivial in the face of the growing `AArch64` platform.

## Testing and Verification 
Testing and proving the impl is correct is probably the biggest issue facing a full AArch64-VMSA. 

We attempt to solve this by using FVP and a custom test harness (https://github.com/joe3925/aarch64-vmsa-test) to test every portion of the current crate. 
The harness launches a FVP instance for every translation regime that logic or semantics differ on. It then runs a catalog of tests for that instance, it properly hooks exceptions and has destructive tests (tests that will destroy the state of the instance so they are given there own instance) in order to confirm that everything always happens as expected. 

Currently there are no known gaps in the test harness every feature of this crate is tested and proven.

## Examples
### examples\basic_offline.rs
basic offline shows the usage of the crate on a `Vmsa64`, `NonSecureEl1Stage1`, `Granule4KiB` offline table. It is intentionally simple it just heap allocates memory to use as the table and will then have the crate offline VMSA operations on that memory. 

It demonstrates:
- How to create `TableGeometry`
- How to create a `RootTable`
- The usage of the `Mapper` to create a `leaf` mapping and `block` mapping. 
- The usage of the `Walker` to walk all the tables and retrive semantic attributes from the `table`, `leaf`, and `block` entries. 

## TODO
