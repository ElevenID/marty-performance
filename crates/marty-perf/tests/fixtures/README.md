# Qualification fixtures

`sd-jwt-issuance-qualification-manifest-v1.json` is the canonical synthetic
manifest emitted by `ElevenID/sd-jwt-rust` commit
`c2fcb62624b6f7d4a7b1a2ddf5389e15b2ca1245` on x86-64 with:

```text
cargo run --locked --no-default-features --features issuance_bench \
  --example issuance_qualification_manifest -- --output <absolute-new-file>
```

Its SHA-256 is
`04EFEB5E52EF19A0278383F9FD8C574F0B0F24941CD5FCD764696A6E496EDC1F`.
The fixture contains no credentials, keys, personal data, or timing results.
The checked-in x86-64 manifest records worker cap 4; validation separately
accepts the target-specific cap while freezing the exact cases, IDs, and cells.
