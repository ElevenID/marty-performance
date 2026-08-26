# Hardware Profiles

Hardware profiles describe intended resource envelopes. `marty-perf doctor`
records the observed machine for each run; a checked-in profile is not proof
that the current machine still matches it.

The initial workstation is represented by
`profiles/ryzen9-9900x-wsl2-v1.json`. It remains provisional until CPU topology
and Docker CPU-set enforcement are verified. Comparable results must retain
the exact Docker memory cap instead of reporting only the host's installed
memory.

