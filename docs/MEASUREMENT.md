# Measurement Method

## Primary outputs

- End-to-end p50, p90, p95, p99, and maximum latency.
- Successful operations per second at a fixed offered load.
- Maximum sustainable throughput found during calibration.
- Error, timeout, and correctness-check rates.
- Per-container CPU, memory, throttling, storage, and network consumption.
- Per-service and dependency latency after shared instrumentation lands.

## Comparison campaign

Use interleaved repetitions to reduce time-dependent bias:

```text
baseline → candidate → baseline → candidate → baseline → candidate
```

The future comparison command will report confidence intervals, coefficient of
variation, and effect size. It must label changes inside the measured noise
floor as inconclusive rather than as a speedup or regression.

Calibration finds the highest offered load that preserves correctness and
avoids accumulating latency. Standard steady runs use approximately 60% of the
baseline's calibrated capacity. Latency comparisons use equal offered load;
throughput comparisons use equal correctness and saturation criteria.

## Run modes

- `comparable`: reduced logs, Prometheus/container metrics, fixed trace
  sampling, and no profiler.
- `diagnostic`: full traces or native profiling; never mixed into comparable
  statistics.

A separate no-telemetry control quantifies instrumentation cost.

## SD-JWT issuance qualification

The issuance microbenchmark uses a source-emitted canonical manifest rather
than rediscovering Criterion IDs from filesystem paths. Freeze its
pre-analysis protocol before building or timing:

    cargo run --locked -- qualification issuance plan \
      --manifest <canonical-manifest.json> \
      --output <absolute-new-plan.json>

The selected-route offline analyzer validates the currently implemented
artifact-integrity slice from fixed campaign roles without launching a
controller, benchmark, or network request:

    cargo run --locked -- qualification issuance analyze \
      --campaign-root <absolute-campaign-root> \
      --route-artifact routes/r00_c00_e0.ndjson \
      --anchor-public-key <out-of-band-raw-32-byte-ed25519-key> \
      --output <absolute-new-analysis.json>

The indexed analyzer first applies that same trust and artifact-integrity
pipeline, including the selected route supplied through `--route-artifact`.
It then traverses the exact canonical Criterion and route indexes, validates
all 10,560 Criterion estimate artifacts and all 10,560 route artifacts with
separately checked aggregate byte counts, and produces 66 paired-cell results
in manifest order:

    cargo run --locked -- qualification issuance analyze-indexed \
      --campaign-root <absolute-campaign-root> \
      --route-artifact routes/r00_c00_e0.ndjson \
      --anchor-public-key <out-of-band-raw-32-byte-ed25519-key> \
      --output <absolute-new-indexed-analysis.json>

Its plan-bound deterministic bootstrap reports the combined, serial-first,
adaptive-first, and disclosed order effects as adaptive-over-serial log ratios
and relative percentages. The first three effects use the predeclared
simultaneous common-max-deviation interval; the order diagnostic uses its
marginal Type 7 interval. Logarithms and exponentials use the exact pinned
`libm 0.2.16` software implementation with architecture-specific paths disabled;
bit-pattern goldens guard the supported-target result contract, and the report
records `libm_0_2_16_force_soft_floats`. Criterion median point estimates are
estimator outputs, not individual-operation p50, p95, or p99 latency. The
indexed report therefore marks tail latency and throughput as `not_evaluated`,
allocation and SIMD-lane evidence as `not_measured`, campaign qualification as
`not_evaluated`, and production-threshold activation as `false`.

The lifecycle analyzer applies the common trust pipeline, then opens every
completion-bound segment and actual timing-window attestation in order. It
validates the complete segment fingerprint chain and footer aggregates, one
controller UTC-to-monotonic affine mapping, contiguous event and sample
ordinals, active-attestation coverage for every traversed segment record and
footer plus the terminal request, continuous pre-timing monitor coverage, and
all 10,560 serial process intent/start/finish triples against the frozen schedule
and completion bindings. It also validates the exact host identity,
validity-threshold, and baseline unrelated-process-set preimages used for every
sample, and proves that baseline is the sole content-addressed observed process
set:

    cargo run --locked -- qualification issuance analyze-lifecycle \
      --campaign-root <absolute-campaign-root> \
      --route-artifact routes/r00_c00_e0.ndjson \
      --anchor-public-key <out-of-band-raw-32-byte-ed25519-key> \
      --output <absolute-new-lifecycle-analysis.json>

Its scope literal is
`complete_segment_chain_and_embedded_lifecycle_semantics_v1`. A `valid`
`artifact_integrity_status` covers only artifacts actually traversed by this
command. It does not cover nonselected route or Criterion-estimate contents,
the Criterion or route indexes, complete Criterion homes, invocation, barrier,
or inventory preimage contents, the first-quiet-window attestation or evidence
contents, or other limitations listed in the report. Its bounded
`embedded_lifecycle_semantics_status` does not reconstruct nonterminal
close-trigger counterfactual precedence or protocol-wide uniqueness against
untraversed nonce preimages. Qualification and activation remain false or not
evaluated.

All three commands verify the exact V3 plan/manifest binding, the
coordinate-selected route record against the retained hardware profile, the
source Git tree/commit and Cargo.lock, typed controller and monitor
configurations, the typed build receipt and streamed build-input archive,
installed binary fingerprints, the
anchored genesis, the terminal segment's bounded record envelopes and footer
summary, and both offline anchor signatures and their same-clock publication
bound. In selected-route and indexed modes, each record using one of the six
lifecycle variants in either inspected segment requires the frozen complete
deny-unknown payload shape and exact compact canonical bytes: continuation,
sample,
process-intent, process-start, process-finish, and attestation-transition. The
segment-zero genesis header is separately typed and canonicalized, as is only
the terminal segment footer. When the genesis and terminal segments differ,
the nonterminal footer ending the inspected genesis segment is outside this
payload-validation slice. Payload shape and canonicality do not establish
lifecycle semantics. Structural inspection of non-footer envelopes in both
inspected segments separately binds campaign, segment and contiguous record
ordinals, exact UTC grammar, and nondecreasing monotonic values. Validation
of the terminal segment footer alone additionally binds its header/footer
time bounds and the five reconstructed terminal-segment type counters.
Those two modes do not traverse or chain intermediate segments or validate
complete within-record and cross-record lifecycle semantics; the opt-in
lifecycle mode performs that bounded replay. Governed inputs are opened
relative to retained directory handles without following links; regular files
must have
one link and remain the same size, identity, and stable metadata through their
exact-length read. Unix file and directory-component opens also set
nonblocking and no-controlling-terminal flags before the retained-handle type
check, so FIFO substitutions reject instead of waiting for a peer and device
leaves cannot acquire a controlling terminal before type rejection. Each
output is deterministic create-new canonical JSON, published without
replacement through a same-directory temporary file on
supported local filesystems and synced as a file. Parent-directory durability
is also synced on Unix; exact crash durability and no-replace rename behavior
remain operating-system and filesystem properties. Temporary-file creation
and final publication are pathname-based, so the output-parent path and its
ancestry must remain quiescent for the entire analysis; retained-handle checks
make observed namespace changes fail closed but do not make publication
race-resistant against a hostile concurrent ancestry swap. The destination
must be outside the retained campaign root. The selected-route report scope is
`offline_artifact_integrity_subset_v1`; it always records campaign
qualification as `not_evaluated` and production-threshold activation as
`false`. The indexed report scope is
`all_indexed_route_and_criterion_estimate_artifacts_v1` and retains the same
nonactivating decisions. The lifecycle report uses the bounded scope described
above and also remains nonactivating. Complete Criterion-home traversal, full
auxiliary process-preimage traversal, first-quiet-window content and build-order
validation, tail latency, throughput, allocation, SIMD-lane evidence,
target-campaign threshold discovery, activation, and re-execution of the
retained build tree's offline dependency-resolution probe remain separate
future analyzer phases. All three commands verify the receipt's exact probe
command and retained result; they do not materialize that tree or run the
command. They also do not validate
first-quiet-window contents or prove the build began after that window. Run
analysis only against a quiescent campaign directory or
an immutable filesystem snapshot: per-file handle binding does not make the
multi-file traversal one atomic snapshot.

All reports are always nonactivating. If a file or parent durability/identity
check fails after the create-new publication step, the command returns an
error, but the already published nonactivating report may remain. No analyzer
attempts a pathname cleanup that could target a concurrently replaced entry.

`--anchor-public-key` is an operator-selected trust input. It must be an
absolute, read-only, single-link 32-byte file outside the campaign tree. Each
analyzer proves that the campaign configuration and signatures bind that key;
none proves that the key was independently preconfigured or trusted.

The plan command rejects changed matrix cardinality, route or estimator
versions, noncanonical bytes, activated production thresholds, reused
benchmark IDs, and an existing output. A compiled 1 MiB cap is enforced before
V3 UTF-8 or JSON parsing; the plan cannot enlarge its own allocation boundary.
The v3 plan fixes two independent 45-minute quiet windows, one source-bound
same-HEAD executable, 20 eight-process
superblocks per paired cell, the Criterion process arguments, and the
whole-global-round simultaneous bootstrap. Each global round visits all 66
cells in manifest order and runs each eight-process expansion serially before
the next cell; its ordinal is therefore one shared bootstrap cluster across
the complete D/S/P/O family.

The multi-day campaign requires bounded, create-new SHA-256-chained validity
segments sampled every five seconds with no gap over ten seconds. One
nonrestarting controller owns the only authoritative monotonic origin and
timestamps every observed monitor, child, segment, and completion event; child
and monitor clocks are never compared across processes. Samples distinguish
idle, launching, and active-process states. Monitoring starts no later than the
second quiet-window boundary, proves all 2,700 clean seconds before process
one, and continues through the last Criterion and route-artifact sync.

The first quiet window is a versioned 2,700-second package with the same host
and boot pseudonyms, thresholds, invalidators, monitor, controller, and
test-window bindings. Closed, deny-unknown v1 schemas govern controller and
monitor configuration, host identity, hardware, thresholds, unrelated-process
sets, and test-window evidence. Process-set and target identities use distinct
independently sampled 32-byte campaign-ephemeral HMAC keys. Their exact inputs
are an ASCII domain, `0x00`, a big-endian `u64` byte length, and the frozen raw
tuple or RFC 6454 HTTPS-origin serialization. Outputs are 64 uppercase hex
characters. Host, boot, launch-process, change-reference, and anchor-challenge
aliases are fresh independent 32-byte values with the same exact encoding and
no key or value reuse. Raw host IDs, PIDs, process names, command lines,
endpoints, ticket identifiers, and credentials are not retained. The trusted
controller validates the raw operator authorization, target origin, and change
reference in memory. Exported evidence proves pseudonym continuity, but
deliberately cannot recover or independently reauthenticate those raw mappings
after the campaign.

Every first-window and campaign sample must satisfy the bound validity
thresholds exactly: CPU and process-count maxima are inclusive, enabled memory
and frequency minima are inclusive, temperature maxima are inclusive, and any
forbidden throttle flag rejects the campaign. A zero memory or frequency
minimum disables only that minimum. The exact hardware profile is retained as
an intentional operational exception and can remain a cross-campaign
quasi-identifier even though the campaign-random aliases are unlinkable. Exact
source commits, toolchain and binary fingerprints, anchor channel/log/key IDs,
and authenticated timestamps are also intentionally retained stable metadata
and can link otherwise pseudonymous campaigns.

Fixed role paths retain the exact plan, manifest, Cargo.lock, controller and
monitor binaries and configurations, anchor-channel configuration, hardware
profiles, thresholds, baseline process set, and content-addressed observed
process sets. `source/exact-tree.sar` is an exact, length-prefixed binary source
archive: a fixed magic header is followed by big-endian lengths, a canonical
manifest, one raw bound commit object, and only the regular-file bytes in the
bound Git tree. The complete archive is capped at 16 MiB, its manifest at
4 MiB, its commit at 1 MiB, and it permits at most 65,536 entries. Portable
ASCII paths are unsigned-byte sorted, at most 1,024 bytes and 256 segments,
with a 255-byte segment limit. Drive and ADS syntax, device names, trailing-dot
aliases, case-fold collisions, and file/directory-prefix conflicts reject.
Every path component whose ASCII case-folded form is exactly `.git` or
`.cargo` also rejects, including a root administrative file or nested
administrative directory; ordinary `.gitignore`, `.gitattributes`, and
`.gitmodules` files remain valid.
Extraction uses directory-handle-relative, no-follow, create-new operations and
verifies each opened handle remains beneath the build root, including on a
case-folding or normalization-lossy target filesystem. The outer fingerprint
is verified before any manifest parse; every conversion, subtraction, and
inner allocation is checked. A one-pass component trie is limited to 131,072
directory nodes and 4 MiB of logical cloned component bytes; each node is
hashed once in reverse creation order, avoiding quadratic prefix scans. There
are no archive-added container headers, padding, timestamps, or unused
metadata. The retained raw Git commit still contains its normal author and
committer metadata, timestamps, and parent identifiers. Validation reconstructs
every Git blob, tree, and commit ID; requires one canonical nonnegative
committer Unix timestamp for `SOURCE_DATE_EPOCH`; and rejects refs, extra
history objects, links, repository config, remotes, recursion, and extra
records. Only the commit-header prefix is parsed bytewise. The tree and final
committer timestamp/timezone tokens have exact ASCII forms, while author and
committer identities, an `encoding` header, and non-UTF-8 message bytes remain
opaque and are still covered by the complete raw Git object ID. The controller
must explicitly attest that this exact source commit is approved for export;
source bytes are the documented exception to operational-metadata privacy
rules.

The nonactivating source-export command produces that exact fixed-role artifact
from local Git objects only:

```text
marty-perf qualification issuance source-archive export \
  --repository /absolute/clean/source-repository \
  --source-commit 40-lowercase-sha1 \
  --source-tree 40-lowercase-sha1 \
  --output /absolute/retention/source/exact-tree.sar \
  --approve-source-export
```

The repository must be a normal clean SHA-1 worktree with its own self-contained
`.git` directory. Inherited Git controls are scrubbed; replacement objects,
lazy fetching, linked or common-directory metadata, alternate object stores,
dirty tracked or untracked files, links, nonportable paths, case-fold aliases,
and any source view that changes during export reject. The exporter reads no
remote and includes only the approved raw commit plus every regular file in
the exact tree, sorted by repository-relative path. It reconstructs and checks
every blob, the complete tree, the commit, and the exact `Cargo.lock` through
the same bounded validator used by retained evidence before creating a
read-only `source/exact-tree.sar`. The destination parent must already exist;
the file is create-new and cannot be placed beneath the source repository.
This command creates no campaign, build receipt, qualification threshold,
network request, benchmark result, or activation claim.

The next nonactivating controller boundary composes that in-process export
receipt with the already-open, read-only `source/exact-tree.sar` handle and an
explicit allowlist of already-open public build-input handles. Every build
input carries an exact uppercase SHA-256 and byte-length pin, a closed logical
role and mode, and a handle-relative staging-root binding. There is no glob,
directory discovery, inherited host path, network access, or secret-input
role. The source-export root, each build-input root, and the new create-only
campaign root are retained as non-cloneable handle capabilities and must be
pairwise neither equal nor ancestors of one another. The controller checks
the receipt's archive, `Cargo.lock`, commit, tree, and member count; the common
campaign ID and target; every approved, allowlisted original staged file
handle; and the canonical retained source, inventory, and framed archive before
returning one opaque `CapturedFixedBuildInputs` capability. Any governed
coordinate mismatch or detected retained-root, approved-binding, or
approved-byte time-of-check/time-of-use change returns no capability, and any
partially written create-only campaign root is poisoned rather than retried.
Consuming the capability only enables the existing immutable materializer; it
does not launch Cargo or rustc, read a remote, create a build or install
receipt, observe a quiet window, run a benchmark, evaluate a threshold, or
activate CDLA. This composition boundary has no command-line entry point.

The current campaign artifact-store kernel deliberately fails closed before
creating a campaign root when the controller runs on Windows because durable
directory synchronization is not implemented there. Consequently this
composition capability is currently unavailable to a Windows-host controller.
An eligible non-Windows controller may bind an explicit Windows target and its
approved staged Windows inputs; that does not claim Windows-host capture or
materialization support.

`build/fixed-benchmark.json` then binds that verified archive and Cargo.lock to
the exact Cargo and rustc binaries/versions, target, `bench` profile, sole
`issuance_bench` feature, exact working directory and logical Cargo command,
build interval, unique compiler-artifact executable, and both produced and
installed binary fingerprints. `build/input-inventory.json` completely binds
the read-only Cargo dependency/configuration inputs, Rust distribution,
linker, archiver, dynamic tool dependencies, staged Windows runtime inputs,
and executable `PATH` directories under closed roles, portable logical modes,
and path/cardinality rules. `build/input-files.bia` retains those exact member
bytes: fixed magic, then one big-endian `u64` length and member body for every
inventory entry in canonical order, followed by immediate EOF. The inventory
is the separate manifest and binds every role, path, `100644`/`100755` mode,
SHA-256, length, checked member total, and archive fingerprint. The build
receipt independently binds both inventory and archive fingerprints.

The 2 GiB build-input cap applies to the complete archive, including magic and
framing. It fits the measured 733,006,527-byte pinned Windows Rust sysroot plus
the projected dependency and tool inputs. Validators verify the outer archive
fingerprint before framing, then stream a second pass over the same immutable
handle; they never buffer the archive or allocate from an unverified member
length. Missing, extra, reordered, aliased, mode-mutated, or byte-mutated
members reject. Materialization is create-new and converts portable logical
modes into read-only data or executable policy without retaining host ACLs.
The archive is an explicit stable-metadata exception: it may link campaigns
and may contain only approved public dependency, configuration, toolchain,
linker, archiver, and runtime bytes—not credentials, private source, secrets,
or operational capture data.

The controller mounts a private campaign directory at the fixed nonpersonal
root `M:/marty-cdla-build-v1` on Windows or `/marty-cdla-build-v1` elsewhere.
It preserves one Rust distribution layout under `ROOT/inputs/toolchain`, with
Cargo and rustc in `toolchain/bin` and the matching sysroot below the same
root. `CARGO_HOME` is exactly `ROOT/inputs/cargo-home`, and its retained
configuration is the Cargo-discovered `ROOT/inputs/cargo-home/config.toml`;
its exact retained bytes are `[net]\noffline = true\n` (the two `\n`
sequences denote LF bytes, including the terminal LF), with no other table or
field;
`RUSTC` is the retained toolchain member; `rustc --print sysroot` must report
`ROOT/inputs/toolchain`; and `PATH` begins with that distribution's `bin`
directory. The target triple is 1 through 128 ASCII alphanumeric, hyphen,
underscore, or dot bytes, but exact `.`, exact `..`, exact `host-tuple`, and
every ASCII case-insensitive `.json` suffix are excluded. The target linker environment entry contains the
concrete derived name, such as
`CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER`, never a template, and resolves to
the unique retained linker member selected by the inventory.
On Windows, `SystemRoot` and `WINDIR` both resolve to the retained staged
`ROOT/inputs/windows-runtime/SystemRoot`, so no live unbound runtime tree is
admitted. Cargo-generated absolute values such as `CARGO_MANIFEST_DIR` and
`OUT_DIR` must derive from the fixed root.

Before the actual build, the controller runs the exact retained rustc sysroot
probe and a real `cargo metadata --frozen --offline --locked --format-version
1` dependency-resolution probe under the same cleared environment, staged
tree, network prohibition, and read sandbox; both must succeed and are bound in
the v2 receipt. The success boolean is a trusted-controller attestation, not a
substitute for retained inputs. The frozen complete qualification protocol
requires its full analyzer to reconstruct the same tree, repeat the exact
offline metadata probe, and invalidate the campaign on failure or dependency
drift. The current `offline_artifact_integrity_subset_v1` command instead
verifies the typed receipt and every retained archive member byte but does not
materialize that tree or rerun the probe. Isolated Cargo, target, and temporary directories are used,
wrappers and ambient flags are forbidden, and the sandbox rejects any
uninventoried readable input or write outside its declared outputs. The trusted
controller creates the receipt after the first quiet window and before
genesis. A relocated, stale, extra, unretained, or differently built
executable cannot satisfy it.

The first-window attestation has the disjoint fixed
path `attestations/first-quiet-window.json`; the actual timing chain uses
`attestations/timing-window-0000.json` through `timing-window-0015.json`.
Genesis binds those validated preimages and the current—not future—timing
attestation. Renewals are create-new chained records produced only after the
shutdown conditions are rechecked. Intervals are start-inclusive and
expiry-exclusive. The first attestation covers the full first quiet window;
the initial timing attestation begins no later than the second quiet window,
and the exact referenced active attestation covers every header, sample,
lifecycle, artifact-sync, terminal, and anchor-request event. Expired, future,
uncovered, or one-nanosecond-gap chains reject the campaign.

Every timing process has a coordinate-derived invocation descriptor, static
token, fresh Criterion home, and portable relative artifact paths. The parent
environment is cleared and rebuilt from the frozen allowlist. Campaign paths
are recorded only as role-relative values; the controller derives the absolute
values required by Criterion and the route sink without retaining raw account
paths, inherited environment bytes, path digests, or secrets. `SystemRoot` and
`WINDIR` are host roles only on Windows and are absent on other targets.
`TEMP` and `TMP` both resolve to the unique coordinate directory
`tmp/rNN_cNN_eN`.

The static token is written and synced before intent. Its nonce and independent
process pseudonym are exact, unique, non-reused 64-uppercase-hex values. At custom benchmark
process entry—before Criterion is constructed—the child validates that token,
emits one bounded canonical ready frame as its first stdout frame, flushes it,
and makes a blocking stdin read its next operation. The controller persists the
ready frame, checks the real PID only in memory against the spawned handle and
exclusive pipes, syncs a pseudonymous start that binds the ready frame,
persists a release frame binding that start, and only then sends the exact
release bytes and closes stdin. The
child rejects partial, extra, early-EOF, or mismatched data and syncs a receipt
before entering Criterion. The persisted, checked
`start.monotonic - intent.monotonic <= 30 seconds` rule conservatively proves
the narrower spawn-to-ready bound. Only the canonical ready frame is retained;
later stdout and all stderr are continuously bounded, drained, and discarded,
with numeric byte counts retained in the typed process-finish record. Checked
addition of stdout-after-ready and stderr counts must remain at or below the
1 MiB per-process bound. Broken pipes, early exit, underflow, arithmetic
overflow, or an output-limit violation invalidates the campaign.
The finish record also requires its retained elapsed duration to equal checked
`finish.monotonic - start.monotonic`, be positive, and remain at or below five
minutes; release preparation must lie between the matching start and finish.

Every direct fixed-binary invocation uses this exact logical Criterion 0.5.1
argument order, substituting the selected full ID for the placeholder:

    --bench --exact {full_benchmark_id} --sample-size 50 \
      --nresamples 100000 --warm-up-time 15 --measurement-time 10 \
      --confidence-level 0.95 --save-baseline base --noplot

`--bench` is required to enter measurement mode; `--exact` makes the full ID a
literal rather than a regular expression.

`SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID` equals the exact Criterion filter. The
fixed binary validates its complete 132-record preflight matrix but writes only
the one selected typed route record to the absolute create-new path supplied in
`SD_JWT_ISSUANCE_ROUTE_NDJSON`. This reduces the measured route-evidence
projection from about 6.39 GiB to 48.41 MiB across the campaign. Each fresh
Criterion home contains exactly the eight Criterion 0.5.1 files for one ID,
totaling 4,832 bytes in the locked validation run:
matching `base` and `new` copies of `benchmark.json`, `estimates.json`,
`sample.json`, and `tukey.json`.

Marty-owned JSON uses locked `serde_json` 1.0.151 typed round-trip bytes:
unknown, duplicate, missing, nonfinite, wrongly typed, and trailing data are
rejected. Route evidence has its own one-compact-record-plus-LF protocol.
Criterion-owned files are opaque hashed bytes. Selected analysis interprets
only its selected projection; indexed analysis interprets the exact Criterion
0.5.1 projection of every indexed `new/estimates.json` while leaving the rest
of each Criterion artifact home untraversed.
Canonical Criterion and route indexes map all 10,560 coordinates to those
artifacts. The route contract closes every stage, requested/effective route,
work-status, budget-result, mode, and selection-reason literal. It freezes all
nullability couplings, batch-count equations, selector branches, and static
chunk ordinal/count/work-sum equations. Index kinds and slash-normalized path
formatters are also exact. Fixed role and ordinal paths reject escape,
alternate padding or separators, links/reparse points, missing artifacts,
duplicates, and extras.

After the terminal segment, the configured create-only log signs ordinal 0, a
terminal-observation receipt over the terminal fingerprint and controller
monotonic request value. The controller records receipt observation on its own
monotonic clock in a create-new wrapper. A separate completion manifest then
binds that wrapper, the ordered segment and attestation chains, exactly 10,560
lifecycle triples and receipts, inventories, and the two canonical artifact
indexes. Only after completion is durably synced does the log sign ordinal 1,
binding completion, terminal, and ordinal-0 evidence.

Both retained receipts use strict RFC 8032 Ed25519 over exact domain-separated,
length-prefixed canonical JSON, include the channel ID, log ID, campaign,
ordinal, key ID, unique challenge, and locator, and are verifiable offline from
the bound 32-byte public key in the analyzer's read-only out-of-band trust
store. No network access is used during analysis. The analyzer applies a
hardcoded 16 KiB cap-plus-one check to each receipt before UTF-8 or JSON parsing
and rejects any conflict for
`(channel_id, log_id, campaign_id, campaign_append_ordinal)`; ordinals are
exactly zero and one. Both receipts bind the same nonrestarting channel clock
session and signed SI-nanosecond monotonic values; a restart changes the session
ID. The five-minute channel-publication proof avoids cross-clock comparison: it
checked-adds terminal-to-receipt-observation on the controller monotonic clock
and ordinal-0-to-ordinal-1 on the channel monotonic clock. Channel and
controller UTC values are authenticated audit metadata only. Underflow,
overflow, session change, or one nanosecond over the limit rejects. This bound
proves channel publication, not local ordinal-one delivery or sync. The pinned
channel's create-only uniqueness and non-equivocation property is an explicit
out-of-band trusted-service assumption: an offline bundle cannot discover a
conflicting receipt withheld by that channel, but every supplied same-tuple pair
whose exact canonical signed bytes differ is rejected—even when the receipt
locator is reused. Only byte-identical retrieval is idempotent. The unkeyed
local chain is tamper evidence; the two signed offline receipts provide
authenticity and detect truncation or wholesale replacement.

Segments are limited to 12 hours, 64 MiB, 65,536 records, and 64 KiB per
validity-record line. Footer closure reasons are limited to the next event
exceeding duration, the next record exceeding bytes or count (in frozen
precedence), or completion of the unique terminal campaign; free-form reasons
are invalid. CPU percentages are finite in `[0,100]`, frequency is bounded at
1 through 10 GHz, temperature at -100 through 200 degrees Celsius in
millidegrees, memory and CPU counts have exact protocol maxima, and threshold
cross-fields are checked against the bound hardware profile. Selected route
artifacts are limited to 1 MiB each and 128 MiB in aggregate; Criterion homes
are limited to 1 MiB each and 512 MiB in aggregate. The whole campaign remains
limited to 16 segments, one million records, 4 GiB, seven days, and five
minutes per timing process. Validators
stream inputs and reject a declared or actual size before any individual,
subtotal, or aggregate bound is crossed. Any gap, abnormal exit, timeout, sync
failure, invalid renewal, resource violation, missing anchor, or other
invalidating event rejects the entire campaign; rounds cannot be deleted,
resumed, or analyzed selectively.

The 16 MiB auxiliary-preimage fallback applies only to controller, monitor,
anchor-channel, host/hardware/threshold, attestation, process-set, invocation,
barrier, and inventory JSON that lacks a dedicated cap. Dedicated route,
Criterion, retained build-input archive, segment, completion, anchor-receipt,
and source-archive caps take precedence; the typed build-input inventory
remains under the auxiliary JSON cap, and every physical artifact is counted
exactly once toward the campaign total.

Every bootstrap replicate draws 20 whole global rounds with replacement from
one continuous replicate-major SplitMix64 stream. Rejected generator outputs
consume state and retry the current draw. The same round vector produces
D/S/P/O; only D/S/P enter the simultaneous max-deviation band, while O receives
a marginal type-7 interval. Discovery gates use the exact relative-percent
transform `100.0 * (exp(effect) - 1.0)`. It describes 10,560 fresh timing
processes but does not execute them or activate a production threshold. Frozen
v1 or v2 evidence must not be reinterpreted as v3.

Fixed-build execution, complete Criterion artifact-home traversal,
first-window content and build-order validation, auxiliary process-preimage
validation beyond the embedded segment records, individual-operation tail
latency, end-to-end throughput, allocation and SIMD/lane measurements, target
campaign execution, threshold discovery, and production activation all remain
later work. The lifecycle analyzer validates the complete retained segment
chain and its embedded lifecycle semantics within the explicit limitations
above. Indexed analysis never pools a target triple, hardware profile, fixed
binary, build receipt, manifest, or plan with another campaign.

## Test window

Contract-defined workloads require a time-bounded attestation that production
traffic is drained, public ingress is disabled, the authorized target matches
the requested gateway origin, and only synthetic data will be used. The harness
validates and binds this evidence but never performs the shutdown itself.

Smoke requests against local mocks do not require a test window. Smoke requests
against production hardware do.

## Invalid conditions

Reject or quarantine a run with response-check failures, unexpected runtime
fallbacks, OOMs, material CPU throttling, thermal instability, uncontrolled
background load, changed build/topology inputs, or incomplete evidence.
