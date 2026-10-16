# fido_search — offline key search for the RIOT FIDO2 timing ladder

Enumerates the constraint set described in
[`../GPU_SEARCH_REQUIREMENTS.md`](../GPU_SEARCH_REQUIREMENTS.md) and returns every
key that reproduces all oracle pairs under AES-128-ECB.

It runs on the **CPU and the GPU together**. On ten cores of an i9-13900KF it
sustains 3.17 × 10⁹ candidates/s using VAES; adding an RTX 3060 over OpenCL brings
that to **6.4 × 10⁹**. `full-2^44` closes in about **46 minutes** against the
1 h 32 min the CPU alone took, and `real-2^50` — the size §2.1 of the brief says to
design for — comes down from ~99 hours to **~49**.

The GPU is worth ~1.15× the ten CPU cores, not the 10× a GPU port usually
promises. That is not a tuning failure and it does not get better with effort; see
[*Why the GPU is only worth 1.15×*](#why-the-gpu-is-only-worth-115) below, which is
the part to read before buying hardware for this.

## Build and run

No crates, no cargo, no network — one `rustc` invocation. The GPU path needs no
toolkit either: the kernel is embedded in the binary as OpenCL C and compiled at
run time by the driver's own compiler, reached through the ICD loader
(`OpenCL.dll`) that ships with the GPU driver.

```bash
powershell -ExecutionPolicy Bypass -File build.ps1
```

```bash
./fido_search.exe --all --gpu
```

`--all` is the default action: FIPS-197 C.1, the randomised self-checks, the GPU
known-answer tests, then every vector up to 2³⁶ with a measured rate and an
extrapolation to the larger ones. Vectors above that are named but **not** run
without being asked.

```bash
./fido_search.exe --vector real-2^50 --gpu --checkpoint ck.txt
./fido_search.exe --vector real-2^50 --gpu --checkpoint ck.txt --resume
```

| option | meaning |
|---|---|
| `--vectors <path>` | constraint file (default `../search_vectors.json`) |
| `--vector <name>` | solve one vector by name, or `all` |
| `--selftest` | FIPS-197 plus the randomised, position-sweep and GPU cross-checks |
| `--threads <n>` | CPU worker threads (default 10, or 9 with `--gpu`) |
| `--cpus <list>` | pin to exactly these logical CPUs |
| `--no-affinity` | do not pin |
| `--backend <name>` | `auto`, `vaes`, `aesni` or `scalar` — forces a CPU kernel so the fallback paths can be exercised on a CPU that has VAES |
| `--gpu` | also search on the GPU, alongside the CPU threads |
| `--gpu-only` | search on the GPU alone |
| `--gpu-device <n>` | which GPU, if there is more than one |
| `--gpu-wg <n>` | work-group size (default 256) |
| `--gpu-grid <n>` | work-items per launch (default 8 groups per compute unit) |
| `--gpu-repl-sh <n>` | log2 of the T0 replication factor (default: the largest the device can hold, up to 5) |
| `--gpu-batch <n>` | candidates per launch (default 2³⁰) |
| `--checkpoint <p>` | record progress to `<p>`, first write immediately then about once a minute |
| `--resume` | start from `<p>`'s watermark instead of the beginning |
| `--quiet` | no progress line |

By default it pins one thread per *physical* core, performance cores first, using
`GetLogicalProcessorInformationEx`. With `--gpu` one core is left for the thread
that drives the device — NVIDIA's `clFinish` spins — so the default is nine CPU
workers plus the GPU rather than ten plus the GPU.

## Results

Measured on an i9-13900KF (8 P-cores + 16 E-cores, VAES/AVX2, no AVX-512) and an
RTX 3060 (28 SMs @ 1.84 GHz, compute capability 8.6), Windows 11, rustc 1.96.

| vector | space | hits | CPU only | CPU + GPU |
|---|---|---|---|---|
| FIPS-197 C.1 | — | pass | — | — |
| `tiny-2^14` | 16 384 | 1 ✓ | 0.001 s | 0.001 s |
| `small-2^26` | 6.7 × 10⁷ | 1 ✓ | 0.044 s | 0.044 s |
| `medium-2^34` | 1.7 × 10¹⁰ | 1 ✓ | 5.44 s, 3.16 G/s | 2.71 s, **6.35 G/s** |
| `full-2^44` | 1.76 × 10¹³ | 1 ✓ | 5543 s = 1 h 32 min 23 s | **2772 s = 46 min 12 s**, 6.347 G/s |
| `real-2^50` | 1.13 × 10¹⁵ | 1 ✓ (seeded, below) | ~99 h extrapolated | **~49 h** extrapolated |

`full-2^44` is the end-to-end claim: a whole 2⁴⁴ space swept with both devices,
returning exactly one hit equal to `answer_key_hex`, in
[`full_run_gpu.log`](full_run_gpu.log). Exactly 2.00× the CPU-only sweep.

Other configurations on `medium-2^34`, all returning the same single hit:

| configuration | rate |
|---|---|
| 10 CPU threads, no GPU | 3.14 G/s |
| `--gpu-only` (0 CPU threads) | 3.36 G/s |
| 9 CPU threads + GPU | **6.35 G/s** |
| 9 CPU threads + `--gpu-device 0,0` | 5.08 G/s |

The last row is a *correctness* test, not a scaling one: it opens two independent
contexts on the one physical card so the several-device path gets exercised on a
machine that has a single GPU. Both workers take chunks, the work splits 50/50, and
one hit comes back — the rate is lower than a single context precisely because the
two contend for the same silicon.

Every vector returns **exactly one** hit, equal to its `answer_key_hex`:

```
KEY : 2b7e151628aed2a6abf7158809cf4f3c
```

Device split on `medium-2^34`, from the run's own counters:

| device | rate | share of the space |
|---|---|---|
| 9 CPU threads | 2.80 G/s | 45% |
| RTX 3060 | 3.55 G/s | 55% |
| together | **6.35 G/s** | |

The card does 3.62 G/s on its own; it gives up ~2% when the CPU threads are also
running, and the CPU gives up rather more than that because one of its ten cores is
the thread driving the device. Both numbers in the table are what the run's own
counters recorded, not the standalone figures.

The two are additive because there is no schedule: one atomic cursor over the
outer index, and every worker — each CPU thread and the GPU — takes chunks from
it. A device twice as fast simply comes back twice as often, so adding a second
GPU or a slower one needs no rebalancing.

### `real-2^50`

The full sweep is ~49 hours, which has not been run. What *has* been run is the
production path over the part of the space that contains the answer: the answer's
outer index on `real-2^50` is 46 426 562 472 of 68 719 476 736 (67.6%), so seeding
a checkpoint at 46 424 562 472 and resuming scans through it on the real vector
with both devices. That run recorded

```
hit=2b7e151628aed2a6abf7158809cf4f3c
```

in its checkpoint. That establishes that the 2⁵⁰ shape — byte 0 **and** byte 15
unreached — reconstructs, enumerates and matches correctly, and that resume works;
it does **not** establish that the whole space is covered. The full-space claim
rests on `full-2^44`, which is swept end to end.

## Why the GPU is only worth 1.15×

Short version: **the CPU has an AES instruction and the GPU does not.**

One candidate is a full AES-128 key schedule plus one block encryption — 160 S-box
evaluations for the ten rounds and 40 for the schedule, 200 in all. On the CPU
those 200 are covered by 20 `vaesenc`/`vaesenclast` instructions: the S-box is in
silicon, two candidates ride in each 256-bit register, and the whole candidate
costs ~15 cycles. On the GPU, which has no AES instruction, every one of the 200
becomes a table lookup plus the arithmetic to build its index.

Counted from the PTX the driver actually generated for the search kernel, per
candidate:

| | |
|---|---|
| `ld.shared` (T0 lookups) | **200** — exactly the 160 + 40 predicted |
| integer ALU ops (PTX) | 1438 |
| effective SASS ops at the measured rate | ~910 |

So the GPU issues ~910 integer instructions where the CPU issues ~20 AES
instructions and ~45 cheap vector ops. The RTX 3060's int32 peak is 28 SMs × 64
lanes × 1.84 GHz = 3.29 Tops/s, and 3.29e12 / 910 ≈ 3.6 G/s — which is what it
does. **The kernel is at its issue roof, not short of tuning.**

Three measurements say the limit is instruction issue and not memory or occupancy,
which is what makes this conclusion worth trusting rather than a plausible story:

* **Shared memory is at 44% of peak.** 200 lookups/candidate against 28 × 32 banks
  × 1.84 GHz = 1.65 T lookups/s is a ceiling of 8.2 G/s, more than twice what the
  kernel achieves.
* **Halving the table replication changed nothing.** 32 copies (32 KB, provably
  conflict-free) gave 3.618 G/s; 16 copies (16 KB, which doubles the work-groups
  an SM can hold but admits two-way bank conflicts) gave 3.580 G/s — under 1%. If
  either occupancy or conflicts were binding, that would have moved a lot. 8 copies
  does move it, to 3.283 G/s.
* **Grid size saturates.** Past ~8 work-groups per compute unit more work-items buy
  nothing.

### What would actually make it faster

See [*Where to get more speed*](#where-to-get-more-speed) below, which is the
consolidated table. The short of it: **fewer candidates beats faster hardware by a
factor of 64 to 12**, and nothing left inside this kernel is worth more than ~10%.

### Faster GPU AES implementations, and why they do not apply

* **The published GPU AES throughput figures are fixed-key.** Hundreds of Gbps for
  AES-CTR is a kernel whose round keys were expanded once and live in constant
  memory, doing 160 lookups per block. This problem has a *different key per
  candidate*, so the 40 schedule S-boxes are unavoidable. Even granting the
  fixed-key case for free it would be 200 → 160 lookups, worth ~+25%, not ~10×.
  This is the main reason published numbers do not transfer.
* **Bitslicing is worse here, and the reason is specific.** A Boyar-Peralta S-box
  is 113 gates for 32 lanes, ~3.5 ops per S-box, which is competitive for the 160
  round S-boxes. But the key schedule's `SubWord` is only **four** bytes wide,
  while the bitsliced circuit is sixteen bytes wide, so the schedule runs the
  circuit at quarter utilisation — ~14 ops per S-box, ~565 ops per candidate for
  the schedule alone. Total lands around 1340 ops against the T-table's ~910.
  Restructuring to bitslice sixteen candidates' schedules together needs a
  transpose between schedule and encryption layouts and was not pursued.
* **Computing the S-box arithmetically** (tower field, Canright) is ~60-100 ops
  against one lookup. No.
* **Tensor cores, DP4A** and the other special units do not do bitwise logic.

### Measured on the GPU and rejected

Costed against the 200 lookups and ~910 issued ops a candidate needs:

* **Hoisting round 1 out of the inner block.** The inner block varies only key
  bytes 0–3, so `w1..w3` are constant within it: `SubWord(RotWord(w3)) ^ Rcon1`
  becomes a per-outer-step constant (round-1 expansion drops to four XORs and no
  lookups), and round 1 of the encryption needs one variable lookup per column
  instead of four. Saves ~50 ALU ops and 16 lookups, ~7%. It needs a second kernel
  plus a host-side applicability check, and 49 h → 45.5 h changes no decision.
* **Storing T1 beside T0** to halve the twelve rotates per round. Both tables at 16
  copies fit the 32 KB budget; saves ~36 ops but pays the two-way bank conflicts
  measured above. ~+4% net.
* **Four tables at 8 copies**, removing rotates entirely: +14% of ops but −9% from
  conflicts. ~+5%, and the messiest of the three.

Two changes *were* taken, because they were free:

* **Byte 2 of `T0[x]` is `S(x)`**, exactly like byte 1, so the byte-2 position in
  the last round and in `SubWord` costs a mask and no shift. Worth ~3%.
* **The replication factor is a build define**, so a device with less local memory
  degrades instead of failing.

## Where to get more speed

The come-back-later summary. Everything below is scaled from one measured point —
3.62 G/s on an RTX 3060, costing **909 int32 issue slots per candidate** — using the
fact that the kernel is ALU-bound with shared memory at 44% of peak, so rate ≈
(int32 issue rate) / 909 until the lookup path catches up.

| option | rate | 2⁵⁰ | cost to get there | confidence |
|---|---|---|---|---|
| ten CPU cores, as measured | 3.16 G/s | 99 h | — | measured |
| + RTX 3060, as measured | **6.35 G/s** | **49 h** | done | measured |
| the two rejected kernel tweaks | ~7 G/s | 44 h | a second kernel and a fallback path | costed, §*rejected* |
| + RTX 4090 instead | ~23 G/s | 14 h | a purchase | scaled |
| + RTX 5090 instead | 29–50 G/s | 6–11 h | a purchase | scaled, one open question |
| Kintex UltraScale KU095 | 10–14 G/s | 23–39 h | weeks of HDL and timing closure | estimated |
| **§2.1 matched filter: 2⁵⁰ → 2⁴⁴** | unchanged | **46 min** | ~5 h of bench time | analysed, not measured |

**The last row is the answer.** A factor of 64 for bench hours beats a factor of 12
for hardware money, and it is already built and synthetic-validated — see
[`../MATCHED_FILTER_K15.md`](../MATCHED_FILTER_K15.md). Everything else on this list
is insurance for the case where `k[15]` stays unreachable.

### GPUs

Linear in SMs × clock, because there is no memory wall to hit. The open question on
Blackwell is whether all 128 unified cores per SM execute INT32 at full rate or only
half do as on Ampere and Ada — worth exactly 2× on the 5090 row, and not a detail to
take on trust:

| card | SMs | GHz | int32/SM | int32 peak | ALU limit | lookup limit |
|---|---|---|---|---|---|---|
| RTX 3060 *(measured)* | 28 | 1.84 | 64 | 3.3 T | **3.6 G/s** | 8.2 G/s |
| RTX 4090 | 128 | 2.52 | 64 | 20.6 T | ~23 G/s | 52 G/s |
| RTX 5090, if 64 int/SM | 170 | 2.41 | 64 | 26.2 T | ~29 G/s | 66 G/s |
| RTX 5090, if 128 int/SM | 170 | 2.41 | 128 | 52.4 T | ~58 G/s | 66 G/s |

In the bottom row the lookup path is at 88% of theoretical, which real code does not
reach, so both units would saturate together and the honest figure is nearer 45-50
G/s. **This is cheap to settle rather than argue about**: `--vector medium-2^34
--gpu-only` runs in seconds and prints the card's own rate.

Two things change at 5090 speeds: raise `--gpu-batch` to 2³² (a 2³⁰ batch becomes a
27 ms launch), and host-side `kbase` generation becomes ~30% of one core — still not
binding, no longer free.

### FPGA — a Kintex UltraScale KU095

**~10-14 Gcandidate/s, so 2⁵⁰ in roughly 23-39 hours.** About 3.4× the RTX 3060 and
about a quarter of an optimistic 5090, for weeks of HDL instead of a purchase order.
Its real advantage is perf/W — an order of magnitude — which matters for a rack and
not for one search.

Taking the device as ~537 600 LUT6, ~1.07 M flip-flops and 60.8 Mb of block RAM, and
70% as the fraction that actually closes timing at high replication:

| core style | LUT6/core | cores | clock | rate | 2⁵⁰ |
|---|---|---|---|---|---|
| iterative, 1 round/cycle, 11 cycles/candidate | ~1 500 | 251 | 400 MHz | 9.1 G/s | 34 h |
| **fully unrolled, 1 candidate/cycle** | ~13 650 | 27 | 450 MHz | **12.2 G/s** | 26 h |

The unrolled pipeline wins on LUT-efficiency — 33 vs 24 Kcandidate/s per LUT — because
it has no control overhead and every stage works every cycle. Flip-flops are not
binding (6% used). Budget per unrolled core: nine rounds of 16 LUT-ROM S-boxes plus
MixColumns, a tenth round without MixColumns, the key schedule unrolled alongside at
four S-boxes per round, eleven AddRoundKeys, and a comparator.

Three things worth knowing before committing to it:

* **On-the-fly key expansion is mandatory, so the published AES core numbers are the
  wrong ones.** The 30-70 Gbps figures in the literature are overwhelmingly
  *fixed-key* — round keys precomputed and held in registers — exactly the same
  mismatch that makes published GPU AES numbers inapplicable. Expanding the key per
  candidate costs ~2 560 LUT6 of the ~13 650 above.
* **Block RAM is not the way to hold the S-boxes.** A 1-candidate/cycle pipeline needs
  160 S-box reads per cycle; a 36 Kb BRAM gives two, so 80 BRAMs per core caps the
  device at 21 cores against 27 from LUT ROMs — and a 2 Kb table in a 36 Kb block is
  mostly waste. BRAM is a supplement worth perhaps +30% if mixed in, not a
  replacement.
* **The system architecture is the well-trodden part, not the core.** COPACOBANA
  (2006, 120 × Spartan-3) and its successor RIVYERA are the canonical FPGA
  brute-force machines — DES and A5/1 rather than AES — and their shape is exactly
  this problem's: N independent key-testing cores, a host dispensing key ranges, a
  thin hit-report path back. This program's work dispenser is already that shape, so
  an FPGA would attach where the GPU worker does.

**There is no "approximate" version of this core, and that is worth saying plainly.**
Approximate computing trades exactness for area, and AES is bitwise exact — an
approximate S-box does not find the key more cheaply, it fails to find it. The one
legitimate approximation, truncating the 128-bit compare to 32 bits and re-checking
the 2⁻³² survivors on the host, saves ~64 LUT6 of ~13 650: under half a percent. The
trick that *is* worth taking is the one the CPU and GPU kernels already use —
pre-XOR the expected keystream into round key 10 so the comparator tests against
zero.

### Not available

* **AVX-512 VAES** would be a straight 2× on the CPU side. Raptor Lake has it fused
  off.
* **An AES instruction on the GPU.** No GPU has one; this is the whole reason the
  card is only worth 1.15× ten CPU cores.

## How it works

### Enumerating

The free fields are the anchor's top six bits (64), two bits per byte in
`unknown_low2_bytes`, and eight bits per byte in `unreached_bytes`. A candidate key
is then

```
key = kbase(anchor_top6)  OR  free-bit pattern
```

where `kbase` carries every bit that is *not* enumerated (including the
`known_low2` bits the file pins) and holds zero wherever a free bit lands, so the
two parts compose with a plain OR.

Fields are ordered by byte index, and the lowest few — enough for ~16k candidates —
become the **inner block**, precomputed once into a table of OR-masks. The rest,
plus `anchor_top6`, form the **outer index**, which is what gets handed to workers.
For `full-2^44` the inner block is bytes 0–3 (256 × 4 × 4 × 4 = 16 384) and there
are 2³⁰ outer steps; for `real-2^50` the same inner block and 2³⁶ outer steps.

Any number of unreached bytes works; each simply contributes a radix-256 field. The
loader rejects a file where a byte is not accounted for exactly once across
`unknown_low2_bytes`, `known_low2` and `unreached_bytes`.

### The CPU hot loop

Unchanged. Per candidate: a fresh AES-128 key schedule and one block encryption,
both on the AES units.

* **`SubWord(RotWord(w3)) ^ Rcon`** is `vpshufb` followed by `vaesenclast(.., rcon)`.
  ShiftRows is the identity on a register whose four columns are equal, so
  `aesenclast` degenerates to `SubBytes ^ roundkey` — exactly SubWord. This avoids
  `AESKEYGENASSIST`, which on Intel has ~12 cycles of reciprocal throughput.
* **The prefix XOR** `w4..w7` is two byte-shifts and two XORs.
* **The last round** takes `rk10 ^ expected_keystream` as its round key, so the
  result is already `ciphertext ^ expected`, and a candidate matches iff it is zero.
* **Rejection** folds those differences over a group of 48 vectors with an unsigned
  byte-wise `MIN` and tests the group once. A spurious trip is about 2⁻⁴¹ and costs
  only a re-scan with the reference AES, so the fast path may be approximate while
  the answer stays exact.

### The GPU kernel

[`src/aes_kernel.cl`](src/aes_kernel.cl). A T-table AES, with two things worth
knowing:

* **The table is replicated once per bank.** `T[i * 32 + lane] = T0[i]` gives lane
  `l` its own copy and makes it land in bank `l` whatever it looks up, so the
  lookups are conflict-free by construction rather than by luck. It costs 32 KB of
  local memory, and the index macros carry a pre-scaled `<< 5` so a lookup is one
  shift and one mask rather than a shift, a mask and a scale.
* **The compare is exact and full-width**, unlike the CPU's group rejection. It
  costs a handful of ops out of ~910, and it means a reported hit is a real 128-bit
  match with no approximate fast path to get wrong.

One table serves everything: `T1/T2/T3` are rotates of `T0`, and `S(x)` alone —
which the last round and the key schedule need — is bytes 1 and 2 of `T0[x]`.

Only the first oracle pair is tested on either device. Every candidate that
survives is re-checked against **all** pairs with the reference AES on the host,
and all hits are reported, not the first.

## Long runs

`--checkpoint` records the scan's progress; `--resume` picks it up.

The recorded watermark is the end of the **contiguous** prefix of completed chunks,
not the work cursor. Chunks finish out of order, so resuming from the cursor would
skip whatever was in flight when the process died; chunks handed out but unfinished
are simply redone. The file carries a fingerprint over everything that defines the
search — anchor, `diff6`, `known_low2`, the field list, the oracle, the layout, but
not the name and not `answer_key_hex` — and a resume against a different problem is
refused by name rather than silently producing a wrong answer.

A GPU error does **not** skip its chunk: the run aborts and says so, because a
driver failure that quietly dropped a range would turn into "no key found".

## Correctness

`--selftest` runs, and `--all` includes:

1. **FIPS-197 C.1** on the reference AES, before anything else. The program refuses
   to search if it fails.
2. **`aes_core_check`** from the constraint file.
3. **The format vector**: `AES128_ECB(cred_key, counter_block_A1)` checked against
   both `keystream_block_1_hex` and `credential_id[0:16] XOR plaintext[0:16]`, so
   §4's derivation is re-verified against the hardware-accepted credential id.
4. **Randomised kernel-vs-reference searches**: a random key, a random anchor, one
   or two unreached bytes and a random set of low-2 fields; the real search must
   return exactly that key, exactly once.
5. **A position sweep**: the answer is planted at 56 inner-block positions — group
   and lane boundaries plus random ones — and must be found at every one.
6. **The GPU's AES against the reference**, on FIPS-197 C.1 and 500-odd random
   blocks, *before* any GPU searching. This matters more than it looks: the search
   kernel's compare is exact, so a wrong AES on the device would not produce wrong
   hits — it would produce **no** hits, and the run would report a clean zero.
7. **The GPU finding a planted answer** at inner-block boundaries and random
   positions, in the `real-2^50` shape (byte 0 and byte 15 both unreached), with
   the CPU threads switched off so the GPU must be the one that finds it.
8. Each vector's `answer_key_hex` is checked to be *reachable* from its own
   constraints before searching, and the computed space size is checked against
   `search_space_bits`.

4, 5 and 8 pass under `--backend vaes`, `--backend aesni` and `--backend scalar`.

`answer_key_hex` is never read on the search path.

## Input files this accepts

Two shapes, because a real constraint file is not a test vector:

* a **bundle**, `{"vectors": [...]}`, as [`../search_vectors.json`](../search_vectors.json) ships;
* a **bare problem**, a single object with `anchor_byte` and the rest at top level,
  which is what [`../constraints_from_campaign.py`](../constraints_from_campaign.py)
  emits and what a measured file looks like. It has no `answer_key_hex` and the
  program does not need one.

A file whose space does not fit in a `u64` is reported and refused in about a
second rather than started:

```
=== constraints_measured ===
  space   : 2^110  = 1298074214633706907132624082305024 candidates
  VERDICT : not searchable. 12 byte(s) unreached ([0, 1, 2, 6, 7, 8, 9, 11, 12, 13, 14, 15]),
            each costing 2^6, so the space is 2^110.
            That is 2^60 times `real-2^50`, the largest size this search is built for.
            This file needs more ladder relations, not more compute.
```

That is a verdict, not a failure, and the exit status says so.

## Problems found

**In the inputs.**

* **`known_low2` was missing** from the first version of the constraint file, which
  made `tiny`, `small` and `medium` unsolvable without reading `answer_key_hex`.
  Reported; the generator now emits it and asserts that every byte index appears in
  exactly one of the three sets. The loader checks that property too and fails with
  the offending indices rather than guessing.
* **A real constraint file could not be loaded at all.** The loader required a
  `vectors` array, and [`../constraints_measured.json`](../constraints_measured.json)
  is a bare problem — so requirement 6 of the brief was blocked on the file format
  before any search ran.
* **The default `--vectors` path was stale.** It pointed at `req/search_vectors.json`,
  a directory that no longer exists; the files are one level up.

**In this program.**

* **An accumulator that was silently doing nothing.** The first version of the CPU
  rejection step AND-accumulated the differences instead of taking a byte-wise
  minimum. ANDing 32 unrelated values leaves zero almost surely, so *every* group
  was flagged and re-scanned and the whole search quietly ran at the speed of the
  scalar reference — 60× slow. It still returned the right key on every vector,
  which is exactly why it was worth catching: the only symptom was the throughput
  number.
* **Hits were not published until a worker exited.** Each worker accumulated hits in
  a thread-local vector and only merged them at the end of its loop, so a hit found
  at hour 3 of a 49-hour run was in no checkpoint. Kill the machine at hour 40 and
  the key was gone, with the resume watermark already past it — and the resumed run
  would have reported a clean zero hits. Found by seeding a `real-2^50` checkpoint
  below the answer and watching the watermark pass it with nothing recorded. Hits
  are now merged into the shared list before the chunk that contains them is marked
  done, which is the ordering that makes the checkpoint safe.
* **`--all` excluded the long vector by name.** It skipped `full-2^44` by matching
  its name, so adding `real-2^50` to the file silently made the default action a
  49-hour run. It now skips by declared size.
* **`stage_table` hard-coded the replication shift.** Any factor but 32 staged the
  table wrong and every answer was wrong. Caught on the first run by the
  known-answer test, which is the argument for having run it before the benchmark.
* **`build.ps1` printed "built" over a failed compile.** `$ErrorActionPreference`
  does not apply to a native exit code, so a `rustc` failure left the previous
  binary in place under a success message. It now checks `$LASTEXITCODE`.
