# flashleak - is this black-box target leaking?

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

A leakage detector for someone who knows almost nothing about the target:
bytes go in or out of something doing crypto, and that's all. Not the mode,
not whether the bytes are plaintext or ciphertext, not whether the device
encrypts or decrypts, not the implementation. Every question gets answered
by a test whose *outcome differs* between the possible answers.

It's deliberately separate from [`../flashattack/`](../flashattack), which
is the key-recovery engine and assumes you already know all of that.
flashleak borrows two things from it, the AES tables and the 2^16 pair
search, and nothing else, so it's easy to lift out.

```bash
python -m flashleak analyse capture.npz          # recorded blocks + timings
python -m flashleak probe  mymod:MyTarget()      # drive a live device
python -m flashleak fwscan firmware.bin          # static triage before any hardware
python -m flashleak placement firmware.bin --part f4   # ... and will the tables be in FLASH?
python -m flashleak selftest                     # check it against known truth
```

## Before the hardware: `fwscan`

Cheapest question first, which is whether this target is even in scope.
Given a firmware image (a vendor's download, or a dump), `fwscan` reports
whether the head parses as a Cortex-M vector table, so it executes in place
from flash rather than being a Linux image running from SDRAM, and then
which AES table layout is present:

| what it finds | what it means |
|---|---|
| four T-tables (`Te0..Te3`) | round 2 resists; the last round still falls |
| one T-table + S-box | leaks, and is round-2 recoverable from one side |
| decryption T-tables (`Td0..Td3`) | 1 KB+ of inverse tables, which exceeds the F2/F4 128 B and the G4/L4 256 B cache, so it leaks on every measured band. A bootloader is often decrypt-only and carries `Td` with no `Te` at all |
| Gladman `sbox`+`gfm2_sb`+`gfm3_sb` | the LoRaMac-node `soft-se` layout, broken here at 16/16 |
| byte S-box only | leaks wherever the data cache is smaller than 256 B, and also where there is no data cache at all if the part has a flash read latch: a G474 with the whole accelerator disabled still gives up the full key. Cache size is necessary, not sufficient (see `../research/targets/stm32g474_art_geometry.md`) |
| nothing | constant-time/bitsliced, or tables built into RAM, so not exposed |

It's checked against the four firmware builds in `rigs/fw_f4_lib/` whose
keys were actually recovered on the F429, so the layouts it reports are
known truth rather than a guess (`tests/test_fwscan.py`).

## The question `fwscan` cannot answer: `placement`

`fwscan` reports a property of the LIBRARY. Every break in this repo rests
on a property of the BUILD: the tables are read *from flash*. ST's own
X-CUBE-CRYPTOLIB, the same vendor binary, one linker line apart, is either
a full AES-128 key in 20 000 timings or `sd = 0.00` and 0/16. `fwscan`
prints word-for-word identical verdicts for those two images, correctly -
same tables, same shapes - and its `@` column prints the table's *load*
address, so on the fixed build it reports a table "in flash" that lives in
SRAM. `placement` is the module that separates them.

```bash
python -m flashleak placement fw.elf --part g4          # exact: from section headers
python -m flashleak placement fw.bin --part f4          # inferred: copy loop + literal pool
python -m flashleak placement fw.hex --part l0          # same, with the base from the records
python -m flashleak placement lib.a --ld project.ld     # conditional: + check the rule
python -m flashleak placement x --list-parts            # the memory maps it uses
python -m flashleak placement build/ --part g4 --fail-on exposed --json p.json   # CI gate
```

| artefact | verdict | how |
|---|---|---|
| linked `.elf` | exact | `sh_addr` is the *run-time* address, even for `.data` |
| raw `.bin` | inferred | the start-up copy loop `(src,dst,len)`, the PC-relative literal pool, group relocation, and `LDRB.W` anchors |
| `.o` / `.a` | conditional | the section name says which linker rule is required; `--ld` checks a script for it |

Verdicts are `EXPOSED` / `SAFE` / `CACHED_RAM` / `CONDITIONAL` /
`UNDETERMINED` / `NO-TABLES`. `CACHED_RAM` exists because "not flash" is
not "safe": on an H7, `0x2000_0000` is DTCM and `0x2400_0000` is cached
AXI-SRAM, and on an F7 the DTCM/SRAM1 boundary moves *within the family*.
Without `--part` the tool returns `UNDETERMINED` for anything in the SRAM
region rather than guessing.

`--fail-on exposed` turns it from a report into a build gate: it exits
non-zero for a build whose tables resolve to flash, and for an archive
whose supplied linker script doesn't place the section it asks for, which
is the check that 2 277 of ST's own scripts would fail.

Scored over 38 artefacts, most with leak/no-leak status measured on real
silicon: 25 TP / 0 FP / 13 TN / 0 FN, from the `.elf` and from the raw
`.bin` alike. Full method, the failure modes found along the way, the
exploitability confusion matrix (18/5/4/0) and what static analysis can
never see:
[`flashwhisperer/docs/STATIC_ANALYSIS.md`](../docs/STATIC_ANALYSIS.md).

## The question neither can answer for a NEW algorithm: `codescan`

`fwscan` and `placement` both start by recognising a table's *bytes*.
That's the right design for AES and it's checked against builds whose keys
came out on silicon, but it means a table nobody has a signature for is
invisible. Three cases in a row went past it, all in
[`research/exposure/PQC_SURVEY.md`](../../research/exposure/PQC_SURVEY.md):
SQIsign keeps its precomputed data in `const` structs, QR-UOV's
modular-inverse table is a non-`const` array, and `rigs/fw_f401_ct` reads
its S-box through a pointer. On the two QR-UOV builds that differ by one
`const` keyword - one table in RAM, one in flash - `placement` prints
word-for-word identical `NO-TABLES` verdicts.

`codescan` asks the other question: a table lookup has a *shape* in the
instruction stream whatever the table holds.

```
LDR   r3, [pc, #N]       ; or MOVW/MOVT - materialise a base
LDRB  r0, [r3, r0]       ; register-offset load from that base
```

A register-offset load whose base resolves into a flash region is a table
read, and it doesn't matter whether the table holds an S-box, GF(16)
products or discrete-Gaussian weights.

```bash
python -m flashleak codescan fw.elf --part f4           # names the table from the symtab
python -m flashleak codescan fw.bin --part l1 --base 0x08000000
python -m flashleak codescan fw.elf --part g4 --fail-on exposed
python -m flashleak codescan x --selftest
```

On the QR-UOV pair it separates them, knowing nothing about QR-UOV:

| build | verdict | base |
|---|---|---|
| as shipped (no `const`) | `SAFE` | `0x20000000` `SRAM1/2 [.data] Fq_inv_table` |
| with `const` added | `EXPOSED` | `0x0800000c` `flash (AXI/ART) [.rodata] Fq_inv_table` |

`--selftest` is a cross-check and not a fixture. It requires `codescan` to
find every base `placement` reports on the in-tree builds whose keys were
recovered on the F429: two independent finders, one answer. It passes on
all four, and `codescan` returns a superset - `fw.elf` yields `sbox`,
`gfm2_sbox` and `gfm3_sbox` by name, plus the firmware's hex-digit table.

Two things to know before trusting a run. It finds a table *read*, not a
*secret-dependent* table read: the index register's provenance isn't
traced, so a hit is a candidate, and jump tables, font data and character
classes will appear. And `--window` is calibrated rather than arbitrary -
at 64 bytes it misses two of `fw.elf`'s three tables, and past the default
it starts attributing stale register values and inventing unmapped bases.
The module docstring lists the rest of what it doesn't cover.

## The two situations

Observation only: you can see data and times but can't control anything. A
bus you're sniffing, a protocol you're watching.

```python
from flashleak import assess, render
print(render(assess(blocks, timing)))            # blocks (n,16) uint8, timing (n,)
```

Controlled input: you can send data and time the response. The bootloader
case, where you write a block and wait for the ACK or the next-packet
prompt.

```python
from flashleak import determinism, fixed_vs_random, collect, assess, render

class MyBootloader:
    def measure(self, data: bytes) -> float | None:
        self.port.write(b"\x01" + data)
        t0 = time.perf_counter_ns()
        ok = self.port.read(1)                   # whatever means "ready"
        return (time.perf_counter_ns() - t0) if ok else None

tgt = MyBootloader()
print(determinism(tgt))                          # will averaging help?
print(fixed_vs_random(tgt))                      # model-free: leaking at all?
blocks, t = collect(tgt, 100_000, repeats=3)
print(render(assess(blocks, t)))
```

`measure` is the entire interface. Return anything monotonic in elapsed
time.

Start with `fixed_vs_random`. It assumes nothing about the cipher, it's the
most sensitive thing here, and it answers "is this target leaking" before
any modelling. The rest tells you *what* the leak is and what it would
cost.

## What it can tell you, and how

| question | how it is decided |
|---|---|
| is the timing data-dependent? | 16x256 byte-value means vs a shuffled null; and fixed-vs-random if you have control |
| which side of the cipher am I observing? | see below, this is the interesting one |
| encryption or decryption? | which of the two output-side predictors (inverse S-box / forward S-box) fires |
| table layout | which byte offsets carry signal: all of them = one shared table; only offsets 0 mod 4 = four separate tables; one family = a restricted access order |
| effective line granularity | an UPPER bound only, and biased coarse, see the caveat below |
| the row width the output side is scored at | scanned over 2/4/8/16 table entries per flash row, each against its own shuffled floor, and the winner reported |
| how many traces to be sure | excess over the shuffled floor grows as sqrt(n) |

### Input side vs output side

The collision channel is visible from either side but means different
things:

* output, where the block is the result of a final round with no
  MixColumns. The key enters *after* the lookup, behind an S-box, so
  collisions are nonlinear in it and absolute key bytes fall out. This is
  the position that yields a key on its own.
* input, where the index is `block ^ key`, key *before* the lookup and
  linear, so a collision only ever reveals `k[a] ^ k[b]` at line
  granularity.

Telling them apart isn't trivial, since neither naive test is specific. The
input-side test responds to output-side leakage too (along a fixed-XOR
diagonal the S-box doesn't spread collisions evenly), and the output-side
2^16 search can find a partition that partly overlaps input-side leakage.
What does separate them is *concentration*: input-side leakage is a
function of `B[a] ^ B[b]` alone, so exactly one bucket is fast and stands
well clear, and anything else smears across buckets.

Two statistics are needed, not one. The median over all 120 pairs
identifies an input side when every pair can collide, but reads ~0 when the
layout PARTITIONS the channel: in a 4-table implementation only 24 pairs
can collide and the other 96 drown them. The best-offset-family statistic
rescues that case, but partitioning raises it on *either* side, so it needs
a higher bar.

| capture | truth | pooled | family |
|---|---|---:|---:|
| tiny-AES decrypt, observed ciphertext | input | 2.78 | 3.39 |
| mbedTLS compact decrypt, observed ct | input | 7.73 | 8.93 |
| mbedTLS 4-table decrypt, observed ct | input | 0.56 | 10.05 |
| SNMPv3 CFB keystream | output | 0.38 | 0.53 |
| simulated single-table, observe input | input | 10.45 | 11.34 |
| simulated 4-table, observe input | input | 0.56 | 24.92 |
| simulated single-table, observe output | output | 0.50 | 0.85 |
| simulated 4-table, observe output | output | 0.45 | 2.11 |

Input-side is called if either bar is cleared (pooled ≥ 1.0, family ≥ 5.0).
The narrow case is a partitioned layout seen from the output side (2.11)
against a partitioned input-side capture (10.05), about 5x, where
unpartitioned cases separate by 20x. A 4-table call is the least certain
thing this tool says.

The 4-table row was a hold-out: it set neither threshold, and the first
version of this rule got it wrong. Calibration uses only captures with no
runtime `FLASH_ACR` change.

When neither identifies the side, the tool says UNDETERMINED rather than
guessing. An early version fell through to an "input" verdict whenever the
cheap test fired, which produced a confidently wrong headline on
output-side targets.

### The granularity figure is an upper bound

`assess` reports the width at which the XOR bucketing concentrates most,
and that's biased toward coarse widths because wider buckets hold more
traces and dip harder. On the tiny-AES decrypt capture it peaks at 16
bytes, while the round-1 difference sweep - which asks whether the
recovered *differences* are correct at each assumed width - resolves 4
bytes on the same data. The difference matters, because the round-1
residual is `16*shift + (8-shift)` bits: 2^38 at 4 bytes against 2^68 at
16.

Use this figure to bound the answer, then get the real one by sweeping
`line_shift` against recovered differences
([`research/round2/round2_decrypt.py`](../../research/round2/round2_decrypt.py)).

## Mode does not matter for detection (mostly)

A fixed unknown XOR mask on the observed data doesn't hide the output side:
for a guess `g`, `tbl[B[j] ^ g]` with `B = out ^ m` is `tbl[out ^ (m ^ g)]`,
so the mask is absorbed into the recovered bytes. A CTR keystream, a raw
ciphertext and a ciphertext XOR some constant header therefore all look
alike, which is why you don't need to know the mode to detect the channel.

What *does* break it is a mask that VARIES per block and is unknown, which
is exactly CBC decryption seen as plaintext only. If you have both sides,
XOR them back together first:

```python
from flashleak import combine_cbc
raw = combine_cbc(plaintexts, ciphertexts)   # ciphertexts includes the IV
```

## Reading a negative honestly

Three ways this tool can say "nothing" about a target that is in fact
broken:

1. Not enough traces. The key-free tests are strictly weaker than a
   key-known attack on the same data. This repo's own SNMPv3 capture yields
   a full key at 100 k traces, and flashleak rates it only *suggestive* at
   250 k. That's expected, since a detector that doesn't know the key is
   searching rather than confirming. Its trace estimate is an UPPER bound
   on an attacker's cost.
2. Unconditioned timing. Raw round trips carry outliers and discrete
   transport modes. On that same SNMPv3 capture, raw sigma is 8.6 million
   and every test reads zero; conditioned it is 108 and the data-dependence
   z goes from +0.1 to +522. `assess` conditions automatically and says
   what it did, but if your measurement has structure it can't model, look
   at that first.
3. A flat model-free result. Cache-collision leakage lives in *pairs* of
   bytes and is normally invisible to any single-byte test. A clean
   `data_dependence` means very little on its own.

The tool tries to say all of this in the report rather than leaving it
here.

## Self-test

`python -m flashleak selftest` runs the detector against simulated targets
whose answers are known, including two negative controls. The simulator is
the part worth trusting or not:

* it leaks from every round, as a real cipher does. A one-round simulator
  reads ~6 on the concentration statistic where hardware reads ~1.4, and
  would have put the threshold about four times too high.
* its decryption walks a real InvCipher, verified against `aesref`. Walking
  the encryption from the plaintext instead, which is the obvious shortcut,
  makes the simulated decryption's first round linear in the observed
  block: it looks input-side when it is not.

Both of those were bugs here first, found because the selftest disagreed
with hardware. If you extend the simulator, keep the selftest honest the
same way.

### What it took to get it to 6/6

It reported 3/6 for a long time, missing every output-side case while both
negative controls passed, and the three causes are worth knowing because
two of them were costing real captures as well.

The row width was a constant. `assess` scored the output side at a
hardcoded 2 for any capture that was not input-side, while the simulator
models a 16-byte row of 1-byte entries, which is 4. At 20 000 traces that
turned +7.9 and +56.4 over the floor into +0.7 and +7.0 - a clean null
that reads exactly like a target which does not leak, which is the trap
this project warns about everywhere else. The width is now scanned, each
candidate against its own shuffled floor, and the chosen one is reported
in the notes.

Conditioning invented modes. The mode finder took any histogram valley,
and the tails of a plain Gaussian go sparse before they end: 20 000
samples of clean N(1000, 3), no cipher involved, came out as three modes
of 3.0 % / 94.4 % / 2.6 %. Each sliver then had its own median subtracted,
which is signal removal when the thing being measured is a shift in a
subset's mean. On the real 250 000-trace `tinyaes` vector it found NINE
modes and cost 60 % of the output-side statistic - 39.5 down to 14.5
against the same floor. An edge now has to clear a share and a separation
test, which the SNMPv3 capture's real modes (~1480 apart, within-mode
sigma ~59, so ~25 sigma) do easily.

The selftest was under-powered. It ran at 20 000 traces, where the
"encrypt, observe ciphertext" case reads +0.19 over its floor; at 50 000
it reads +40. The default is now 50 000. Note the pytest suite had been
exercising the same cases at 60 000 and 150 000 all along, which is why it
stayed green while the CLI did not.

**NOTE:** scanning the width is not free. Keeping the best of four widths
inflates the statistic under the null, so both bars had to be re-measured
rather than inherited: 20 draws of pure Gaussian noise, no cipher in them,
scanned and scored through the identical call, read mean +0.29, sd 1.66,
**max +3.72**. The old firing bar was 4.0, which that nearly clears, and
the old "suggestive" bar was 1.5, which noise cleared about half the time.
They are now 6.0 and 4.0, named and documented in
[`hypotheses.py`](hypotheses.py). A pilot of only 8 draws had put the null
max at +2.16 and would have left the firing bar alone, which is worth
remembering next time a threshold is set from a handful of runs.

The cost is real and worth stating: the band a fixed-width rule would have
hedged now reads "none detected". This detector is the weaker instrument
either way, so read a quiet result as "not at this trace count", never as
"safe".

## Files

| file | what |
|---|---|
| `probe.py` | the statistics: conditioning, data-dependence, the two pair tests, the shuffled floor |
| `hypotheses.py` | turning statistics into statements; the input/output discriminator and its calibration |
| `target.py` | the `Target` interface, the simulator, fixed-vs-random, determinism, a serial example |
| `report.py` | rendering |
| `cli.py` | `analyse` / `probe` / `selftest` |
