# flashattack

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Target-agnostic toolkit for the flash-accelerator AES timing side channel.
The exploitation engine doesn't depend on any board or firmware - those
live under [`../hardware/`](../../hardware) and may move to another
project. This package is the part worth keeping and generalising.

## Layout
```
flashattack/
  aesref.py      reference AES-128/192/256 (enc/dec, key-schedule + inversion), FIPS-197 verified
  sm4.py         SM4 (GM/T 0002) reference + partial leak (Feistel -> top-nibble only; see EXPERIMENTAL.md)
  EXPERIMENTAL.md  partial results & their structural ceilings (SM4, ARIA/Camellia)
  ROUND2.md        round-2 collisions: full key from ONE side of the cipher
  bruteforce.py  batched multi-key AES: 2^24 candidate keys in ~26 s (finishes an uneven vote)
  search.py      ranked candidates from a score surface + a best-first walk -> (traces, candidate keys)
  engine.py      unified last-round cache-collision engine + robust assembler; recover_full (192/256)
  lastround.py   THE scoring rule: surface, row geometry, fast path + its selftest, pair coverage
  geometry.py    where the table starts inside the flash row, and why a wrong value costs 2x-10x
  round2.py      round-2 collision primitives (both directions) - the attack ROUND2.md documents
  oracle.py      conditioning a NETWORK round-trip time: fit the transport artefact, subtract per mode
  modes.py       AES mode -> block the attacker reconstructs (ECB/CBC/CTR/GCM/CMAC, enc+dec)
  capture.py     Capture: target-agnostic OBSERVED data (pt/ct + timing, NO key); save/load npz, from_csv
  sources.py     TraceSource interface (Recorded/Array/SerialModes) - the extension point for agents
  attack.py      attack(capture, verify=...) -> AttackReport (JSON/summary); unknown-key entry point
  tvla.py        quick check: constant-time detector, key-free exploitability, fixed-vs-random t-test
  stats.py       jitter-robust preprocessing: trim, detrend (drift), min-filter
  transport.py   serial target + timing sources (on-chip batch; host ACK-latency w/ amplify+min-filter)
  feasibility.py trace-count estimate + amplification (K) advice from a pilot capture
  boards.py      board descriptors (L552/G474/F429/F303): part, VCP, cache size, ACR presets
  cli.py         `python -m flashattack {selftest,attack,boot,feasibility,assess,attack-file}`
```

## Working with recorded data, or any interface (no key needed)
The engine consumes a `Capture`: observed data plus timing, no key. Build
one from a file, from arrays, or from your own interface, and attack it:
```python
from flashattack import Capture, run_attack
cap = Capture(timing=t, mode="ctr", plaintext=pt, ciphertext=ct)   # observed; no key
report = run_attack(cap, verify=(known_pt, known_ct))              # key used only to verify
print(report.summary()); print(report.to_json())
```
To add a new hardware interface or data format, implement one method
(`sources.TraceSource.capture() -> Capture`) and nothing else in the tool
changes. CLI on recorded files:
`attack-file --file cap.npz [--verify-pt .. --verify-ct ..] [--json]`.

## Quick vulnerability check, before committing to full recovery
```bash
python -m flashattack assess --file cap.npz        # constant-time? exploitable? ~traces-to-break
```
`tvla.assess` returns a constant-time verdict (std≈0) and, if
data-dependent, a key-free collision-margin strength estimate. A
first-order/Bernstein test is flat for this channel, so the check measures
the *pairwise collision* the attack actually uses.

## Engine

```python
from flashattack import engine, modes, aesref
known, direction = modes.known_output("ctr", material, key)   # material = per-trace input bytes
res = engine.recover(known, timing, direction=direction, keysize=128,
                     verify=(pt, ct))          # optional known PT/CT enables verify+brute-force
print(res.summary())                            # -> master key, verified True/False
```

`recover` scans all 120 output-byte pairs (layout-agnostic: S-box or
T-table), assembles each key byte by a margin-weighted vote across the 15
pairs that touch it, then, if a known plaintext/ciphertext pair is given,
verifies the key and brute-forces the low-confidence bytes - the full
0..255 over the positions whose confidence gap flags them - until it
matches. That turns near-misses like 13/16 or 15/16 into exact recovery.

Two parameters the engine didn't used to have, and both are worth traces.

`line_off=` is where the table starts inside the flash row, in table
ENTRIES: a byte S-box at `0x...cc` is 12, a 4-byte T-table 12 bytes in is
3. It's a per-IMAGE property, so it travels on the `Capture`
(`line_off_last`/`_prev`), is read off a firmware image by
`flashleak.row_offset_from_image`, and can be swept over
`geometry.candidate_row_offsets()` keeping whichever verifies. Measured on
captures with a known key, getting it (and the row width) right is worth
2x to 10x in traces: see `results/stm32f4/rescore_rowoffset.py`, and a row
of `research/FINDINGS_LEDGER.md` section D.

`pairs=` is the coverage: `"all"` (the 120, the default), `"intra-column"`
(the 24 pairs that are two reads of one state column, which is what every
archived `hardware/atk_lastround.py` trace count was measured with), or a
row-pairing name such as `"r1r2"`. A wider vote is NOT automatically
better: where the leak is concentrated in one adjacent-read pair set, 104
noise pairs cost more than the coverage buys, and `leaking_offsets` is how
to choose without the key.

- `direction="enc"` (attacker knows the ciphertext / keystream block) ->
  recovers the last round key -> master via schedule inversion.
- `direction="dec"` (firmware image case; attacker knows the InvCipher
  output) -> recovers the first round key, which for AES-128 IS the master
  key.
- `keysize` 128 / 192 / 256 all work end to end on unmodified firmware.
  For 192/256, `engine.recover_full` also recovers the second-to-last round
  key via a MixColumns-linearity reduction (byte-wise, same traces) and
  inverts the schedule to the master:
  ```python
  r = engine.recover_full(ct, timing, keysize=256, line_shift_last=4,
                          line_shift_prev=2, verify=(pt, ct_known))
  print(r["master"], r["verified"])
  ```
  `line_shift_prev` = the round Nr-1 table granularity (2 = 4-byte T-table,
  4 = S-box). CLI: `attack --full`.

## bruteforce.py: many keys, one block

`aesref` runs one key over many blocks. `bruteforce` runs many keys over
one block, which is the shape the endgame of an uneven attack needs: the
vote leaves a few bytes undetermined, and finishing them key-by-key in
Python is hours where a vectorised search is seconds. Round keys become an
`(n, 11, 16)` array and everything else is the same table lookups and XORs.

Measured at 0.44 M keys/s, so 2^16 is instant and 2^24 about 26 s; verified
byte-for-byte against `aesref` for the key schedule, its inversion and the
decryption. `search_positions()` filters candidates on CCM counter-block
structure, which needs no known plaintext - see `demo/oscore/verify.py`. It
earns its place on the F746 OSCORE victim, where the leak is uneven enough
that the vote stalls three bytes short of the key.

`search_positions()` and `search_pairs()` both accept `known=(pt, ct)`: an
exact single-block check that replaces the CCM structural test wherever the
mode hands the attacker the cipher's *input* as well as its output. TLS-CBC
does - `C_i = E(K, P_i ^ C_(i-1))`, both ends on the wire - and there it
settled a key on the very first position pair. See
[`demo/tls_https/`](../../demo/tls_https).

`search_pairs()` is the cheaper and better-behaved endgame: all
C(16,2) = 120 position pairs at 2^16 each is 7.9 M candidates, less than
one 2^24 search, and it recovers ANY vote that is right on 14 of 16 bytes,
wherever the wrong two sit. That matters because escalating to the *least
confident* positions assumes the vote knows which bytes it got wrong, and
it often doesn't: on the F429 OSCORE capture at 300 k traces the two wrong
bytes rank 1st and 4th by confidence, so the ranked search misses one.
Switching to the pair sweep halved that attack's capture, 600 k traces to
300 k.

## engine.leaking_offsets: which byte pairs leak, without the key

Only some pairs of output bytes can collide in a cache line; the rest
contribute nothing but noise to the vote, and they can outnumber the real
ones seven to one. `leaking_offsets()` finds which offsets matter with no
key at all: a single pair's peak is a max over 65536 cells and reads
~4.2 sigma on noise alone, but averaging over the 16 pairs that share an
offset separates them cleanly.

`recover(pair_offsets=...)` then restricts the vote. On the F429 OSCORE
capture that took the vote from 11/16 to 15/16 at 250 k traces and made the
scan 7x faster. It's target-dependent and worth checking rather than
assuming: TinyCrypt leaks only on offset 3, while mbedTLS leaks
*uniformly* across all 120 pairs, so there the restriction correctly finds
nothing to discard.

Watch out: a false positive here fails the attack, since the restriction
throws away 105 of 120 good pairs. A uniformly-leaking target produces a
gently decreasing ramp of peaks whose top can clear a "median + margin" bar
by a hair and mean nothing. On one SNMPv3 draw that took the vote from
15/16 to 8/16, and at 130 k traces all five draws misfired identically -
the spurious peak grows with n just as a real one does, so it was a
deterministic ceiling rather than bad luck.

So selection requires the kept offsets to be a *spike* rather than the top
of a ramp: excess over the median at least `ratio` (default 3) times the
best rejected offset's. Measured, that statistic reads 17-40 for a real
single-family leak and 1.2-1.7 for a uniform one, so the cut isn't tuned.
`engine.select_offsets` is the rule on its own, tested against eight
recorded peak maps in
[`flashwhisperer/tests/test_offsets.py`](../tests/test_offsets.py), because
the scan that produces one costs ~50 s.

Note the calibration needs more traces than the attack it accelerates
(~450 k against 200 k on the OSCORE capture), so on a live target the
offsets come from a device the attacker owns and not from the attack data.
`leaking_offsets` on a 200 k subset correctly returns nothing.

## CLI

```bash
python -m flashattack selftest                              # hardware-free smoke test
python -m flashattack attack  --port COM9 --mode ctr --n 150000 --acr 00000705 --verify
python -m flashattack boot    --port COM9 --n 60000 --K 255 --verify   # ACK-latency oracle
python -m flashattack feasibility --port COM9 --mode ecb-dec --n 20000
```

## Tests (two tiers)
```bash
PYTHONPATH=. pytest                 # QUICK CI: fast unit tests only (seconds)
PYTHONPATH=. pytest --runslow       # LONG: + engine scans + replay of captured vectors
```
- Quick (`test_flashattack.py`, the default): FIPS-197 vectors
  (128/192/256), key-schedule inversion, mode-mapping consistency. No
  hardware, no big data.
- Long (`--runslow`): synthetic recovery (clean + brute-force rescue) and
  replay of real captured trace vectors in `tests/vectors/*.npz` (S-box +
  T-table, several key sizes/modes). Capture more with
  `tests/make_vectors.py`. Vectors store only timing (uint16,
  seed-regenerated material) so each is ~100-250 KB compressed and lives in
  git.
- The same two tiers cover [`demo/oscore/`](../../demo/oscore)
  (`demo/oscore/test_replay.py`), which replays the over-Ethernet captures
  and re-derives the OSCORE key and its negative control. `--runslow` there
  is the key recovery itself.
- `conftest.py` lives at the repository root so both test directories share
  one `--runslow` option.
