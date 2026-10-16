# Experimental / partial results and their ceilings

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

This documents the investigations whose outcomes are partial or negative  - 
real, validated, but not full key recovery - so future work knows exactly where the
walls are and why: (1) known-plaintext-only AES, (2) SM4, and (3) ARIA/Camellia.
They stem from the same fact: a flash-line collision reveals only the top bits
of a lookup index (a 16-byte line ⇒ nibble resolution for an S-box), and it is only
exploitable when many lookups pass through a single table so a within-round
collision survives the cache, *and* the collision relates to the key through a
nonlinear function. AES's single-table SPN last round provides both; other
structures fail one or the other.

## 1. Known-plaintext-only recovery (AES) - `engine.recover_round1_keyspace`

Scenario: the attacker sees the *inputs* (plaintext) and timing but not the
ciphertext (e.g. a device that encrypts chosen/known plaintexts without exposing
output, or the first block of a CMAC). The mirror image is a decryption with
chosen ciphertext, where the input is likewise known and the output is not.

> Outcome, updated: on a single-table implementation this is a full key
> recovery, not a partial one - round 1 reduces to 2^38 and round 2 finishes the
> job from timing alone. What remains genuinely partial is the 4-table case
> (2^56, and round 2 does not decompose there). The rest of this section is the
> round-1 analysis that gets you to the residual.

Method: round-1 S-box index = `pt ^ k0`, and `topbits(pt^k0) = topbits(pt) ^
topbits(k0)`, so two positions collide iff `topbits(pt[a])^topbits(pt[b]) ==
topbits(k0[a]^k0[b])`. Bucketing by the (known) left side and taking the
shortest-time bucket gives the top-bit key-byte difference for each leaking
pair; a confidence-ranked graph propagation then assigns every byte's top bits
relative to a reference.

Measured (F429, recorded vectors):

| Implementation | resolved | correct | residual keyspace |
|---|---|---|---|
| S-box (tiny-AES) | 16/16 | 16/16 | 128 → 38 bits |
| T-table (Mbed-TLS, 4-table) | 16/16* | 4/16 | unreliable |

*The 4-table layout interleaves the round-1 lookups across four separate tables,
so few pairs truly collide; the method reports resolutions with false confidence.
Reliable only on S-box implementations.

The ceiling is set by the channel's granularity, and it is finer than the cache
line. A 16-byte line holding 1-byte S-box entries should resolve only the top
nibble of a lookup index, leaving ~68 bits. Sweeping `line_shift` over the
tiny-AES capture says otherwise:

| `line_shift` | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---:|---:|---:|---:|---:|---:|
| bytes/line implied | 1 | 2 | 4 | 8 | 16 | 32 |
| differences correct | 2/16 | 9/16 | 16/16 | 16/16 | 16/16 | 1/16 |
| residual |  -  |  -  | 2^38 | 2^53 | 2^68 |  -  |

The channel resolves 4-byte granularity *here*: `line_shift=2` recovers all
fifteen 6-bit key-byte differences exactly, `line_shift=1` degrades to 9/16 and
`line_shift=0` fails.

This is a property of the implementation, not of the part. The same sweep on
a TinyCrypt capture from the same F429 resolves only the 16-byte line --
16/16 differences at `line_shift=4`, but 6/16 at `line_shift=2` - so its
residual is 2^68, not 2^38. mbedTLS `FEWER_TABLES` behaves like tiny-AES and
resolves 4 bytes. Sweep the width on your own target rather than assuming
either. So there is sub-line structure - consistent with 32-bit
flash data reads inside a 128-bit line - and the honest residual for an AES-128
S-box is 2^38, not 2^68. Verified: the true key satisfies all sixteen
recovered constraints, and random keys satisfy them at the expected 2^-90 rate,
so the constraints are not vacuous.

That changes the verdict, and round 2 changes it again - the single-table case
is now a full break with no known block at all. 2^38 is about 2.7e11
candidates, each settled by one known (plaintext, ciphertext) pair, so a single
known block already turns the reduction into a key. But the residual does not
have to be enumerated: round-2 collision indices are nonlinear in the key and
resolve the remaining bits directly. Measured end to end on this capture
(250 k traces, tiny-AES on the F429, ART on):

```
round 1: 16/16 byte differences resolved, 16 correct
  residual after round 1: 2^38
round 2 chose R=10, score -19.494  (734s)
recovered round-0 key: 2b7e151628aed2a6abf7158809cf4f3c
truth                : 2b7e151628aed2a6abf7158809cf4f3c
16/16 bytes correct -> EXACT
```

The attacker here sees plaintexts and a per-operation time, and nothing else
 -  no ciphertext, no known (P,C) pair, no verification oracle. The key falls in
12 minutes of CPU. So for a single-table implementation, "known-plaintext
only" is not a keyspace reduction at all; it is a break, and this section's
original framing was too pessimistic by the whole 2^38.

See [`ROUND2.md`](ROUND2.md) for the decomposition that makes it cheap (four
independent per-column searches) and [`research/round2/round2_fullsolve.py`](../../research/round2/round2_fullsolve.py)
for the run above.

The 4-table case is weaker but not dead, and the earlier reading of it was a
tool artefact. `recover_round1_keyspace` reports 4/16 on the mbedTLS
ECB-decrypt capture, which looks like "the layout does not leak". Scoring every
pair individually says otherwise - the pairs that resolve correctly are exactly
the offset-4, -8 and -12 families, and *all* of them do:

| pair offset | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| correct | 1/15 | 0/14 | 0/13 | 12/12 | 1/11 | 0/10 | 0/9 | 8/8 | 0/7 | 0/6 | 0/5 | 4/4 |

Byte positions congruent mod 4 index the *same* `RT` table, so they can share a
line; everything else cannot. The channel is therefore partitioned into four
independent groups - `{0,4,8,12}`, `{1,5,9,13}`, `{2,6,10,14}`, `{3,7,11,15}`  - 
and within each, all three differences come out correct (12/12 total). The 4/16
was simply the single-reference propagation being unable to leave byte 0's group.

Solve the group jointly rather than pair by pair. The per-pair argmin above
treats each of a group's six histograms separately. Scoring one hypothesis
`(d1,d2,d3)` against all six at once
([`research/round2/round1_joint.py`](../../research/round2/round1_joint.py))
shares evidence across the group and is measurably stronger: on the bench capture
it recovers all 12 within-group unknowns at 25 k traces where per-pair
scoring still reads 20/24 and needs 50 k. On the SNMPv3 network capture with the
data cache on it gives 12/12 at both 4-byte and 16-byte granularity.

It is not a cure-all. Against a weak channel the gain is bounded by how much
there is to pool - six pairs per group here, against ~15 per byte on the output
side - and on a `DCEN=0` network capture joint scoring moves 4/24 pairs to only
2 of 12 unknowns. Pooling six pairs cannot cover a 70x amplitude deficit.


That leaves 16 x 2 low bits + four 6-bit group references = 2^56: far
worse than the single-table 2^38, out of brute-force range, but a long way from
nothing. Linking the four groups is what a round-2 attack would be for, since
round-2 indices are nonlinear in the key - and round-2 collisions are measured to
leak just as strongly as round-1 ones (mean dip -2.37 vs -2.31 cycles at 4-byte
granularity, 101/120 vs 102/120 pairs below -1 on the tiny-AES capture), so the
obstacle there is the search structure, not the signal.

Any single output observation (the last-round attack) is still the better
route when available, and needs no search at all.
`recover_round1_diffs` (naive all-vs-ref) and `recover_round1_keyspace` (robust,
graph) are both experimental, not wired into `attack()`.

Future: select leaking pairs by margin (done); combine with a partial output
oracle to anchor the differences; profiled/template variant for very low SNR.

## 2. SM4 (`sm4.py`) - a structural resistance result

SM4 is fully implemented (GM/T 0002 reference verified) and integrated as a target
(`fw_f4_lib LIB=sm4`, GmSSL). The security-relevant finding:

- GmSSL's default SM4 uses four separate T-tables (`T0..T3`) - the four
  per-round lookups hit four different tables, so they never share a cache
  line: no within-round collision at all (exactly like the "safe" 4-table AES).
- The single-table / S-box build (`ENABLE_SMALL_FOOTPRINT`, `make LIB=sm4
  SM4_SBOX=1`) does collide, but SM4 is a Feistel cipher: the last-round S-box
  index is `X32^X33^X34 ^ rk31` with `X32..X34` known from the ciphertext, and the
  S-box *output* is not observable (`X31` is unknown). So the collision is on an
  index that is linear in the key ⇒ only the top-nibble differences of the
  last round key `rk31` leak, and you cannot peel to earlier rounds (peeling
  needs the full round key). `recover_rk31_topnibble_diffs` returns exactly that.

Contrast with AES: AES's SPN last round is `ct = SBOX(state) ^ k10`, so the
index `state = SINV[ct ^ k10]` passes through the nonlinear inverse S-box  - 
which is what lets the collision pin the *full* key byte and enables full recovery.
SM4's pre-S-box key XOR (Feistel) denies that anchor. SM4 is therefore markedly
more resistant to this flash-timing channel than AES: only a partial top-nibble
leak of one round key, no full-key path.

Validated: reference (GM/T vector), synthetic partial leak (3/3 rk31 top-nibble
diffs), and on real F429 silicon (S-box build) - see RESULTS. A previous "full SM4
recovery" claim was a modeling error (collisions were planted on the S-box
*output* instead of the *index*); corrected here.

Future: the same partial leak applies to other Feistel/ARX table ciphers; see
ARIA and Camellia below for the tested comparisons.

---

## 3. ARIA and Camellia - the *single-table last round* is the real condition

The initial hypothesis was "SPN ⇒ recoverable like AES." ARIA falsifies it, and
the corrected condition is sharper: full last-round recovery requires the last
round to funnel its lookups through a SINGLE table (AES's `FSb`, 16 lookups on
one 16-byte-line S-box). Both new ciphers were verified on real F429 silicon
(mbedtls, `ACR=00000705`, 128 B ART data cache) against their published test
vectors before the timing check.

- ARIA (`aria.py`) - SPN, but resists. ARIA *is* an SPN whose last round is
  `ct = SL(state ^ ek) ^ ek_final`, structurally identical to AES. But its
  substitution layer uses four separate S-box tables (`SB1,SB2,IS1,IS2`); the
  last SL sends only 4 of the 16 bytes through each table. On the 128 B cache
  those few same-table lines are evicted between the sparse lookups, so the
  within-round collision never survives. Measured: known-key within-table
  collision dip ≈ 0 (−0.01 / +0.04 / −0.06 / +0.06 cyc across the four tables),
  `recover_final_roundkey` scores 0/16 on hardware - despite the overall
  `cyc std ≈ 19.6` (the cipher *does* leak, just not an exploitable within-round
  same-table collision). Synthetic single-table model still gives 16/16, so the
  code is kept for reference and for genuinely single-table SPN targets.
- Camellia (`camellia` firmware target) - Feistel + 4-table F, resists.
  Camellia is Feistel (key XOR *before* the S-box, like SM4 - a linear index anchor
  at best) *and* its F-function spreads lookups over four SP tables. Both walls at
  once. Measured: NIST vector `67673138…eabe43` OK, `cyc std ≈ 16.1`
  (data-dependent timing present), but no clean full-key path - partial at best,
  like SM4.

Summary of the structural map (all validated on F429 silicon):

| Cipher | Structure | Last round | Result |
|---|---|---|---|
| AES-128/192/256 | SPN | single table (`FSb`) | full key (192/256 via 2nd-round MixColumns-linearity) |
| ARIA | SPN | 4 tables, 4 lookups each | resists (dip ≈ 0, 0/16) |
| SM4 | Feistel | 1 table (`SM4_SBOX=1`) | partial - top-nibble `rk31` diffs only |
| Camellia | Feistel | 4 tables | resists (leaks timing, no clean recovery) |

Both results reinforce, and correct, the project's central theme: the
flash-timing collision recovers the full key only when the last round funnels many
lookups through a *single* table (AES-style). A Feistel key-XOR-before-S-box, a
multi-table substitution layer, or a non-table (bitsliced/constant-time) layout
each independently reduces it to a partial leak or nothing. SPN-vs-Feistel was
the wrong axis; single-table-last-round is the right one.
