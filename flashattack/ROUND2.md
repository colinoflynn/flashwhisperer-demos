# Round-2 collisions: finishing the key when only the *input* is known

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Status: demonstrated end to end on recorded hardware. Round 1 + round 2
recovers the complete AES-128 key from plaintexts and timing alone - no
ciphertext, no known (P,C) pair, no verification oracle - on the 250 k tiny-AES
F429 capture, in 734 s of CPU:

```
round 1: 16/16 byte differences resolved  ->  residual 2^38
round 2 chose R=10                        ->  2b7e151628aed2a6abf7158809cf4f3c  EXACT
```

The decrypt direction is now measured too, not argued. A fresh 1 M-trace
tiny-AES ECB-decrypt capture on the F429 (`fw_f4_lib` with the new `Y` batch
command) reproduces every step:

```
round 1 granularity sweep:  4-byte granularity, 16/16 differences  -> 2^38
round 2 low-bit test:       16/16, round-1 control spread 0.0e+00
round 2 chose R=52, score -18.516 (best wrong -12.066)
recovered rk10: d014f9a8c9ee2589e13f0cc8b6630ca6   EXACT
master key    : 2b7e151628aed2a6abf7158809cf4f3c   EXACT
```

R=52 was predicted from `rk10[0]=0xd0` before the sweep reached it. So the CBC
bootloader case is fully demonstrated: supply ciphertext, time the decryption,
never see a plaintext, recover the master key.

It is not confined to toy implementations. The same solver, unchanged, on a
1 M-trace decrypt capture of mbedTLS built with `MBEDTLS_AES_FEWER_TABLES` --
a documented flash-saving option, not an exotic configuration:

```
round 1: 16/16 differences resolved            -> residual 2^38
round 2 chose R=52, score -43.470              (best wrong -12.010)
recovered rk10: d014f9a8c9ee2589e13f0cc8b6630ca6   EXACT
master key    : 2b7e151628aed2a6abf7158809cf4f3c   EXACT
```

R=52 was predicted from `rk10[0]=0xd0` before the sweep reached it, as on the
tiny-AES run.

The margin is 31.5 against tiny-AES's 6.5 - about five times stronger. That
is the T-table geometry rather than luck: 4-byte entries put 4 per 16-byte line
where a byte S-box puts 16, so each collision constrains more. It matches the
older finding that a compact T-table "leaks more richly than the S-box".

So the claim is not "a toy AES falls to this". It is that a shipped
configuration of the most widely deployed embedded TLS stack gives up its key
from ciphertext and timing alone, with no plaintext ever observed and no
verification pair.

## Everything above is a LOCAL result. Remote is not demonstrated yet.

Worth stating plainly, because the claim this work leans on - that round-2
analysis does not need chosen input, against three papers that concluded it does
-- is about the remote setting, and every recovery above used an on-chip
SysTick over a serial link.

Tested on a real network capture and it does not yet work. The SNMPv3 demo is
the right vehicle: under CFB the second keystream block is `E(K, C1)`, so
ciphertext block 1 is the block cipher's *input* and it travels in clear.
Running round 1 on `(C1, network round-trip time)` and never touching the stored
keystream:

| assumed line width | 4 B | 8 B | 16 B |
|---|---:|---:|---:|
| differences correct | 1/8 | 1/1 | 1/1 |

Round 1 does not resolve far enough to hand round 2 anything to finish.
(Read that table with the caveat below: under this victim's 4-table layout the
propagated score cannot exceed 4/16 no matter how good the channel is.)

A noise-matched control predicted this was only a trace-count problem, and
that prediction was wrong. Adding Gaussian noise to the bench capture to bring
its sigma from 31.6 to the network's 101 reproduced the 250 k failure exactly
(1/16) and then recovered at 1 M (15/15), so ~1 M network traces were predicted
to suffice.

A 1 M-exchange capture was taken - 45 minutes of traffic, 0 timeouts - and it
still does not reach a usable round-1 solution:

| 1 M capture, 717 099 traces kept, sigma 60.1 | 4 B | 8 B | 16 B |
|---|---:|---:|---:|
| differences resolved | 1/16 | 1/16 | 1/16 |

Note the conditioned sigma is 60.1, not the 101 the extrapolation assumed, on
4.3x as many kept traces. Quieter and larger, and still short.

That was first read as "there is no input-side signal to find", and that
reading was wrong. The check behind it scored all 120 byte pairs with the key
supplied and got 9 correct against a chance level of 7.5. But the SNMPv3 victim
is stock mbedTLS, which uses four T-tables: only byte pairs at offsets
0 mod 4 share a table, so only 24 of the 120 pairs can produce a round-1
collision at all. Pooling buries those 24 in 96 pairs of noise. Scored on the 24
alone, the same capture is not at chance:

| SNMPv3 1 M, 717 099 kept, sigma 60.1 | aligned 24 pairs | p | other 96 |
|---|---:|---:|---:|
| 4-byte granularity | 4/24 (chance 0.4) | 4.9e-4 | 1/96 |
| 16-byte granularity | 4/24 (chance 1.5) | 0.06 | 5/96 |

The same mistake inflated the propagated score's ceiling. `recover_round1_keyspace`
walks differences out from byte 0, and under a 4-table layout byte 0 reaches only
{0, 4, 8, 12} - so 4/16 is a saturated result, not a weak one. The bench
capture of the same library build also stops at exactly 4/16, at every trace
count from 25 k to 1 M, with 24/24 aligned pairs correct. The remote 1/16 was
being read against a ceiling of 16 that the layout forbids. That ceiling was
already written down in [`EXPERIMENTAL.md`](EXPERIMENTAL.md) - the error here
was failing to apply it to a capture from a 4-table victim.

So the remote input side carries a real but weak signal. What it does not do
is grow:

| aligned pairs correct (shift=2) | 50 k | 100 k | 250 k | 500 k | 717 k |
|---|---:|---:|---:|---:|---:|
| remote SNMPv3 | 3/24 | 3/24 | 3/24 | 3/24 | 4/24 |
| bench, same build | 15/24 @10k | 20/24 @25k | 23/24 @50k | 24/24 @100k | 24/24 |

Three of the twenty-four pairs sit well above the detection floor at 50 k and the
other twenty-one stay below it at 717 k. That is a saturating channel, not a
noisy one.

### It is not the statistic, not the call, and not the noise budget

Three confounds were removed, all offline, on captures already taken.

Not the statistic. The input side buckets linearly into 16 or 64 bins; the
last-round attack searches 2^16 guesses through a non-linear predictor. Run both
on the *same* bench traces over the *same* AES calls
([`research/round2/statistic_power.py`](../../research/round2/statistic_power.py)),
they track each other almost exactly - tiny-AES decrypt, 1 M:

| traces | input side | output side |
|---:|---:|---:|
| 25 k | 2/16 | 1/16 |
| 50 k | 10/16 | 8/16 |
| 100 k | 15/16 | 15/16 |
| 250 k | 16/16 | 16/16, key EXACT |

The linear bucketing is not the weaker instrument.

Not which call was observed. The SNMPv3 capture stores both ends of CFB block
2 - `C1` is its input, `keystream2` its output, one AES call, one round-trip
time ([`research/round2/same_call_sides.py`](../../research/round2/same_call_sides.py)).
Pointed at that single call, the output side reads 15/16 from 50 k traces onward
while the input side reads 1/16 at 717 k. The asymmetry survives the
deconfounding.

Not the noise budget. The obvious remaining story is that the network is
simply noisier. It is testable: rescale the bench capture into the attacker's
clock (216 MHz counting a 180 MHz victim) and add Gaussian noise until its sigma
matches the remote 60.1
([`research/round2/noise_matched_bench.py`](../../research/round2/noise_matched_bench.py)).
If sigma were the whole story the two ladders would overlay. They do not:

| aligned pairs correct (shift=2) | 50 k | 100 k | 250 k | 500 k | 717 k |
|---|---:|---:|---:|---:|---:|
| bench, noise-matched to sigma 60.1 | 11/24 | 20/24 | 20/24 | 24/24 | 24/24 |
| remote, sigma 60.1 | 3/24 | 3/24 | 3/24 | 3/24 | 4/24 |

At matched sigma and matched trace counts the bench recovers every collidable
pair and the network recovers four. Whatever the network costs the input side,
it is not additive noise - additive noise averages out, and this does not.

### Being the second block of a chained mode: tested, and it is not that

The hypothesis was that round 1 of CFB block 2 runs on a cache already warmed
by block 1, with the warming independent of `C1`. A collision is only visible
if the second access would otherwise have missed; if block 1 already pulled that
line in, the access hits either way and the pair goes dark. That masks signal
rather than adding noise, which matched the saturating behaviour.

It is wrong. A `Z` command was added to
[`rigs/fw_f4_lib/main.c`](../../rigs/fw_f4_lib/main.c) that runs the CFB
chain on the bench - `ks1 = E(iv)` with `iv` from the PRNG, `C1 = P1 ^ ks1`,
`ks2 = E(C1)` - so the attacked call is preceded by one whose table-access
pattern varies per trace and is unrelated to `C1`. Three arms, one board, one
ACR, 250 k traces each
([`research/round2/chain_warmup.py`](../../research/round2/chain_warmup.py)):

| arm | sigma | aligned 4 B | aligned 16 B | last round |
|---|---:|---:|---:|---:|
| A constant warm-up (the existing `X`) | 14.29 | 24/24 | 24/24 | 16/16 EXACT |
| B CFB chain, 2nd call timed | 14.72 | 24/24 | 24/24 | 16/16 EXACT |
| C CFB chain, both calls timed | 20.50 | 24/24 | 24/24 | 16/16 EXACT |

Nothing moves. A varying warm-up does not mask the input side, and neither does
carrying the first call's timing variance. (`Z 3` prints `C1` per trace so the
host can prove it mirrors the chain; it does, 8/8 byte-exact. Without that check
a host-side mirroring bug and a confirmed hypothesis would both read at chance.)

### It is amplitude, and the number is 70x

The noise-matched control assumed the two captures differ only in noise. That
assumption was never checked, and it is false. Measuring the collision dip
directly with the key known - how much faster colliding traces run, in cycles
([`research/round2/dip_amplitude.py`](../../research/round2/dip_amplitude.py)):

| capture | side | sigma | median dip | dip/sigma |
|---|---|---:|---:|---:|
| bench mbedTLS 4-table | round-1 input | 19.13 | -4.250 | 2.2e-1 |
| bench mbedTLS 4-table | last round | 19.13 | -4.095 | 2.1e-1 |
| remote SNMPv3, same build | round-1 input | 60.11 | -0.060 | 1.0e-3 |
| remote SNMPv3, same build | last round | 60.11 | -0.024 | 4.1e-4 |

(bench scaled by 216/180 into attacker cycles first, since the F746 counts a
180 MHz victim at 216 MHz.)

The remote per-pair dip is about 70x smaller than the bench's, which is a
5000x penalty in traces - roughly 1.6e7 for one pair at 4 sigma, against 2500
on the bench. That, and not the network as such, is what the input side ran into.

And the remote's two sides have the same amplitude. Both sit near 1e-3 of
sigma. So the input/output asymmetry was never a difference in channel strength.

### Why the output side survives the same amplitude: pooling

What differs is how much evidence each analysis can pool behind one hypothesis.
The last-round attack scores a single key-byte guess against every pair that
touches that byte - about 15 of them - and sums margins, so consistent
evidence compounds. `recover_round1_keyspace` takes a separate argmin per pair
and only then propagates. Under a 4-table layout a byte's group holds just four
bytes, so the input side has at most 6 pairs to pool, against the output
side's 15 - and its unknown is a difference rather than an absolute value.

Solving each group jointly - one hypothesis `(d1,d2,d3)` scored against all six
of the group's histograms at once, rather than six independent argmins
([`research/round2/round1_joint.py`](../../research/round2/round1_joint.py)) --
confirms the mechanism works and is not enough:

| | joint | per-pair |
|---|---:|---:|
| bench, 25 k traces | 12/12 unknowns | 20/24 pairs |
| remote, 717 k, 16 B | 1/12 (chance 0.75) | 4/24 |
| remote, 717 k, 4 B | 2/12 (chance 0.19) | 4/24 |

Joint scoring recovers the bench group at 25 k where per-pair scoring needs
50 k, so the aggregation is real. On the remote capture it moves 4/24 to 2 of 12
unknowns. Pooling six pairs cannot cover a 70x amplitude deficit.

Status of the load-bearing claim: round-2 recovery is demonstrated locally and
NOT demonstrated remotely - but the reason is now measured rather than
guessed. It is not the statistic, not which call is observed, not sigma, and not
chained-mode cache warming. The remote per-pair collision dip on this victim is
~70x smaller than the same library build on the bench, both sides alike, and the
last-round attack survives it only because a 4-table layout lets it pool 15 pairs
per byte where round 1 gets 6.

### Answered: the victim runs with the data cache OFF, and the bench did not

The SNMPv3 victim prints its own configuration at boot. Flashing it back and
reading the banner:

    === snmpv3-victim (NUCLEO-F429ZI) ===
    SYSCLK  = 180000000 Hz
    FLASH_ACR = 0x00000305

`0x305` is LATENCY=5, PRFTEN=1, ICEN=1, DCEN=0. Every bench capture it was
being compared against was taken at `0x705` - same wait states, same prefetch,
data cache on. The two were never the same channel. This is not news to the
repo: [`demo/oscore/README.md`](../../demo/oscore/README.md) already documents
that ST's own `stm32f4xx_hal_conf.h` for this board never defines
`DATA_CACHE_ENABLE` while CubeMX does, and measures both. The error was using a
`0x705` bench capture as the reference for a `0x305` victim.

Rerunning the bench at both settings, 717 099 traces each, one runtime `C`
command apart
([`research/round2/acr_amplitude.py`](../../research/round2/acr_amplitude.py)):

| | sigma | dip (4 B) | dip/sigma | input per-pair | output per-pair | pooled vote |
|---|---:|---:|---:|---:|---:|---:|
| bench `0x705` DCEN=1 | 14.31 | -3.700 | -2.6e-1 | 24/24 | 23/24 | 16/16 EXACT |
| bench `0x305` DCEN=0 | 5.98 | -0.016 | -2.8e-3 | 2/24 | 1/24 | 16/16 EXACT |
| remote SNMPv3 `0x305` | 60.11 | -0.060 | -1.0e-3 | 4/24 | 2/24 | 15/16 |

Every feature of the remote result reproduces on the bench over a serial
cable. Turning the data cache off drops the collision dip by ~230x, takes
per-pair evidence to 1-2 of 24 on *both* sides, and leaves the pooled last-round
vote at 16/16 EXACT. The remaining 2.7x between the bench `0x305` row and the
remote one is the network; the other ~100x was a cache bit.

So the input-side "null" was never about remoteness, and neither was the
input/output asymmetry. Both are what a DCEN=0 victim looks like from either
side, and the last round survives only because it pools ~15 pairs per byte where
a 4-table round 1 gets 6.

### Confirmed over Ethernet: DCEN=1 brings round 1 alive

The prediction above was tested. The SNMPv3 victim gained a `DCACHE=1` build
(`make ROMTABLES=1 DCACHE=1`, banner verified at `0x705`) and a clean 1 M capture
was taken over the same link - 717 896 kept, sigma 71.4, zero timeouts, zero
batch failures.

| victim, over Ethernet, ~717 k kept | sigma | dip (4 B) | dip/sigma | round-1 pairs | joint unknowns | last round |
|---|---:|---:|---:|---:|---:|---:|
| `0x305` DCEN=0 | 60.1 | -0.060 | -1.0e-3 | 4/24 | 2/12 | 15/16 |
| `0x705` DCEN=1 | 71.4 | -3.627 | -5.1e-2 | 22/24 | 12/12 | 16/16, key EXACT |

The measured dip of -3.627 attacker cycles sits against -3.700 on the bench and
-3.634 on an earlier 250 k run: bench amplitude carries over the network,
reproducibly. Round 1 resolves 12/12 within-group unknowns at both 4-byte and
16-byte granularity.

A trade-off framing written here earlier is withdrawn. From a 250 k capture
(sigma 107.3) whose last-round vote read 2/16, this section said the bit trades a
last-round attack for a round-1 one. At sigma 71.4 the last round recovers the
key outright, so at this trace count `DCEN=1` gives the attacker *both*. That
250 k capture was taken immediately before the attacker board hung and its sigma
is suspect. What survives is the solid half: `DCEN=0` leaves round 1 dead,
`DCEN=1` brings it fully alive, and the data cache is not a mitigation. The
OSCORE demo's `DCEN=1` last-round null (0/16 at 524 k) is a different victim
(TinyCrypt, sigma 154.6) and its round-1 behaviour there is untested.

### Four tables give four references, not one

Round 1 resolving is necessary but not sufficient. The round-2 search needs a
single global reference `R`: it assumes every byte's top bits are known
relative to byte 0. A 4-table layout splits the 16 bytes into four sets that
never collide with each other, so round 1 yields four independent reference
offsets. Linking them is a separate problem and more traces do not touch it.

`round2_network.py` used to gate on `recover_round1_keyspace` reaching 16/16 and
so printed "round 1 does not resolve - round 2 has nothing to finish" on the
capture above, whose round 1 is fully solved. That is the propagation ceiling
once more: byte 0 reaches only {0,4,8,12}, so 4/16 is the most that gate can ever
see. It now runs the joint group solve, reports 12/12, and names the real
obstacle rather than blaming the channel.

The capture that settles the remote round-2 claim is therefore a single-table
victim, where all 120 pairs collide and round 1 gives one reference across all 16
bytes: `make ROMTABLES=1 DCACHE=1 COMPACT=1`. Taken, 1 M exchanges, 724 646 kept
at sigma 97.3, and round 1 resolves globally:

| assumed line width | resolved | correct |
|---|---:|---:|
| 4 B | 16/16 | 11/16 |
| 8 B | 16/16 | 16/16 |
| 16 B | 14/16 | 14/14 |

16/16 correct at 8-byte granularity, input side only, residual 2^53 - the single
global reference round 2 requires. Whether the round-2 search completes from it
is running at the time of writing and is the one thing still unreported.

## Demonstrated remotely: the full key, input side only

The claim this document exists to support is now measured rather than argued.
On a 1 M-exchange SNMPv3 capture against a single-table `DCEN=1` victim, using
only `C1` off the wire and never reading the keystream:

| step | result |
|---|---|
| round 1 | 16/16 key-byte differences correct at 8-byte granularity |
| round 2 | R=23, score -13.845 vs runner-up -11.822 (margin 2.023); 13/16 bytes exact |
| residual | every error confined to the low 3 bits round 2 owns - round 1's top 5 bits were correct for all 16 |
| finish | 38,498 candidate tests against `E(K,C1)==ks2`, a pair free off the wire |
| key | `befa18829b1376e8d5d0d232ce6ecf5b` EXACT |

[`research/round2/round2_complete.py`](../../research/round2/round2_complete.py)
does the last step; it needs no new traces and no statistics, so 13/16 was never
a failure but a 2^9-shaped residual in a known structure.
[`research/round2/round2_parallel.py`](../../research/round2/round2_parallel.py)
runs the search across processes with per-offset checkpointing: 3,376 s against
the serial version's 5.4 h, after a machine crash destroyed 2.8 h of the latter.

### It also survives an Ethernet switch - but not a 10 Mbit link

Three switches and a direct cable, each a full seam-free 1 M verified byte-exact
at start, middle and end. At 100 Mbit a switch is free: round 1 resolves 16/16
on the direct cable and on both 100 Mbit switches, with sigma ~97-104 and the
dip within 10% across all three. On a 10 Mbit link the arrival time is quantised
ten times more coarsely, sigma collapses to 13.7, the dip goes to -0.016 and
nothing resolves.

An earlier draft of this section blamed a particular switch for re-timing frames
and costing ~1e8 traces. That was wrong: the variable is link speed, invisible
from the host, and the same two switches produced both outcomes on different
sessions. See [`demo/snmpv3/README.md`](../../demo/snmpv3/README.md).

Still open: the round-2 search on that single-table capture, linking the four
groups of a 4-table victim, and wiring the
solver into the package rather than
[`research/round2/round2_fullsolve.py`](../../research/round2/round2_fullsolve.py)
and its `_dec` sibling. This document is the
solver into the package rather than
[`research/round2/round2_fullsolve.py`](../../research/round2/round2_fullsolve.py)
and its `_dec` sibling. This document is the
design and the measured evidence behind it, so a later session can start from the
open questions rather than re-deriving the closed ones.

### A partial round-2 result is not a failure: rank the columns

The switch #2 capture first reported 8/16 bytes correct - MISMATCH, against
13/16 on the direct cable. Round 1 was identical on both (16/16 at 8-byte
granularity) and both chose the same, correct, R=23, so the top 5 bits of every
byte were right and all eight errors sat in the low 3 bits round 2 owns.

Searching those blindly is 2^36. But round 2 scores all 4096 low-bit
combinations per column and reports only the best one, so the real question is
where the TRUE combination ranks
([`research/round2/round2_rank.py`](../../research/round2/round2_rank.py)):

| column | bytes | rank of truth |
|---|---|---:|
| 0 | 0, 5, 10, 15 | 775/4096 |
| 1 | 4, 9, 14, 3 | 0 |
| 2 | 8, 13, 2, 7 | 0 |
| 3 | 12, 1, 6, 11 | 75/4096 |

Two columns were already exact. Only two needed a deeper look, and because the
columns are independent and their scores add, the cost is the product of those
ranks rather than the worst one raised to the fourth power - about 6e4 against
3.6e11, seven orders of magnitude apart.

[`research/round2/round2_finish.py`](../../research/round2/round2_finish.py)
walks the four ranked lists best-first against the free `E(K,C1)==ks2` oracle:

```
EXACT after 295,791 verifications   column ranks used: [775, 0, 0, 75]
key = befa18829b1376e8d5d0d232ce6ecf5b
```

So the key is recovered over Ethernet through a switch, input side only. The
product of ranks (about 6e4) is a lower bound on the search, not the count: a
best-first walk of the score lattice visits nodes outside the strict rank
rectangle, which is where the remaining factor of five went.

The lesson for reading these results: a round-2 byte count is the rank-0
projection of a four-column search, and quoting it alone understates what the
capture contains. Rank the columns before calling a capture short.

## What it buys, and when it is worth anything

The last-round attack needs the block cipher's output. Two important cases do
not have it:

| case | what is known | round-1 result |
|---|---|---|
| CBC bootloader, chosen ciphertext, no plaintext | input = `C` | differences only |
| encrypt-only device, known plaintext, ciphertext never emitted | input = `P` | differences only |

Both land on round 1, where the key enters *before* the lookup and linearly, so a
line collision reveals only `(k[a] ^ k[b]) >> line_shift` - key-byte differences
at the channel's granularity, never absolute bytes. Measured residuals
([`EXPERIMENTAL.md`](EXPERIMENTAL.md)):

* single-table (tiny-AES S-box, one 256-byte table): all 15 differences at
  4-byte granularity → 2^38
* 4-table (mbedTLS `RT0..RT3`): differences only *within* the four
  same-table groups `{0,4,8,12}`, `{1,5,9,13}`, `{2,6,10,14}`, `{3,7,11,15}` →
  2^56

Round 2 is the way out, because its lookup indices are a nonlinear function of
the key (they sit behind an S-box and MixColumns), so collisions there carry
absolute bits rather than differences.

Before building this, check whether you need it. If any known plaintext block
exists, 2^38 is finishable by brute force against that one pair (hours with
AES-NI) and round 2 is wasted effort. If ~10^5 known-plaintext blocks exist, the
ordinary last-round attack applies with no new code at all. Round 2 earns its
keep only when the *output side is genuinely unavailable*.

## Measured feasibility (recorded F429 capture, tiny-AES single S-box)

All from `tests/vectors/sbox_tinyaes_ecb-enc_128.npz`, 250 k random inputs,
scored against the known key.

1. Round 2 leaks as strongly as round 1. Predicting round-2 S-box indices and
pooling the collision dip over all 120 pairs at 4-byte granularity:

| | mean dip | pairs below −1 |
|---|---:|---:|
| round 1 | −2.31 cyc | 102/120 |
| round 2 | −2.37 cyc | 101/120 |

2. It carries exactly the bits round 1 cannot see. Perturbing only the low 2
bits of a key byte leaves every round-1 line tag identical (XOR has no carries,
so `top6(P^k) = top6(P)^top6(k)`) - a built-in control. Round 2 picks the true
value 16/16, true −2.37 against ~−1.33 for the other three, and the round-1
control reads exactly `0.00e+00` spread.

3. It survives not knowing the round-2 key. `k1` enters the same-column
collision condition only as a single 6-bit nuisance target per pair, and
bucketing by the predicted quantity yields all 64 targets in one pass, so the
search is free. Still 4/4 with `k1` unknown.

4. Pooling all 120 pairs does NOT decompose. With 4 or more other key bytes
wrong, recovery collapses to chance (1/12, 2/8, 1/4) and the margin goes
negative. A round-2 state byte depends on 4 key bytes, so most pairs touch a
wrong one. Scoring all 120 pairs jointly makes round 2 a *verifier* over the
whole 2^38, which is useless - the whole point is to avoid enumerating it.

5. The per-column decomposition is what makes it work. Round-2 state byte
`4c+r` depends on exactly one diagonal of the key, so the six same-column
pairs of column `c` are a function of just 4 key bytes:

```
column c  ->  key bytes { 4c, 4((c+1)%4)+1, 4((c+2)%4)+2, 4((c+3)%4)+3 }
column 0  ->  0, 5, 10, 15        column 2  ->  8, 13, 2, 7
column 1  ->  4, 9, 14, 3         column 3  ->  12, 1, 6, 11
```

Given round 1, a column has 4 x 2 = 8 unknown low bits. Column 0, 256
candidates, rank of the true one out of 256:

| traces | `k1` known | `k1` unknown, best-of-64 | `k1` unknown, max-z |
|---:|---:|---:|---:|
| 25 000 | 1 | 31 | 39 |
| 100 000 | 0 SOLVED | 0 SOLVED | 0 SOLVED |
| 250 000 | 0 SOLVED | 0 SOLVED | 0 SOLVED |

The 25 k failure is statistical power, not structure - six pairs instead of
120 is √20 less averaging. At 100 k it solves cleanly in the realistic mode.

6. The full attacker position solves. Column 0 with *both* unknowns searched
jointly - the shared 6-bit reference `R` and the column's 8 low bits, 64 x 256 =
16 384 candidates, `k1` unknown:

| traces | rank of true candidate | margin over best wrong | time |
|---:|---:|---:|---:|
| 50 000 | 1 / 16384 |  -  | 35 s |
| 100 000 | 0 / 16384 | +0.475 z | 72 s |
| 250 000 | 0 / 16384 | +1.338 z | 185 s |

So `2^38` becomes four independent 2^14 searches that take about a minute
each, with the threshold at ~100 k traces and comfortable margin by 250 k. Since
`R` is shared, the four columns cross-check each other: the correct reference is
the one whose four columns all score well, which should push the usable threshold
below 100 k.

## The algebra

### Encryption (known plaintext)

Round-2 S-box indices are the state after round 1:

```
x2 = MixColumns( ShiftRows( SubBytes( P ^ k0 ) ) ) ^ k1
```

A line collision between two round-2 bytes is `top6(x2[j] ^ x2[j']) == 0`, and for
two bytes in the same column the MixColumns rows share their inputs, so

```
x2[4c+r] ^ x2[4c+r'] = XOR_m ( M[r][m] ^ M[r'][m] ) . S( P[d_m] ^ k0[d_m] )
                       ^ ( k1[4c+r] ^ k1[4c+r'] )
```

with `d_m` the diagonal above. The `k1` term is one unknown byte, and since the
condition only needs its top 6 bits, it is a 6-bit nuisance target `T` per
pair. Note four of the six row-pairs have a vanishing MixColumns coefficient
(`[2,3,1,1]^[1,2,3,1] = [3,1,2,0]`, etc.), so they involve only 3 key bytes  - 
worth exploiting if the 4-byte search ever gets tight.

### Decryption (chosen or known ciphertext)

Identical in structure; only the primitives change.

```
plain InvCipher (tiny-AES):
    x2 = InvMixColumns( SINV( InvShiftRows( C ^ rk10 ) ) ^ rk9 )

equivalent inverse cipher (mbedTLS, Td tables):
    x2 = InvMixColumns( SINV( InvShiftRows( C ^ rk10 ) ) ) ^ rk9'
         where rk9' = InvMixColumns(rk9)
```

`rk10` is the last encryption round key, so recovering it and inverting the
key schedule gives the master key - the same endpoint as `direction="dec"`. The
diagonal mapping changes because InvShiftRows rotates the other way; derive it
rather than copying the encryption one.

Both forms put the round key either inside or outside the InvMixColumns, which
changes only what the nuisance byte is, not that there is one.

Chosen ciphertext is not required. The attack buckets traces by a predicted
quantity, so random inputs work - which is what the measurements above use. The
chosen-CT capability from a bootloader is useful for *amplification* (an image of
N identical blocks multiplies the deterministic per-block time by N), not for the
cryptanalysis. This is a simplification over the fixed-byte designs in the
Bonneau–Mironov literature and removes their worst problem, which is that holding
15 bytes fixed leaves only 256 distinct blocks whose algorithmic noise is
deterministic and cannot be averaged away.

## Implementation plan

1. `flashattack/round2.py` - `round2_state(blocks, rk, direction)` returning
   the 16 round-2 lookup indices, for both cipher forms. The encryption version
   already exists in prototype (see *Reproduction* below); the decrypt version is
   the main new derivation.
2. `column_score(blocks, timing, rk_candidate, column)` - pool the six
   same-column pairs, bucketing by `(x2[j] ^ x2[j']) >> line_shift` so all 64
   nuisance targets come out of one `bincount`; score with the standardised
   `max-z` form, which behaved best at low trace counts.
3. `solve_round2(blocks, timing, round1_result)` - for each of the 64 shared
   references, solve the four columns independently over their 256 low-bit
   combinations; pick the reference whose four columns agree best. 64 x 4 x 256 =
   65 536 scorings, each a handful of `bincount`s.
4. Wire into `recover_round1_keyspace`'s output so the pipeline is
   round 1 → round 2 → full key, and the `known=` verification pair becomes
   optional rather than required.
5. Hardware validation: a fresh F429 capture with a single-table decrypt
   victim. Everything measured so far is an *encrypt* capture; the decrypt
   analogue is structurally identical but unmeasured, and this repo's standard is
   hardware with controls.

Budget: the algebra and solver are days, given the feasibility results above. The
schedule risk is item 5, not the cryptanalysis.

## Open problems

The 4-table layout does not decompose this way, and this is the real open
question - but it is a search problem, not a signal problem. Measured on the
mbedTLS ECB-decrypt capture (120 k traces), predicting round-2 state with the
true key:

| | same-table pairs (offset ≡ 0 mod 4) | cross-table pairs |
|---|---:|---:|
| round 1 | −3.335 cyc (24 pairs) | −0.044 (96 pairs) |
| round 2 | −2.555 cyc | −0.055 |

So round-2 collisions are there, on the same four families round 1 uses, at about
three quarters of round 1's strength; cross-table pairs are flat in both rounds,
as the separate-flash-region argument requires.

What does not carry over is the decomposition. In a T-table round the four
lookups of a column go to `RT0..RT3` - *different* tables - so same-column
round-2 pairs can never collide, and the pairs that can are
same-row-across-columns, drawing on two diagonals: 8 key bytes, which with
round-1's four group references is 24 + 16 + 6 = 46 bits per relation. A
round-1 x round-2 cross-round pair in the same table is cheaper (1 + 4 key bytes)
but still carries all four group references, ~40 bits. Both are too big for a
direct numpy sweep and would want a GPU or a meet-in-the-middle; neither is
attempted here. Low priority, because a 4-table target with any known
plaintext falls to the ordinary last-round attack (its final round uses the single
256-byte `RSb`, which is exactly why the SNMPv3 and TLS demos work on mbedTLS).

Trace count for the decrypt case is unmeasured. 100 k is the encrypt figure.

Selection bias in the nuisance search is handled but not analysed. Every
candidate gets the same best-of-64 advantage so the comparison is fair, but the
variance it adds is what pushed the 25 k case to rank 31. A likelihood-ratio
score over the 64 buckets would probably beat max-z and lower the trace
requirement; untested.

## Reproduction

Prototypes are kept in [`../research/round2/`](../../research/round2). They are
research scripts, not part of the package or the test suite - run them from the
repo root, and they score against the known key because they exist to answer
"does this work", not to attack anything:

| script | what it establishes |
|---|---|
| `round2_gonogo.py` | round 2 sees the low 2 bits; round-1 control is exactly flat |
| `round2_nuisance.py` | survives unknown `k1`; trace-count curve |
| `round2_solve.py` | pooling all 120 pairs does *not* decompose; reference R is findable |
| `round2_column.py` | the per-column decomposition |
| `round2_power.py` | 25 k fails / 100 k solves - power, not structure |
| `round2_joint2.py` | the full 16384-candidate joint search, rank 0 at 100 k |

The relevant one-liner for any future check is that perturbing only the low 2
bits of a key byte is invisible to round 1 by construction, which makes it a free
control on every round-2 experiment.
