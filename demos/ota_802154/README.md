# 802.15.4 over the air: the link key, from a third board

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

A NUCLEO-F401RE with an X-NUCLEO-S2915A1 shield runs X-CUBE-SUBG2's Contiki-NG
stack with link-layer security on, as ST ships it. A second one generates
traffic. A third board a few feet away transmits nothing at all: it listens to
the link and times how long the victim takes between the end of a data frame
and its acknowledgement, which is the interval the AES-CCM* decrypt happens in.
The network-wide AES-128 LLSEC key comes out of about 2.5 million frames, which
is 17 hours of listening on the faster of the two links here and 20 on the
slower one.

The result this demo carries is the blind one. The key was chosen and flashed
by someone else, it was never on the analyst's machine, and it was learned from
the recovery rather than used in it. Nothing was attached to either legitimate
node: the victim's console is silent by default, its image contains no
instrumentation, and `victim/verify_build.py` is what checks that rather than
asserting it.

## Try it with no hardware

```bash
python tools/replay.py demos/ota_802154/vectors/f401_blind_2500k.npz --controls
```

```
   victim      STM32F401RE, X-CUBE-SUBG2's Contiki-NG over the S2-LP radio, ...
   geometry    line_off=4 line_shift=4  (row of a lookup is (x+4)>>4)
   conditioned turnaround: 2500000 traces kept, high-pass 33 modes, spread 40.0
   pooled z    -34.31   (the effect over the 120 pairs, given the key)
   shuffled    +0.00   (control: timing permuted)
   wrong key   +1.02   (control: labels from a key that is not it)
   note        vote got 16/16 round-key bytes (validation only)
   note        true-byte ranks [1, 1, 1, ...], 0.0 residual bits (validation only)
   note        verified straight from the vote, 1 candidate key
   recovered   deadbeefcafeface1133710551223945
   EXACT  as expected in 32s
```

Half a gigabyte of listener log is 3.9 MB of vector, because almost none of it
is irreducible. The AES output block the attack reads is `AES(K, A_1)` and
`A_1` is built out of the frame counter, the source EUI-64 and the security
level, all of which the frame carries in the clear - so every block regenerates
exactly from the key and the counters, and `host/make_vector.py` refuses to
write a vector whose blocks do not come back byte for byte. What is left is one
measured turnaround per frame.

## What the three boards are

| | |
|---|---|
| victim | NUCLEO-F401RE + X-NUCLEO-S2915A1. X-CUBE-SUBG2's Contiki-NG, `csma` with LLSEC at security level 5, built from `STMicroelectronics/x-cube-subg2 @ 277e8c1b` plus `victim/rig.patch`: 62 added lines across 4 files, zero deletions, every hunk an `#ifndef` or a new `#ifdef`. `FLASH_ACR = 0x00000702` |
| coordinator | the same board, sending a 24-byte payload every 20 ms. Freely modified, since it is only a traffic source |
| listener | NUCLEO-L152RE + X-NUCLEO-S2915A1 running [`instruments/sniff802154`](../../instruments/sniff802154), timing `end of data frame -> ACK sync` in its own 32 MHz cycles |

The cipher is Contiki-NG's `aes-128.c`, which is a byte-oriented
implementation with a 256-byte S-box and no T-tables, so the last round reads
`sbox` sixteen times and that is the table the attack is about. CTR mode hands
the attacker the AES *output* for free: the payload is plaintext XOR keystream,
and the keystream block is the cipher's output.

## What it costs

| | stock capture | blind capture |
|---|---:|---:|
| frames heard | 2 686 000 | 2 643 500 |
| listening time | 18.2 h | 21.4 h |
| frames per second, averaged over the capture | 41.0 | 34.3 |
| log on disk | 0.50 GB | 496 MB |
| usable frames at MPDU 54 | 2 679 616 | 2 625 106 |
| median turnaround | 87 621 listener cycles | 87 785 |
| robust sd of the turnaround | 65.2 cycles, 2.04 µs | 65.2, 2.04 µs |
| and after the high-pass | 46.0, 1.44 µs | 40.0, 1.25 µs |
| key recovered at | 2 400 000 frames | 2 500 000 frames |

The blind run's link was deliberately worse: the boards were separated, the
instantaneous rate fell as low as 20.5 frames a second against the other
capture's 40.7, and 8 % rising to 15 % of data frames never paired with an ACK.
It cost 4 % in frames. So a worse link costs listening time and little else,
which is worth knowing because link quality is the thing a deployment is most
likely to vary.

The cipher is about 47 % of what the listener measures. That is not an
estimate: with security the only variable, the same generator and the same code
path, the victim's own turnaround goes from 51 855 cycles unsecured to 102 542
secured, and the extra 9 bytes of aux header and MIC account for about 2 050 of
the 50 687. So roughly 48 600 cycles, 579 µs, of AES-CCM*, which for the ~8 AES
calls of a 54-byte frame is about 6 000 cycles per block - slow for AES and
entirely plausible for a byte-oriented implementation doing 160 S-box lookups
and an arithmetic MixColumns.

## The trace ladder

Vote and search on the blind capture, at the row offset its image has. The unit
is (frames, candidate keys), because a byte count cannot tell a near miss from
a recovery:

```bash
# the vote column, in one pass
python tools/replay.py demos/ota_802154/vectors/f401_blind_2500k.npz \
    --ladder 1200000,1600000,2000000,2500000
# and one rung with the search behind it
python tools/replay.py demos/ota_802154/vectors/f401_blind_2500k.npz --n 1600000
```

| frames | listening | round-key bytes from the vote | residual search | candidate keys | key |
|---:|---:|---:|---:|---:|---|
| 500 000 | 4 h | 1/16 | 76.0 bits | 5.1 M tried | no |
| 1 200 000 | 10 h | 11/16 | 16.1 bits | 5.1 M tried | no |
| 1 600 000 | 13 h | 13/16 | 8.6 bits | 1.3 M | yes |
| 2 000 000 | 16 h | 15/16 | 1.0 bits | 64 | yes |
| 2 200 000 | 18 h | 16/16 | 0.0 bits | 1 | yes |
| 2 500 000 | 21 h | 16/16 | 0.0 bits | 1 | yes |

The listening column is this capture's own average of 34.3 frames a second.
The residual-search column is the product of the true bytes' ranks: it needs
the key, so it is validation rather than attack, and it is a lower bound on
where a search finds the answer rather than where it does.

Below about 1.6 million frames the vote is wrong on more bytes than the
escalation covers, and the honest answer there is more frames rather than more
CPU. The campaign that took these captures bisected the threshold to between
2.28 M and 2.30 M frames with its own search, so re-scoring moved it down by
roughly a third.

## Re-scoring the same data took the search from 760 million candidates to one

This is the one number in this demo that is not a measurement of the victim.

The campaign scored the output-byte pairs that are two reads of one state
column - four row pairings, four columns each - took the joint `(ga, gb)`
argmin of every one, and searched a disjoint cover of eight of them. That cover comes out lopsided on a passive capture - seven
edges essentially solved and one at rank 435 - and total-score order then
grinds through every tuple that trades a cheap worse candidate for an expensive
better one. The first key-free recovery from the air needed **59.1 million**
verified candidates and 80 minutes of CPU at 2.4 M frames; the blind one needed
**763.9 million** at 2.5 M, which took a threaded AES-NI searcher in C to run
at all, and would have been missed entirely by a candidate depth of 512.

Scoring all 120 pairs instead, standardising each surface and summing what each
one says about each byte on its own, constrains every byte with the fifteen
pairs it appears in rather than with one. On the blind capture at 2.5 M frames
that puts all sixteen round-10 bytes at rank 1: **one** candidate key, settled
by one AES block, 32 seconds of arithmetic. The stock capture is 13 of 16 from
the vote and takes about 560 000 candidates at 2.4 M frames, against 59.1
million for the same data.

Two things worth saying about that. The mean along the other byte, which is the
obvious way to marginalise, is much worse than the minimum - 3 of 16 bytes at
rank 1 against 16 of 16 on the same capture - because averaging dilutes one
good cell into 255 bad ones. And the older search is still here, in
`host/recover.py` as `cover_search()`, because it is what the published numbers
were measured with and because it is the fallback when the byte evidence comes
out flat.

## The row offset is the whole ballgame

`static const uint8_t sbox[256]` carries no alignment attribute, so GCC gives
the section 4-byte alignment on ARM and the table starts somewhere in its
16-byte flash row. The row a lookup hits is `(sbox[x] + line_off) >> 4`, and a
256-byte table at a non-zero offset spans seventeen rows rather than sixteen.
Measured on the blind capture at 2.5 M frames, vote only, nothing else changed:

```bash
python tools/replay.py demos/ota_802154/vectors/f401_blind_2500k.npz \
    --line-off 0 --vote-only
```

| `line_off` | 0 | 4 | 8 | 12 |
|---|---:|---:|---:|---:|
| round-key bytes at rank 1 | 2/16 | **16/16** | 3/16 | 0/16 |
| residual search, bits | 67.0 | 0.0 | 44.1 | 100.2 |

The sweep is unimodal and the timing recovers the linker's placement on its
own. The two captures here are the same sources built with different keys and
they land on 4 and on 12, so this is link-order luck rather than a property of
the part - and `aligned(16)` is not a mitigation, since it moves the offset to
0 and sixteen equal rows is if anything cleaner for the attacker. An attacker
needs none of this: four offsets, keep whichever verifies, about 30 seconds
each.

A rebuild of these sources with the blind key and gcc 10.3.1 lands the S-box at
`0x08017ce4`, which is offset 4 - the offset the capture was taken at. The
original build tree was ephemeral, so that is a reproduction rather than the
same ELF, and `victim/build_rig.sh` prints the offset of whatever you build.

## The instrument is part of the measurement

The listener's own receive chain contributes 1.4 to 1.7 µs of per-frame noise
against the victim's own 0.6 µs, which is a 6x to 9x penalty in traces for
being outside the victim rather than inside it. That is the attacker's
equipment and not the link: sigma is flat across a 6.5x sweep of the data rate,
and within a single frame the listener's two edges agree to 46 ns, which is 1.5
cycles of its own clock. So the frame counts above are an upper bound that a
better receiver moves, and
[`instruments/sniff802154/README.md`](../../instruments/sniff802154/README.md)
has the calibration.

## The controls

* the timing shuffled: `+0.00`. Permute the per-frame times and the effect has
  to vanish.
* the wrong key: `+1.02`. Label the collisions with a key that is not the
  network's and it also has to vanish.
* the sign: a flash-row collision saves an access, so a colliding frame must be
  FASTER. `-34.31` is negative.
* the row offset: the sweep above. A channel that is an artefact of the
  analysis would not be unimodal in a property of the victim's image.
* half a million frames of the same capture:
  [`vectors/f401_blind_500k.json`](vectors/f401_blind_500k.json) is shipped as
  a control that must stay silent, and it does - pooled z `-15.15`, which is
  enormous, and no key in the 5.06 million candidates the escalation tries. A
  statistic is not a channel. Run the recovery.

The two controls the campaign actually took cannot be replayed here and saying
so is more useful than shipping one that looks like evidence. The first is the
unsecured-traffic arm, which is the experiment that isolates the cipher and is
where the 47 % above comes from; with security off there is no keystream to
read and the payload does not vary, so the attack has nothing to score. The
second is the listener calibration, which has no cipher in it at all. Both are
numbers rather than vectors.

## Capturing it yourself

```bash
./deps/fetch.sh x-cube-subg2
demos/ota_802154/victim/build_rig.sh --key 000102030405060708090a0b0c0d0e0f
# flash out/victim, out/coord and out/sniffer; both Contiki nodes come up on
# power alone, and only the listener's console has to be read

python instruments/sniff802154/capture.py --port COM25 --log passive.log \
    --n 3000000 --wall 86400
python demos/ota_802154/host/campaign.py --log passive.log \
    --elf build/ota_802154/out/victim/S2915A1_UDP_Client.elf \
    --ladder 500000,1000000,1500000,2000000,2500000,3000000

python demos/ota_802154/host/make_vector.py passive.log \
    --out demos/ota_802154/vectors/mine.npz --key 000102030405060708090a0b0c0d0e0f \
    --listener-hz 32e6 --label "my capture"
python tools/replay.py demos/ota_802154/vectors/mine.npz
```

`host/monitor.py` is the progress meter for the hours in between, and it needs
no key: every round-10 byte is covered by two of the four attackable pair sets,
so "how many bytes do their two estimates agree on" is a self-contained signal
with a chance expectation of 0.06 bytes out of 16. Be careful what you read
into it. It is conservative, and on one run it stood at 7 of 16 while 15 of the
16 bytes were already right in at least one pair set.

## What this does not settle

* The traffic shape is an assumption about the deployment, not an attacker
  capability. A 24-byte payload every 20 ms is a "device reports periodically"
  model; a passive attacker cannot make a device transmit. 24 bytes happens to
  be the measured optimum for a listener, beating both 16 and 48, so there is
  nothing to tune there.
* The known plaintext is a generator pattern rather than real 6LoWPAN headers.
  Real headers are equally known to anyone who has read the RFC, but this
  capture does not demonstrate that.
* It is one part, one stack, one radio and two captures. Nothing here says
  another 802.15.4 stack leaks, or that a hardware AES engine on the same radio
  shield would.
* The threshold is a rung on a ladder, not a floor. Both searches here improved
  on the one before and the threshold moved each time; the only honest
  statement is the pair (frames, candidate keys) at a stated row offset.
* Contiki-NG's CSMA LLSEC has no anti-replay check and a replayed frame is
  acknowledged again. The listener's dominant noise is random per frame, so
  repeating one frame and averaging would reduce it as sqrt of the repeat count.
  That is the largest untested lever here, and it would also make the attacker
  active, which is a different threat model from the one this demo is about.
