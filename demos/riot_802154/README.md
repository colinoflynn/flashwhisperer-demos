# riot_802154 — RIOT's secured 802.15.4 echo reply, from the air

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

Ping a RIOT node. It answers, and because 802.15.4 link security is on it
encrypts the answer with AES-CCM\*. Time the answers with a second radio and
the AES-128 link key falls out, in about an hour and a quarter of pinging. The
victim is stock RIOT at a pinned commit with **one build flag changed**, which
is the key; there is no probe on it, no debugger, no instrumentation and no
shell command in the capture path.

The attacker's key is the wrong one, so it authenticates **none** of the
replies it is attacking. Its radio hook records each frame before the MIC is
checked, which is the whole shape of the thing: a victim that will never
knowingly accept anything from you still hands you its key.

| | |
|---|---|
| victim | nRF52840-DK, RIOT `f59dcdac`, `ieee802154_security` at its defaults |
| what times it | an nRF52840 Dongle, its own TIMER4 at 16 MHz latched in the radio ISR |
| what came out | the AES-128 link key, verified, from 70 000-ish clean replies |
| what the attacker needs | a radio on the channel and a clock. Not the key, not a probe, not a debugger |

## The route, end to end

```
attacker                                  victim (stock RIOT)
   |                                          |
   |-- ICMPv6 echo request, UNSECURED ------->|  RADIO RX end
   |   FCF 0x61                               |    RX ISR
   |<------------- MAC ACK -------------------|    submac builds the ACK IN
   |   (t_ack)                                |    SOFTWARE, *before* GNRC
   |                                          |    decrypts anything
   |                                          |  netif -> 6lo -> ipv6 -> icmpv6
   |                                          |  ieee802154_sec_decrypt_frame
   |                                          |  build the echo reply
   |                                          |  ieee802154_sec_encrypt_frame  <-- the channel
   |                                          |  CSMA backoff, whole 320 us slots
   |<-- ICMPv6 echo reply, SECURED -----------|  RADIO TX end
       FCF 0x69, aux header in the clear
       (t_reply)
```

The ACK's position is the load-bearing fact. RIOT's nRF52840 submac assembles
and transmits it in software (`drivers/netdev_ieee802154_submac/netdev_ieee802154_submac.c:310-331`)
**before** GNRC calls link-security decryption, so it carries no cipher time —
measured at `r = 0.006` against the victim's own encryption clock — and it does
carry the medium-access delay. That makes it a free common-mode reference, and
§ *Conditioning* spends it.

Everything above the ACK is emitted after processing. That is why the echo
reply carries AES time and the ACK does not, and it is a question to ask per
**observable** rather than per stack.

## The frames

The two frames differ in the header by **one bit**. Printed by
[`host/frame_anatomy.py`](host/frame_anatomy.py) from a capture:

### Request, attacker to victim, unsecured, 96 bytes on the air

```
61dc e4 2300 552bdd16401b10ba 3e3502b9ef15215e
7a33 3a 80 00 eadf afef 0000 7b018d4e 000102...3b
```

| bytes | field | note |
|---|---|---|
| 0:2 | FCF `61 dc` | data frame, **security_enabled 0**, ack requested, PAN compressed, both addresses extended |
| 2 | sequence | |
| 3:5 | PAN id `2300` | 0x0023, RIOT's default |
| 5:13, 13:21 | destination, source | EUI-64, little-endian |
| 21:96 | payload, in clear | 6LoWPAN IPHC `7a 33`, next header `3a` = ICMPv6, type `80` = echo request, code, checksum, identifier, sequence, then the ping data |

### Reply, victim to attacker, secured, 109 bytes

```
69dc d7 2300 3e3502b9ef15215e 552bdd16401b10ba
06 02000000
ed1c4de7636c7c4a6d0b5117842464d4 ... 4553c6a
a2cce03c57f1c256
```

| bytes | field | note |
|---|---|---|
| 0:2 | FCF `69 dc` | **security_enabled 1**. That is the entire header difference |
| 21 | security control `06` | level 6 = ENC-MIC-64, key id mode 0 (implicit key) |
| 22:26 | frame counter `02000000` | **2, little-endian, in the clear** |
| 26:101 | ciphertext | |
| 101:109 | MIC | 8 bytes |

So `len(reply) = 26 + len(payload) + 8`. The five bytes at 21:26 are the
auxiliary security header, and they are why this route is attackable at all:
**the CCM\* nonce is the source EUI-64, the frame counter and the security
level, and the frame carries all three in clear.**

## Why the attacker knows the cipher's output

An ICMPv6 echo reply is its request with two edits: type `0x80` → `0x81`, and
the checksum adjusted by `-0x0100` in ones-complement arithmetic — it wraps at
`0xffff`, not `0x10000`, which is the one place this is easy to get wrong.
Identifier, sequence and every payload byte come back unchanged.

So the attacker writes the reply's plaintext down from the request it sent
itself, XORs it with the ciphertext it heard, and reads the **raw block cipher
output**:

```
A1        = 01 ba101b4016dd2b55 00000002 06 0001
AES_K(A1) = 972f77666385a3e5820b516c85a92ad4      <- plaintext XOR ciphertext
A2..A4    = the same with the block index 2, 3, 4
```

`A_i` is `flags(0x01) || nonce(13) || block index(2)`, every byte public. That
is the strongest position a last-round collision attack can be in: the
quantity it scores against is not a guess about the plaintext, it is the
cipher's own output, known exactly, four blocks per reply.

It also makes **verification free** — a candidate key is checked by encrypting
`A_i` and comparing, with no further traffic. So the offline candidate count is
offline work and nothing else.

## How many AES calls, and how many of them matter

One secured reply costs `1 (B0) + 2 (the 26-byte header, in two blocks) +
ceil(m/16) (CBC-MAC over the plaintext) + 1 (A0, the MIC keystream) +
ceil(m/16) (A1..An)` with `m` the payload length — read off
`sys/crypto/modes/ccm.c:70,139,148,206,215,223`.

| `ping -s` | frame | payload | AES calls | complete CTR blocks | calls the attacker models |
|---:|---:|---:|---:|---:|---|
| 5 | 37 | 16 | 6 | 1 | 1 of 6 |
| 48 | 80 | 59 | 12 | 3 | 3 of 12 |
| **64** | **96** | **75** | **14** | **4** | **4 of 14** |
| 80 | — | — | — | — | fragments at 6LoWPAN, different path, out of scope |

The attacker models the last round of the blocks whose output it knows. The
other ten calls in a 64-byte reply have outputs it cannot predict, so they are
spread with no signal — the same effect that makes a byte-S-box build's rounds
1 to 9 noise for a last-round attack.

**So the currency is observations, frames times blocks scored, and an
observation does not transfer between arms.** Scoring one block of a
four-block reply leaves the other three blocks' last rounds as noise in the
very same measurement: 220 000 such observations recovered nothing where
280 000 that model all four of theirs gave the key. Pick the payload size so
the reply divides into blocks you can predict, and score all of them.

## Where the channel is

RIOT's default AES build has **no `Te1`..`Te4` at all**. `sys/crypto/aes.c:149-155`,
under `#ifndef MODULE_CRYPTO_AES_PRECALCULATED`, defines all five table macros
in terms of `Te0`, including

```c
#define Te4(n)  (((Te0[n] & 0x00FFFF00) >> 8) | ((Te0[n] & 0x00FFFF00) << 8))
```

so the last round reads the same 1 KB table. Its entries are 4 bytes and the
nRF52840's flash read latch is one 16-byte row, which gives `line_shift = 2`;
`line_off` is wherever the linker happened to put the table inside its row and
**you must read it off your own ELF** — `victim/verify_build.py` does, and on
the build this demo's vector came from it is **2**, not the 0 an earlier image
of the same source happened to have.

### The compiler hoists the last round, and the attack finds that out by itself

`aes.c:1296-1330` reads sixteen table entries and recombines them. The compiler
does not emit them there: disassembling `crypto/aes.o`, all sixteen
`ldr.w rX, [r3, rY, lsl #2]` loads are **hoisted into the round-9 body**, their
results parked in registers and at `[sp,#8]`..`[sp,#44]`, and the code after
the loop exit only masks, XORs and stores. Mapping each load to the ciphertext
byte it feeds gives the emitted order

```
ct[0] ct[4] ct[1] ct[3] ct[2] ct[5] ct[6] ct[7] ct[8] ct[9] ct[12] ct[10] ct[11] ct[13] ct[14] ct[15]
```

which is neither the source order nor anything a reader would guess. A depth-1
row buffer can only serve reads that are **adjacent in that stream**, so only
its fifteen consecutive pairs should leak. Scoring all 120 output-byte pairs
and ranking them by their own **blind** z-margin — no key involved — the top
fifteen came out as exactly those fifteen pairs, member for member, margins
6.24 to 10.29 with the next pair at 5.20, covering all sixteen key-byte
positions.

So **the attack reads the compiler's instruction schedule off the air**, and
nothing has to preselect a pair set. Which is just as well: the obvious
preselection, the 24 intra-column pairs, is the wrong 24 here — it cannot
express `(7,8)`, one of the strongest leakers, and twelve of its members are
not adjacent in this stream and measure nothing.

## Conditioning, which is what decides whether this works at all

The attacker's interval is reply END minus request END on its own 16 MHz timer,
so one tick is 62.5 ns — **4 CPU cycles on the victim**, against roughly 11
cycles of data-dependent spread in an 18 360-cycle call. The signal is well
under the instrument's resolution per frame and only averaging recovers it.

Two nuisance terms sit in that interval. Both are visible to the attacker,
neither is key-dependent, and leaving them in is what makes this capture look
like a null:

**The CSMA slot keeps its own offset.** Backoff is drawn in whole
`aUnitBackoffPeriod` units, so the interval is quantised rather than
continuous. Subtracting `320 µs × round((reply − min) / 320)` removes the
*nominal* period, not the realised one, and leaves each slot a residual offset.
Median-centre within (capture file, slot) instead.

**The reply shares its medium access with the ACK.** Regress the ACK interval
out — and **fit that coefficient per frame shape**. A longer reply has both a
longer reply time and a longer ACK, so one coefficient across mixed payload
sizes estimates the between-size relation instead of the within-size common
mode: on a 48/64-byte mix the global fit took the timing's SD from 1.20 µs to
**7.09 µs** and returned 0/16, which is worse than not fitting it at all.
Fitting per capture file is the opposite error, about 200 frames per
two-parameter fit, and that noise alone cost a single-size rung 16/16 by vote
down to 13/16 plus a 1 992-key walk.

Measured on the campaign's 182 004-frame capture, as a diagnostic with the key:

| timing fed to the surfaces | SD | predictor | vote |
|---|---:|---:|---:|
| slot-adjusted, centred per capture file | 0.807 µs | −0.0157 | 3/16 |
| centred per (file, CSMA slot) | 0.464 µs | −0.0309 | 13/16 |
| ACK regressed out, centred per file | 0.739 µs | −0.0178 | 6/16 |
| **both** | **0.335 µs** | **−0.0447** | **15–16/16** |

## What this re-run measured

A fresh random key, a victim rebuilt from the pin with nothing but that key
changed, and the attacker board untouched.

| | |
|---|---|
| key, generated just before the run | `96be93b552fa3ad3f5da80d9437b6a92` |
| victim image | sha256 `6d607d66edd5f09750d69bae3c68860599ed2cf54a67a40070c82a4362de1de3` |
| `Te0` | `0x0000f5f8`, so **`line_off = 2`** |
| capture | 120 000 probes, about 1 h 40 min at 20.5 probes/s |
| clean replies | 80 380, or 67.1 % |
| **recovered** | **the key, from 60 000 clean replies, 16 of 16 bytes from the vote alone and no search** |

60 000 clean replies is about **89 400 probes, 73 minutes of pinging**. The
trace table, vote only, straight off the shipped vector:

| clean replies | observations | round-key bytes from the vote |
|---:|---:|---:|
| 10 000 | 40 000 | 2/16 |
| 20 000 | 80 000 | 2/16 |
| 40 000 | 160 000 | 7/16 |
| 50 000 | 200 000 | 14/16 |
| **60 000** | **240 000** | **16/16** |
| 79 631 | 318 524 | 16/16 |

```
$ python tools/replay.py demos/riot_802154/vectors/nrf52840_newkey_80000.npz --controls
   geometry    line_off=2 line_shift=2  (row of a lookup is (x+2)>>2)
   pooled z    -7.97   (the effect over the 120 pairs, given the key)
   shuffled    -1.62   (control: timing permuted)
   wrong key   -0.71   (control: labels from a key that is not it)
   recovered   96be93b552fa3ad3f5da80d9437b6a92
   truth       96be93b552fa3ad3f5da80d9437b6a92
   EXACT  as expected in 27s
```

### Controls

| control | result |
|---|---|
| timing shuffled, two seeds | 0/16 and nothing in 2^20 candidates |
| labels from a wrong key | pooled z −0.71 against the real −7.97 |
| **the row offset, swept** | `line_off` 0, 1, 3 give 5/16, 6/16, 7/16 against **16/16** at 2 |
| one CTR block per reply | 3/16 and no key, at the same 76 380 replies |
| the control vector | `nrf52840_newkey_20000`, the same capture truncated, no key |
| holdout | 3 996 of 4 000 replies the surfaces never saw reproduce under the recovered key |

The row-offset sweep is the one to look at twice. This build's table is 8 bytes
into its row and the campaign's earlier build of the same source had it
row-aligned; at the wrong offset this capture reads as a half-recovery that
never closes.

### The conditioning, on this capture

| timing | round-key bytes | key |
|---|---:|---|
| centred per capture file only | 1/16 | no |
| per (file, CSMA slot) | 9/16 | no |
| ACK regressed out per shape, per file | 3/16 | no |
| **both** | **16/16** | **yes** |

**Neither term alone is enough here**, which is a difference from the
campaign's own capture, where conditioning on the slot alone reached 13/16 and
closed with a 971-key walk. Same analysis, same victim source, a different
build and a different table offset. So treat the ablation as something to run
on your own capture rather than a constant: what does not change is that
leaving both terms in reads as a null.

### Where the capture's replies went

| | |
|---:|---|
| 21 395 | missing, retried, or later than 10 ms |
| 18 069 | unexpected frame shape |
| 3 | ambiguous captured frames |
| 749 | clean, but the predicted reply plaintext did not regenerate (0.93 %) |
| **79 631** | in the vector |

That last row is worth a word. The extractor writes the reply's plaintext down
from the request, and on an odd frame it is wrong -- a different 6LoWPAN
compression, or an ICMP body that did not come back byte for byte. It costs
under a percent of the traces here and 0.09 % on the campaign's capture, and it
is the prediction missing rather than anything about the key. `make_vector`
refuses to pack a reply that does not regenerate, so the vector holds only the
ones that do.

## Running it

```bash
./deps/fetch.sh riot
python demos/riot_802154/victim/gen_key.py             # writes it down for you
cd demos/riot_802154/victim && ./build.sh && make flash BOARD=nrf52840dk
# note the victim's link-local address from its own ifconfig, once
cd ../../.. && python -m demos.riot_802154.host.capture \
    --target fe80::... --count 120000 --prefix captures/riot_802154/run
python -m demos.riot_802154.host.recover captures/riot_802154/run_*.jsonl \
    --blocks 1 2 3 4 --line-off <from verify_build.py> --frames 90000
```

Or with no hardware at all:

```bash
python tools/replay.py demos/riot_802154/vectors/<vector>.npz --controls
```

The victim is [`victim/`](victim) and builds with no change to RIOT; the
attacker is [`../../instruments/riot802154_stamp`](../../instruments/riot802154_stamp)
and is the one place a RIOT source file is patched, by a script that keeps the
original bytes. [`victim/OPTIONAL_DWT_PATCH.md`](victim/OPTIONAL_DWT_PATCH.md)
is the victim-side cycle counter, which the attack does not use.

## What did not work, and what this does not establish

* **One CTR block per reply.** 6/16 at 182 000 frames and no key. The 5-byte
  echo shape is not a smaller version of this one.
* **The 48-byte echo on its own.** 9/16 at 26 000 clean replies, 78 000
  observations, no key. Its per-frame correlation is actually the best of the
  three sizes at −0.0550; it simply does not have the observations.
* **Pooling sizes with one global ACK coefficient.** 0/16, worse than either
  size alone, for the reason in § *Conditioning*. With the coefficient fitted
  per shape the 48+64 pool recovers outright, but it spends 250 250 probes to
  do what 85 000 of the 64-byte shape does, so it is a confirmation and not a
  cheaper break.
* **Four earlier capture extensions.** The campaign took this capture to
  220 000 probes across four runs and wrote it down as a null with "a weak
  key-related component". The channel was there the whole time. That is the
  lesson worth carrying: *before adding traces to a transport-boundary null,
  ask what else is in the interval that the attacker can see and the cipher did
  not put there.*
* **Not byte-identical stock RIOT.** The key is a build flag, so the image is
  not one anybody ships, and the attacker's RIOT carries a radio hook. The
  cipher, the link-security module, the radio driver and the compiler's output
  are the pin's.
* **No SRAM control vector here.** The table-in-RAM arm is the control that
  speaks to the mechanism, and this re-run did not re-take it; the campaign's
  numbers for it are quoted in [`victim/README.md`](victim/README.md) and are
  not in this repository's vectors.
