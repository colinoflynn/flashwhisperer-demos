# OSCORE over Ethernet: the AES key of a stock CoAP endpoint

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

Two Nucleo boards on a direct Ethernet cable. One runs an ordinary OSCORE
(CoAP, RFC 8613) server built out of off-the-shelf parts; the other is the
network attacker, and it is [`ethtimer`](../../deps/ethtimer) rather than
anything in this repository. Nothing on the victim is instrumented for the
attack, and nothing the attacker uses is secret: it reads the bytes of the
exchange off the wire and times the victim's turnaround from its own Ethernet
interrupt.

The victim's AES-128 key comes out of 150 000 exchanges, which is about five
minutes of traffic.

## Try it with no hardware

The two captures in [`vectors/`](vectors) are the real measurements, packed so
they fit in a repository. This replays one to a verified key:

```bash
python tools/replay.py demos/oscore_coap/vectors/f429_standard_600k.npz --controls
```

```
   geometry    line_off=12 line_shift=4  (row of a lookup is (x+12)>>4)
   conditioned dt_hw: 150000 traces kept, 2 modes, spread 95.2
   pooled z    -7.44   (the effect, given the key)
   shuffled    +0.75   (control: timing permuted)
   wrong key   -1.39   (control: labels from a key that is not it)
   recovered   ffb14e093c94c9cac9471648b4f98710
   truth       ffb14e093c94c9cac9471648b4f98710
   EXACT  as expected in 4s
```

The vector holds the timing and regenerates the keystream from the key, the
Common IV and the first Partial IV, which is how 600 000 exchanges fit in under
two megabytes. [`host/make_vector.py`](host/make_vector.py) refuses to write a
vector whose keystreams do not reproduce byte for byte, so that compression is
checked rather than assumed. The key is in the vector for that regeneration and
the recovery never reads it.

## The row offset is part of the attack

The S-box in this victim's image sits at `0x0801120c`, which is 12 bytes into
its 16-byte flash row, so the row a lookup hits is `(x + 12) >> 4` and not
`x >> 4`. That number is in [`vectors/f429_standard_600k.json`](vectors/f429_standard_600k.json)
and `tools/replay.py` refuses to run without it.

It is not a detail. Same capture, same conditioning, the same sixteen
offset-3 pairs, scored both ways, vote only:

```bash
python tools/replay.py demos/oscore_coap/vectors/f429_standard_600k.npz \
    --ladder 50000,100000,150000,200000,300000 [--line-off 0]
```

| traces | 50 k | 100 k | 150 k | 200 k | 300 k |
|---|---|---|---|---|---|
| `line_off=12`, what the image says | 7/16 | 11/16 | **16/16** | **16/16** | **16/16** |
| verified | - | - | **EXACT** | **EXACT** | **EXACT** |
| `line_off=0`, the usual guess | 0/16 | 2/16 | 3/16 | 10/16 | 15/16 |

So the right geometry recovers the key outright where the wrong one is still
three bytes in at the same count, and does not get there at twice the traces.
Read the offset off the ELF (`flashleak.row_offset_from_image`) rather than
assuming it, and quote it with any trace count. A rebuild moves it.

## What the two ends are

| | |
|---|---|
| victim | NUCLEO-F429ZI, Cortex-M4 at 180 MHz. `uoscore-uedhoc` over TinyCrypt, lwIP and the HAL out of STM32CubeF4, compiled as they ship. `FLASH_ACR = 0x305`: five wait states, prefetch and the instruction cache on, data cache **off**, which is what ST's own `stm32f4xx_hal_conf.h` for this board leaves it at |
| attacker | NUCLEO-F746ZG running `ethtimer`. It times the turnaround from its own transmit-complete interrupt to its own receive interrupt, in its own clock cycles |
| host | not on the attack link. It builds the OSCORE requests, tells the instrument what to send and what to keep, and collects the records |

```
   host PC --USB--> F746ZG instrument --Ethernet--> F429ZI victim
            control                    the only       OSCORE server
            + records                  attack path
```

The cipher is TinyCrypt's `aes_encrypt`: one 256-byte S-box in flash, no
T-tables. That is the expensive end of the table-layout spectrum, which is why
this demo costs more traces than a T-table victim would.

## Capturing it yourself

`victim/` has NOT landed in this repository yet - the vectors, the host
side and the analysis are here, the firmware port is the next step. What goes
in it is the overlay against STM32CubeF4 and `uoscore-uedhoc` plus a Makefile,
and nothing else; the vendor trees stay under `deps/` and unmodified.

The attacker end needs nothing from here, which is the point of using
`ethtimer`:

```bash
cd deps/ethtimer && tools/fetch_sdk.sh f746 && make -C firmware BOARD=f746
python -m ethtimer.cli --target oscore --n 300000 \
    --ip 192.168.7.20 --gw 192.168.7.1 --victim 192.168.7.10 --out oscore.npz

python demos/oscore_coap/host/make_vector.py oscore.npz \
    --out demos/oscore_coap/vectors/mine.npz --label "my capture"
python tools/replay.py demos/oscore_coap/vectors/mine.npz
```

The capture finishes by encrypting each captured AES input under the victim's
real key and comparing against the captured output, so a capture that verifies
has exercised the request, the reply parse, the window offset and the transfer
at once. A capture that returns nothing is usually the link rather than the
attack, and `--target dns` against any resolver is how to tell those apart -
those two failures look identical from an empty capture.

## How many exchanges

The ladder above, at the right geometry: 150 000 for a verified key. It is one
capture conditioned one way, so that is a rung and not a threshold. At about
500 exchanges a second it is five minutes of traffic.

## The controls

A statistic is not a channel, so the thing that makes this readable is what
happens when the channel is removed and everything else is held:

* the S-box in RAM. [`vectors/f429_ramtables_300k.json`](vectors/f429_ramtables_300k.json),
  `make RAMTABLES=1`: same firmware, same instrument, same security context,
  one changed line, and the build asserts that exactly one line changed. No key,
  and the pooled statistic goes flat. Scored at the leaky vector's own geometry
  rather than at settings picked to make it fail.
* the timing shuffled. Permute the per-trace times and the effect has to
  vanish, which rules out the analysis finding structure in the keystream
  alone.
* the wrong key. Label the collisions with a key that is not the victim's.
  Same.
* the sign. A flash-row collision makes a trace FASTER, so the effect must
  be negative. One-sidedness is a property of the mechanism, and a two-sided
  "signal" is a sign something else is being measured.

## What this does not settle

* It is one victim, one build, one part. The demo says a stock OSCORE
  endpoint on an F429 leaks its key. It says nothing about a part with a data
  cache on, and nothing about a T-table cipher, where the trace count would be
  lower rather than higher.
* Nothing here was measured passively. The attacker chooses when to send
  and reads the Partial IV it put on the wire itself. A passive listener on
  somebody else's OSCORE traffic is a different experiment.
* The replay is arithmetic. It recomputes a recovery from numbers measured
  once, on one bench. It is not a re-measurement, and nothing in `vectors/`
  re-times anything.
* The trace table above is a single draw. A second capture would move the
  rungs; treat 150 000 as the order of magnitude.
