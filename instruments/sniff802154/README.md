# sniff802154: the third board, and what it costs to be one

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

The listener for `demos/ota_802154`. It is a NUCLEO-L152RE with an
X-NUCLEO-S2915A1 shield sitting on the same 915 MHz link as the two legitimate
nodes, timing two on-air edges per exchange with its own cycle counter:

```
r_data   end of the data frame        t_ack   sync-word detect on the ACK
```

and printing one line per paired record, at 921600:

```
S <r_data> <t_ack> <len> <hex of the first MPDU bytes> <drops> ...
```

The victim decrypts between those two edges, so that interval is the oracle.
Nothing is attached to either legitimate node.

## Build it

The listener is ST's own `CUSTOM_FIFO_RX` example with four files replaced, so
that is what this directory ships - the four files, not a copy of ST's project.

```bash
./deps/fetch.sh x-cube-subg2
instruments/sniff802154/stage.sh deps/x-cube-subg2
instruments/sniff802154/diff_vs_stock.sh deps/x-cube-subg2 --stat
```

`demos/ota_802154/victim/build_rig.sh` does the staging and the build for you,
for both the L152RE and the F401RE. One application source builds for either
board; only the BSP header differs, picked with `__has_include`. `SNIFFER_BOARD`
overrides the default.

| file | changed lines | what it is for |
|---|---:|---|
| `Src/app_custom_s2lp_fifo_rx.c` | 799 | the listener itself: receive, stamp, pair, print |
| `Src/stm32l1xx_it.c` | 9 | the DWT stamp in the radio's EXTI handler |
| `Src/stm32l1xx_nucleo.c` | 5 | LD2 on PA5, which the shield leaves free |
| `Inc/s2lp_radio_settings.h` | 30 | band and rate as `-D`-overridable defaults |

## Pairing is exact, not heuristic

`csma.c` builds the soft ACK as `{ FRAME802154_ACKFRAME, 0, hdrptr[2] }`, and
byte 2 is the acknowledged frame's 802.15.4 sequence number. So the listener
pairs on that rather than on "the next 3-byte frame", and a dropped frame, a
retransmission or the victim's own traffic produces *no* pair rather than a
wrong one. Unpaired data frames are counted separately from ring overflows,
because a listener missing ACKs and a UART that cannot keep up need different
fixes.

LD2 blinks once per *paired* record, deliberately not per frame received, so a
dark LED on a live network means the pairing is broken rather than the radio.

## What being a real listener costs

Measured against the victim's own stamps, joined on the 802.15.4 frame counter
so the two instruments are looking at the same frame rather than at comparable
populations:

| | median | robust sd |
|---|---:|---:|
| victim, its own DWT | 1226.25 µs | 0.60 µs |
| listener, `r_data -> t_ack` | 2755.8 µs | 1.90 µs |
| listener, `sync -> sync` | 4586.2 µs | 2.04 µs |

Listener-added noise is the residual about a fit of the listener's gap against
the victim's: 1.38 to 1.75 µs depending on the bench, which is a **6x to 9x
trace penalty** for being outside the victim rather than inside it. Frame yield
96 to 98 %. The spread in that range is real and it is thermal: the first
calibration of a session, on a cold bench, reported 4.7x, and the same rig half
an hour later reported 9.3x. Calibrate when the bench has settled, or quote the
range.

`r_data -> t_ack` is the quietest observable in every run, which is also the one
the mechanism predicts: the victim starts its decrypt when the data frame ends
and stops when it keys up the ACK, so that pair is the tightest bracket around
the cipher. Timing `sync -> sync` instead measures 30 to 45 % worse.

## The noise is the attacker's receiver, not the link

The listener also reports two intervals with no signal in them at all - each is
one frame's airtime measured end to end by the listener alone, with the
victim's cipher nowhere in it:

| interval | median | robust sd |
|---|---:|---:|
| ACK airtime, 3-byte frame | 195.4 µs | 46 to 93 ns |
| data airtime, 54-byte frame | 1830.3 µs | 510 to 741 ns |

46 ns is 1.5 cycles of the listener's own 32 MHz clock, so within a single frame
the two edges are quantisation-limited. Any interval spanning *two* frames
scatters by about 1.9 µs, forty times worse. An offset common to a frame's two
edges cancels inside that frame and does not cancel between frames, so the
dominant term is a per-frame common-mode offset in the receiver, roughly 1.2 to
1.4 µs, and the obvious suspect is how long the S2-LP's bit-clock and AFC
recovery take to settle before the sync word.

Three things follow, and the first is the one that matters for reading any
trace count here:

* It is not the link. Sigma is flat across a 6.5x sweep of the data rate, which
  this explains: a fixed number of *symbols* of lock time is a fixed number of
  microseconds only if the rate does not change the lock behaviour, and raising
  the rate does not make the recovery loop settle in fewer symbols. So the
  penalty is the attacker's equipment, and a better receiver moves it.
* It is not the clock or the core. 46 ns on a short frame rules out timer
  resolution, ISR latency and dispatch jitter, which would apply to both frames
  equally. The 84 MHz F401 core buys nothing in this seat.
* It is random per frame, so it averages as sqrt of the repeat count - which is
  what makes Contiki-NG's missing anti-replay check interesting, since a
  replayed frame is ACKed again.

## Which part should be the listener

Decided by measurement rather than by expectation, back to back on the same
cold bench. Only one L152RE was on hand, so the listener and the coordinator
had to swap together; the ACK-airtime diagnostic is what makes the comparison
interpretable, because the ACK always comes from the same victim board.

| | listener | coordinator | sigma_add | penalty | yield | gain | ack air |
|---|---|---|---:|---:|---:|---:|---:|
| A | L152RE | F401RE | 1381 ns | 6.3x | 97.7 % | 0.993 | 92.7 ns |
| B | F401RE | L152RE | 1483 ns | 7.1x | 91.5 % | 0.925 | 105.9 ns |

A wins on every axis and the two diagnostics say why independently: the L152 is
the marginally quieter receiver, 92.7 against 105.9 ns on the same transmitter,
and the F401 is the substantially cleaner transmitter, 649 against 865 ns of
data-airtime sd. The expectation had been the opposite, that the instrument
should be the faster part.

## Capture

```bash
python instruments/sniff802154/capture.py --port COM25 --log passive.log \
    --n 3000000 --wall 86400
```

It appends, so an interrupted run continues into the same log and
`demos/ota_802154/host/campaign.py` can read the file while it grows. 2.6
million records is about 500 MB of text and 21 hours of listening at 40
records/s.

**NOTE:** check a fresh capture before leaving it running. A debug probe clears
`DEMCR.TRCENA` on disconnect and that freezes `DWT->CYCCNT`, so every interval
comes out exactly zero while the stamps stay plausible - the log looks healthy
and the sigma looks wonderful. `host/logread.py` refuses a capture whose
turnaround is constant, which is the backstop rather than the check.

## What this instrument is not

It never learns the key, and `verify_build.py` in the demo checks that the key
is absent from the listener's image. It also has no part in the recovery: it
produces a log, and everything that reads one is in the demo.
