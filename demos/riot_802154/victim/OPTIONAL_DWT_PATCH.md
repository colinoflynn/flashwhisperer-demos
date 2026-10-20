# Optional: time the cipher on the victim itself

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

**The attack does not use this and the capture host never reads it.** The demo's
numbers, its vector and its recovered key were all taken from a victim built
without it. It is here because "is the effect there at all, before I try to see
it from the air" is a reasonable first question and a far easier measurement,
and because a reader should be able to tell which of this demo's numbers came
from the victim's own clock and which came off the radio.

What it adds: a linker-wrapped `ieee802154_sec_encrypt_frame` that records DWT
cycles and the public frame counter into a ring, and a `cryptodump` shell
command to read the ring out. It adds **no AES calls** and prints nothing on
the send path.

## Adding it

Two lines in [`Makefile`](Makefile):

```make
SRC += optional_dwt/crypto_stamp.c
LINKFLAGS += -Wl,--wrap=ieee802154_sec_encrypt_frame
```

Then rebuild, and after a run of pings:

```
> cryptodump clear
> cryptodump dump
crypto count=250 freq=64000000
0,2,18361,75,0
1,3,18357,75,0
...
```

The columns are index, frame counter, DWT cycles across the call, payload size
and RIOT's return code. On the measured build that is a mean near **18,360
cycles** with a spread of about **11 cycles** over roughly 32 distinct values,
for the 64-byte echo's fourteen AES calls.

## Why it is not in the attack

Because it is the victim's clock, and the claim is about the attacker's. The
two differ by more than convenience:

* The internal measurement has about **11 cycles** of data-dependent spread on
  an 18,360-cycle call. The attacker sees that through 0.93 µs of radio spread
  before conditioning, and 0.33 µs after, on a timer whose tick is 62.5 ns --
  which is 4 CPU cycles. The attacker's instrument is coarser than the whole
  signal, and only averaging recovers it.
* It makes the victim non-stock. Everything else in this demo is RIOT's own
  bytes at the pin, and keeping it that way is most of the point.

So the honest use of this file is as a **ladder**: wrap the call, confirm the
spread exists and tracks the collision model, then take the wrapper out and go
and find the same thing from the air. If you only ever measure it on the
victim, you have measured a cipher and not an attack.

## The one number it is load-bearing for

The campaign used it for the pairing diagnostic that says the radio interval
really does track the cipher: over 181,986 paired frames, radio time against
internal encryption time is `r = 0.238`. That is a check on the measurement,
run after the radio-only attack had already finished, and it is the kind of
thing this wrapper is for.
