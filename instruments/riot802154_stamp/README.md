# riot802154_stamp — the 802.15.4 instrument

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

The attacker for [`demos/riot_802154`](../../demos/riot_802154). A RIOT node on
an nRF52840 Dongle that sends ICMPv6 echo requests in the clear and timestamps
every radio frame it sees, so the host can measure how long the victim took to
answer.

Like `ethtimer`, it knows nothing about the attack. It sends probes, it records
instants and frame bytes, and the protocol knowledge lives in the demo's
`host/`.

## What it measures, and why not DWT

TIMER4 free-runs at 16 MHz — one tick is 62.5 ns — and keeps counting while the
core sleeps between radio interrupts. The DWT cycle counter does not, which on
a node that idles between probes makes every interval it reports wrong by
however long the core was asleep.

**The instant is latched in hardware.** `main.c` points PPI channel 18 at
`RADIO->EVENTS_END` with `TIMER4->TASKS_CAPTURE[0]` as the task, so the capture
register is written by the PPI the moment the frame ends. The ISR hook only
reads `CC[0]` afterwards, so interrupt scheduling jitter never reaches the
number. That is worth saying because the obvious implementation — read the
timer in the ISR — puts the ISR's own latency into the measurement, and on this
victim the whole signal is a few cycles.

For each frame the ring records the latched tick, the direction, the length,
the first two FCF bytes, the sequence number, the CRC status, and for the
request and the secured reply the frame bytes themselves. So every interval the
host derives can be audited against the direction and the security bit rather
than trusted.

The ring is 64 records; the host arms it, sends one probe and reads it back, so
a campaign is a long sequence of small shell exchanges at about 19 probes a
second.

## The one patch, and why it is here rather than in the victim

RIOT's radio driver owns the RADIO interrupt, so a hook has to go in it.
[`patch_riot.py`](patch_riot.py) inserts one `extern` declaration and one call
into `cpu/nrf52/radio/nrf802154/nrf802154_radio.c`, **checks its source anchors
first and refuses a driver that does not match**, keeps the original bytes in a
backup beside the file and takes `--restore`.

That is a patched RIOT — on the **attacker**. The victim in that demo is built
from the pin with no source change at all, which is the asymmetry that matters:
the instrumentation is on the board the attacker owns.

```bash
python patch_riot.py ~/riot-checkout
make BOARD=nrf52840dongle RIOTBASE=~/riot-checkout
make flash PORT=COM46          # nrfutil over the Nordic bootloader
python patch_riot.py ~/riot-checkout --restore
```

Use a disposable checkout, never a shared source tree.

**Flashing overwrites whatever is on the Dongle**, including a SoftDevice if
one is there — the Nordic bootloader layout RIOT targets leaves no room for
one. Put it in DFU mode with the small side button (SW2, the green LED
pulses), and note the port it comes up as.

## The shell

```
> ifconfig 5 -encrypt      # send in the clear; the host does this once
> stamp arm
> ping -c 1 -s 64 -W 30 fe80::...%5
> stamp dump
stamp count=4 freq=16000000
0,3905978554,1,98,61,dc,228,1
frame,0,61dce42300...
...
```

The attacker's own link key is RIOT's default, so against a victim with any
other key it **authenticates nothing** — every ping reports failure and waits
out its timeout. The hook records the frame before the MIC is checked, which is
why that does not matter.

## What it is not

* Not a sniffer. It transmits, and the interval it measures starts at its own
  transmission. A passive listener on this route would need a different
  reduction and does not have one here.
* Not specific to this attack. Anything that wants "when exactly did that
  frame end, on a clock that does not stop" can use it.
* Not a calibrated absolute clock. The intervals are differences on one
  free-running counter; nothing here is traceable to anything.
