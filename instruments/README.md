# The instruments: what does the timing, and what it costs

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

Every demo needs something to hold the clock. For the wired ones that is
[`ethtimer`](../deps/ethtimer), which lives in its own repository and is pinned
under `deps/`; the rest need an instrument that is not Ethernet.

| instrument | demo | what it times | where it is |
|---|---|---|---|
| `ethtimer` | the four wired demos | request out to reply in, in its own clock cycles, from its own Ethernet interrupts | [`deps/ethtimer`](../deps/ethtimer) |
| `spitimer` | `sbsfu_spi` | chip-select rise to the next chip-select fall on the victim's serial flash - the gap the decrypt happens in | not landed yet |
| `ctaphost` | `fido2_usb` | a CTAPHID request to its reply, from a bare-metal USB host rather than a PC | not landed yet |
| `sniff802154` | `ota_802154` | a data frame's end to the victim's ACK, off the air, with nothing on either legitimate node | not landed yet |

## Why these are not inside ethtimer

`ethtimer` is an Ethernet request/response timer that mentions no flash channel
and knows about no application protocol. That is what made it publishable on
its own, and it is worth keeping: an SPI chip-select timer in it would be a
different instrument wearing the same name. So the three above follow its shape
instead - firmware and host in one directory, one adapter per target, records
that come out under the array names the analysis already reads - and they stay
here.

## The instrument is part of the measurement

Two numbers worth knowing before reading any trace count:

* A better instrument is worth traces. The 802.15.4 listener's own receive
  chain contributes about 1.6 µs of per-frame noise against the victim's 0.6,
  which is a 9x trace penalty. That is the attacker's equipment, not the link:
  σ is flat across a 6.5x sweep of the data rate.
* An MCU host beats a PC host by about 100x on jitter for the USB demo, and
  the reason is that `bInterval` is a host scheduling policy rather than a
  property of the link. A host that implements no periodic scheduling does not
  pay it.

So where a demo quotes a cost, it is a cost for that instrument. A quieter one
moves it, and in both cases above the published number is an upper bound rather
than a property of the target.

## `hostlib`

[`hostlib/`](hostlib) is the small part of driving a board that is not specific
to one: find the port a probe serial belongs to, and refuse to guess. It
deliberately carries no board registry, no COM numbers, no drive letters and no
claim system - those belong to whoever's bench it is, in `BOARDS.local.json`,
which is gitignored.
