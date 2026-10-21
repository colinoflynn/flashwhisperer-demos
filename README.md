# FlashWhisperer-Demos: AES Timing Side-Channel Demos

*🤖🥩: This document is partially human-written, partially LLM. This repo flags
LLM-written docs as I find they can be more annoying to read as a human bag of 🥩*

A microcontroller's flash accelerator (called the read latch, prefetch buffer,
or  little data cache) makes an AES lookup table's access time depend on which
row the last lookup touched. That is enough to recover the key, and you do not
need a probe on the board: a protocol that answers you is a good enough clock.

These are the demos where that worked end to end, against stock stacks, over a
real transport, finishing in a key that was then verified. Each one ships the
capture it was measured from, so you can recreate the attack demo.

```bash
git clone -c core.longpaths=true <this repo> && cd flashwhisperer-demos
./deps/fetch.sh --tools              # ethtimer, at its pin. flashwhisperer is
                                     # vendored here while it is private
pip install -e deps/flashwhisperer
python demos/00_no_hardware/run.py   # recover a key. No board needed.
```

**Clone somewhere short, and on Windows with `core.longpaths=true`.** A clone
into a deep directory exceeds MAX_PATH and **aborts part way through the
checkout**, leaving a tree that looks complete; the vendor SDKs under `deps/`
make that likely rather than possible. `./tools/verify.sh` is what catches it.

## The demos

| | victim | what times it | what came out |
|---|---|---|---|
| [`oscore_coap`](demos/oscore_coap) | NUCLEO-F429ZI, `uoscore-uedhoc` + TinyCrypt over lwIP | `ethtimer` on a second Nucleo | AES-128 key, verified, 150 000 exchanges |
| [`snmpv3_lwip`](demos/snmpv3_lwip) | NUCLEO-F429ZI, lwIP's own SNMPv3 agent on mbedTLS, both out of STM32CubeF4 | `ethtimer` | privacy key, verified, 250 000 exchanges and a floor near 100 000 |
| [`tls_https`](demos/tls_https) | NUCLEO-F429ZI, lwIP `httpd` + `altcp_tls` + mbedTLS, all out of STM32CubeF4 | `ethtimer` | record key, verified, 41 000 exchanges of one TLS session |
| [`snmpv3_harmony`](demos/snmpv3_harmony) | PIC32MZ2048EFH144, Harmony 3 + wolfCrypt on FreeRTOS | its own CP0 counter, and the wire | privacy key, verified - but the **shipped build does not leak, this was a modified build** |
| [`ota_802154`](demos/ota_802154) | NUCLEO-F401RE + S2-LP, X-CUBE-SUBG2 Contiki-NG, stock | a third board listening to the link | link key, verified, 2.5 M frames, blind, victim nodes stock (but with artificial traffic or the test) |
| [`sbsfu_spi`](demos/sbsfu_spi) | ATSAMD21J18A, NUCLEO-L152RE and B-L475E-IOT01A running X-CUBE-SBSFU | a Nucleo clipped to the serial flash's chip select (plus flash programmer, or emulator) | the key with nothing on the victim |
| [`fido2_usb`](demos/fido2_usb) | nRF52840 Dongle, RIOT's `fido2_ctap_hid` demo | a Nucleo acting as the USB host | `cred_key`: allows recovery of private keys |
| [`riot_802154`](demos/riot_802154) | nRF52840-DK, RIOT GNRC's `ieee802154_security` | nRF52840 Dongle is attacker, exploits accepting unsecure ping requests | the AES-128 link key, from about 1.25hrs of pinging |

The demos above have a number of recorded traces. There is also a "control" which normally means moving the AES tables to RAM
(which does not leak on these micros). This control is done to ensure it was not some other problem (misflashed, or the LLM did some
dirty trick to the crypto):

```
oscore_coap     f429_standard_600k       key       expected
oscore_coap     f429_ramtables_300k      no key    control
snmpv3_lwip     f429_romtables_250k      key       expected
tls_https       f429_romtables_50k       key       expected
snmpv3_harmony  pic32mz_cacheoff_60k     key       expected
snmpv3_harmony  pic32mz_shipped_10k      no key    control
ota_802154      f401_blind_2500k         key       expected
ota_802154      f401_stock_2400k         key       expected
ota_802154      f401_blind_500k          no key    control
sbsfu_spi       l475_flash_5110          key       expected
sbsfu_spi       l475_ramtwin_5110        no key    control
fido2_usb       dongle_ladder_13stages   relations relations
riot_802154     nrf52840_newkey_80000    key       expected
riot_802154     nrf52840_newkey_20000    no key    control
```

## How a demo is laid out

```
demos/<name>/README.md     what it recovers, what it costs, what did NOT work
           /victim/        the overlay against the vendor tree (normally pins from git upstream)
           /host/          capture, analyse, recover
           /vectors/       the distilled capture, and the geometry it needs
           /images/        known-good binaries, built with a published test key
```

Everything shared sits beside those: `deps/` for pinned upstreams,
`instruments/` for the boards that do the timing, `tools/` for the replay, the
manifest and the checks.

## EthTimer Project

For the four wired demos the attacker board is
[`ethtimer`](https://github.com/colinoflynn/ethtimer), pinned under `deps/`. It
sends host-supplied bytes, times the turnaround from its own Ethernet
interrupts, and knows nothing about any application protocol - the OSCORE,
SNMPv3 and TLS clients live in its `demos/`. So this repository ships no
attacker firmware and no protocol code for them, which is also why the
instrument can be used for something else entirely.

The other three demos need an instrument that is not Ethernet: a chip-select
timer, a USB host, a radio listener. Those are in [`instruments/`](instruments).

## Common Key Recover Failures

A trace count without the table's **address** is under-specified. The row a
lookup hits is `(index + line_off) >> line_shift`, `line_off` is where the
table happens to land inside its flash row, and it is a property of the image
rather than a constant of the attack. Getting it wrong is worth between two and
ten times the traces, and on this OSCORE capture it is the difference between a
verified key at 150 000 exchanges and three correct bytes:

| traces | 50 k | 100 k | 150 k | 200 k | 300 k |
|---|---|---|---|---|---|
| `line_off=12`, which is what the image says | 7/16 | 11/16 | **16/16, EXACT** | **16/16, EXACT** | **16/16, EXACT** |
| `line_off=0`, the usual guess | 0/16 | 2/16 | 3/16 | 10/16 | 15/16 |

Every vector therefore carries its geometry in a `.json` beside it, and
`tools/replay.py` refuses to run without one.

When recreating the demos, shifts in the AES table layout was a common issue that
made it seem like it suddenly did not work.

## Related

| | |
|---|---|
| [flashwhisperer](https://github.com/colinoflynn/flashwhisperer) | the toolkit: the simulator, the attack engine, the scoring rule, the row geometry. Every recovery here goes through it |
| [flashwhisperer-crypto-eval](https://github.com/colinoflynn/flashwhisperer-crypto-eval) | the same question on the bare metal: one part, one library, the victim's own cycle counter. That is where a demo's **on-chip floor** comes from, and it needs only a dev board |
| [ethtimer](https://github.com/colinoflynn/ethtimer) | the Ethernet instrument, firmware and host in one project |
