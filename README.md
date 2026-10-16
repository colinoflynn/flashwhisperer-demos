# flashwhisperer-demos

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

A microcontroller's flash accelerator - the read latch, the prefetch buffer,
the little data cache - makes an AES lookup table's access time depend on which
row the last lookup touched. That is enough to recover the key, and you do not
need a probe on the board: a protocol that answers you is a good enough clock.

These are the demos where that worked end to end, against stock stacks, over a
real transport, finishing in a key that was then verified. Each one ships the
capture it was measured from, so you can check it before you own any of the
hardware.

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
| [`oscore_coap`](demos/oscore_coap) | NUCLEO-F429ZI, `uoscore-uedhoc` + TinyCrypt over lwIP, as shipped | `ethtimer` on a second Nucleo | AES-128 key, verified, 150 000 exchanges |
| [`snmpv3_lwip`](demos/snmpv3_lwip) | NUCLEO-F429ZI, lwIP's own SNMPv3 agent on mbedTLS, both out of STM32CubeF4 | `ethtimer` | privacy key, verified, 250 000 exchanges and a floor near 100 000 |
| [`tls_https`](demos/tls_https) | NUCLEO-F429ZI, lwIP `httpd` + `altcp_tls` + mbedTLS, all out of STM32CubeF4 | `ethtimer` | record key, verified, 41 000 exchanges of one TLS session |
| [`snmpv3_harmony`](demos/snmpv3_harmony) | PIC32MZ2048EFH144, Harmony 3 + wolfCrypt on FreeRTOS | its own CP0 counter, and the wire | privacy key, verified - but the **shipped build is a null** |
| `ota_802154` | NUCLEO-F401RE + S2-LP, X-CUBE-SUBG2 Contiki-NG, stock | a third board listening | key from 2.4 M frames, blind, nothing on either node |
| `sbsfu_spi` | ATSAMD21J18A and NUCLEO-L152RE running X-CUBE-SBSFU | a Nucleo clipped to the serial flash's chip select | key with nothing on the victim, and the SAM D21 has no cache at all |
| `fido2_usb` | nRF52840 Dongle, RIOT's `fido2_ctap_hid`, unmodified | a Nucleo acting as the USB host | `cred_key`, blind: no debugger, key never known |

The first four have landed, with their vectors. The last three arrive in that
order, and this table is the one place that says which.

Each of the four replays to a verified key in under a minute with no hardware,
and each ships at least one control that must NOT give a key:

```
oscore_coap     f429_standard_600k       key       expected
oscore_coap     f429_ramtables_300k      no key    control
snmpv3_lwip     f429_romtables_250k      key       expected
tls_https       f429_romtables_50k       key       expected
snmpv3_harmony  pic32mz_cacheoff_60k     key       expected
snmpv3_harmony  pic32mz_shipped_10k      no key    control
```

## How a demo is laid out

```
demos/<name>/README.md     what it recovers, what it costs, what did NOT work
           /victim/        the overlay against the vendor tree. Never a copy of it
           /host/          capture, analyse, recover
           /vectors/       the distilled capture, and the geometry it needs
           /images/        known-good binaries, built with a published test key
```

Everything shared sits beside those: `deps/` for pinned upstreams,
`instruments/` for the boards that do the timing, `tools/` for the replay, the
manifest and the checks.

## The attacker is not in here

For the four wired demos the attacker board is
[`ethtimer`](https://github.com/colinoflynn/ethtimer), pinned under `deps/`. It
sends host-supplied bytes, times the turnaround from its own Ethernet
interrupts, and knows nothing about any application protocol - the OSCORE,
SNMPv3 and TLS clients live in its `demos/`. So this repository ships no
attacker firmware and no protocol code for them, which is also why the
instrument can be used for something else entirely.

The other three demos need an instrument that is not Ethernet: a chip-select
timer, a USB host, a radio listener. Those live in [`instruments/`](instruments)
and they follow ethtimer's shape rather than growing inside it.

## The one thing that will cost you a key

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

## Related

| | |
|---|---|
| [flashwhisperer](https://github.com/colinoflynn/flashwhisperer) | the toolkit: the simulator, the attack engine, the scoring rule, the row geometry. Every recovery here goes through it |
| [flashwhisperer-crypto-eval](https://github.com/colinoflynn/flashwhisperer-crypto-eval) | the same question on the bare metal: one part, one library, the victim's own cycle counter. That is where a demo's **on-chip floor** comes from, and it needs only a dev board |
| [ethtimer](https://github.com/colinoflynn/ethtimer) | the Ethernet instrument, firmware and host in one project |
