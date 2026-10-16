# SNMPv3 over UDP: the privacy key of lwIP's own agent

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

A NUCLEO-F429ZI runs lwIP's own SNMPv3 agent with mbedTLS underneath, both
shipped inside STM32CubeF4 and compiled as they ship. A second Nucleo running
[`ethtimer`](../../deps/ethtimer) sends requests and times the replies. The
agent's AES-128 privacy key comes out of about 250 000 exchanges, which is
eleven minutes of traffic, and the attack floor is nearer 100 000.

An SNMPv3 privacy key is a good target for a reason: it does not rotate. TLS
gives you a session key and a handshake to chase, where this one key covers
every response the device will ever send under that passphrase.

## Try it with no hardware

```bash
python tools/replay.py demos/snmpv3_lwip/vectors/f429_romtables_250k.npz --controls
```

```
   geometry    line_off=12 line_shift=4  (row of a lookup is (x+12)>>4)
   conditioned dt_hw: 150000 traces kept, 2 modes, spread 64.0
   pooled z    -15.82   (the effect over the 120 pairs, given the key)
   shuffled    +0.01   (control: timing permuted)
   wrong key   -0.68   (control: labels from a key that is not it)
   note        vote got 15/16 round-key bytes (validation only)
   note        brute-forced byte positions [0, 1] (all 120 pairs, 2^16 each)
   recovered   befa18829b1376e8d5d0d232ce6ecf5b
   EXACT  as expected in 31s
```

The vector is the capture's two useful columns: CFB block 2's keystream, which
is `E(K, C1)`, and the turnaround that producing it took. One free
`(input, output)` pair comes with it, because `C1` is on the wire and block 2's
keystream is the known plaintext XOR the ciphertext - so a candidate key is
settled by one AES block with nothing secret, and the recovery does not need
the 15th and 16th vote bytes to be right.

## What the two ends are

| | |
|---|---|
| victim | NUCLEO-F429ZI. lwIP's SNMPv3 agent, mbedTLS as its crypto backend, HAL and lwIP out of STM32CubeF4. `make ROMTABLES=1`, which is mbedTLS's own documented `MBEDTLS_AES_ROM_TABLES` and the only decision this project makes. `FLASH_ACR = 0x305` |
| attacker | NUCLEO-F746ZG running `ethtimer`, which times its own transmit-complete interrupt to its own receive interrupt |

The cipher is mbedTLS's four-table AES; what the last round reads is `FSb`, the
256-byte final-round S-box, and that is the table the attack is about.

## The row offset is worth a third of the traces here

`FSb` lands at `0x08017d7c` in this image, 12 bytes into its 16-byte flash row.
Measured on this capture, vote only:

```bash
python tools/replay.py demos/snmpv3_lwip/vectors/f429_romtables_250k.npz \
    --ladder 50000,100000,150000 [--line-off 0]
```

| traces | 50 k | 100 k | 150 k |
|---|---|---|---|
| `line_off=12`, what the image says | 7/16 | 13/16 | 15/16 |
| `line_off=0`, the usual guess | 1/16 | 10/16 | 13/16 |

An earlier note paired this build with `0x08017d10`, which is offset 0 and was
a different build with an extra `.rodata` pad. Both cannot be right.
`-fdata-sections` makes the linker's ordering depend on everything else in the
image, so read the address off the ELF after every build - and note that the
TLS victim next door, same library and same table, lands on 4 rather than 12.

## This capture is not stationary, and that matters more than it sounds

Its first stretch runs about 8 microseconds faster than the rest. A single mode
fit that straddles that step spans both regimes and the signal dies. The vector
asks for `fast` conditioning, which keeps the fast mode and subtracts its mean;
`mode` is what the TLS demo uses and it is the wrong choice here. If you
re-capture and the step is gone, change the json rather than leaving a
conditioning choice standing for a reason that no longer holds.

## Capturing it yourself

`victim/` is the overlay against STM32CubeF4: the agent, the lwIP port, the
configuration headers and a Makefile. The vendor tree itself stays under
`deps/` and unmodified.

```bash
./deps/fetch.sh stm32cube-f4
make -C demos/snmpv3_lwip/victim ROMTABLES=1
arm-none-eabi-nm demos/snmpv3_lwip/victim/Build/romtab/snmp_victim.elf | grep FSb

cd deps/ethtimer && tools/fetch_sdk.sh f746 && make -C firmware BOARD=f746
python -m ethtimer.cli --target snmpv3 --n 250000 \
    --ip 192.168.7.20 --gw 192.168.7.1 --victim 192.168.7.10 --out snmp.npz

python demos/snmpv3_lwip/host/make_vector.py snmp.npz \
    --out demos/snmpv3_lwip/vectors/mine.npz --label "my capture"
python tools/replay.py demos/snmpv3_lwip/vectors/mine.npz
```

`make` on its own is mbedTLS's default, which computes its tables into RAM at
startup - that is the control, not the attack.

## The controls

* the timing shuffled: `+0.01`. Permute the per-trace times and the effect has
  to vanish.
* the wrong key: `-0.68`. Label the collisions with a key that is not the
  agent's and it also has to vanish.
* the sign: a flash-row collision makes a trace faster, so the effect must be
  negative. `-15.82` is.
* tables in RAM: measured at pooled z `-0.58`, no pair below `-3`, 0/16, at
  250 000 exchanges on the same agent and the same analysis. **That capture is
  not in this kit** - it was taken on an earlier instrument and kept only as a
  number. The replayable RAM-table twin here is the OSCORE demo's, on the same
  part.

## What this does not settle

* It is one victim, one build, one part, one capture conditioned one way. The
  trace counts are rungs on a ladder.
* The attack reads the AES **output**. There is a second route on this same
  victim that uses the input side only - round 1 plus round 2, no response
  plaintext - and it recovered the key from a million exchanges, but it needs
  the data cache on and a compact table build, and it is not shipped here as a
  vector.
* Nothing here says an SNMPv3 agent on another stack leaks. The Harmony demo
  next door is the same protocol on a different vendor's stack, and its shipped
  build is a null.
* A 10 Mbit link kills this measurement (sigma 13.7, dip -0.016). The capture
  above is on a direct 100 Mbit cable.
