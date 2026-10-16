# HTTPS over TLS 1.2: the session key of an embedded web server

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

A NUCLEO-F429ZI serves a page over HTTPS: lwIP's `httpd` on lwIP's `altcp_tls`
on mbedTLS, all three out of STM32CubeF4 and compiled as they ship. A second
Nucleo running [`ethtimer`](../../deps/ethtimer) drives one long keep-alive
session and times the replies. The server's AES-128 record key comes out, and
an MCU serving its configuration page over HTTPS is about as ordinary as
embedded devices get.

The key here is a TLS session key, so it dies with the session - which is
exactly why the capture is one session. What makes that affordable is that
every record carries fifteen usable AES blocks, so the exchanges needed are a
fifteenth of the blocks needed.

## Try it with no hardware

```bash
python tools/replay.py demos/tls_https/vectors/f429_romtables_50k.npz --controls
```

```
   geometry    line_off=4 line_shift=4  (row of a lookup is (x+4)>>4)
   conditioned dt_hw: 611805 traces kept, 2 modes, spread 165.6
   pooled z    -8.17   (the effect over the 120 pairs, given the key)
   shuffled    -1.68   (control: timing permuted)
   wrong key   -0.81   (control: labels from a key that is not it)
   note        40787 exchanges x 15 blocks = 611805 traces
   note        vote got 15/16 round-key bytes (validation only)
   note        brute-forced byte positions [0, 1] (all 120 pairs, 2^16 each)
   recovered   975bb9222c7f445319900f1a28359dab
   EXACT  as expected in 29s
```

Two units there and they are not interchangeable: 40 787 measured turnarounds,
611 805 AES blocks. Quote the wrong one and this demo looks fifteen times
cheaper or fifteen times dearer than it is.

## Why fifteen blocks per measurement

A TLS 1.2 CBC record is `header || IV || C_1 .. C_n` with
`C_i = E(K, P_i ^ C_(i-1))`, and the victim encrypted the whole record inside
the one turnaround that was measured. The response is 255 bytes of known HTTP,
so blocks 1 to 15 are fully known - block 16 is where the MAC starts - and each
one is another known `(input, output)` pair covered by that same timing. The
collision patterns of different blocks are independent, so each block
contributes its own evidence while the other fourteen look like noise to it.

It also means the attack is self-verifying with no key at all: any candidate is
checked by encrypting a known input and comparing with the known output. The
vector keeps one such pair, and `975bb922...` in the output above is a
*validation* line, not an input to the recovery.

## The row offset

`FSb` lands at `0x0801e944` here, 4 bytes into its 16-byte row - a different
number from the SNMPv3 victim's 12, same library and same table, because
`-fdata-sections` lets everything else in the image decide. Measured on this
capture, vote only, counts in exchanges:

```bash
python tools/replay.py demos/tls_https/vectors/f429_romtables_50k.npz \
    --ladder 12500,25000,40000 [--line-off 0]
```

| exchanges | 12.5 k | 25 k | 50 k | 100 k | 150 k |
|---|---|---|---|---|---|
| `line_off=4`, what the image says | 4/16 | 8/16 | 14/16 | 15/16 | 15/16 |
| `line_off=0`, the usual guess | 0/16 | 0/16 | 2/16 | 14/16 | - |

The 50 k and above rows were measured on the full 250 000-exchange capture; the
vector shipped here holds the first 50 000 of it, of which about 40 000 survive
conditioning. That is already enough.

## What the two ends are

| | |
|---|---|
| victim | NUCLEO-F429ZI. lwIP `httpd` + `altcp_tls` + mbedTLS out of STM32CubeF4, `make ROMTABLES=1`, `FLASH_ACR = 0x305`. The certificate and key in `victim/` are a published demo pair, generated for this and nothing else |
| attacker | NUCLEO-F746ZG running `ethtimer`, in `relay` then `bank` mode: it holds the TCP connection open and keeps a slice of each response |

## Capturing it yourself

```bash
./deps/fetch.sh stm32cube-f4
make -C demos/tls_https/victim ROMTABLES=1
arm-none-eabi-nm demos/tls_https/victim/Build/romtab/https_victim.elf | grep FSb

cd deps/ethtimer && tools/fetch_sdk.sh f746 && make -C firmware BOARD=f746
python -m ethtimer.cli --target tls --n 250000 \
    --ip 192.168.7.20 --gw 192.168.7.1 --victim 192.168.7.10 --out tls.npz

python demos/tls_https/host/make_vector.py tls.npz --n 50000 \
    --out demos/tls_https/vectors/mine.npz --label "my capture"
python tools/replay.py demos/tls_https/vectors/mine.npz
```

The capture has to stay inside one session: a new handshake is a new key, and
the traces either side of it do not pool.

## The controls

* the timing shuffled: `-1.68`, against `-8.17` for the real thing.
* the wrong key: `-0.81`.
* the sign: negative, as a row collision must be.
* tables in RAM is the structural control for this victim, and it is the
  OSCORE demo's vector in this kit rather than a TLS capture - same part, same
  instrument, same question about where a table lives.

## What this does not settle

* The key is one session's. Recovering it buys that session, not the device.
* 250 000 exchanges in one session is a lot of keep-alive. A server that closes
  the connection, rekeys, or rate-limits is a different experiment, and this
  demo says nothing about how much any of those cost an attacker.
* One capture, one build, one part. The ladder rows are rungs.
* The shipped vector is the first fifth of the capture. Nothing here says the
  rest of it would behave the same, though the two ladder rows that overlap
  agree.
