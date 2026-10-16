# The victim, and why you can check it is stock

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

One command builds all three images from ST's own sources at a pinned commit:

```bash
./deps/fetch.sh x-cube-subg2
demos/ota_802154/victim/build_rig.sh --key 000102030405060708090a0b0c0d0e0f
```

The point of this directory is that the node under attack is auditable. Clone
the same commit, apply the same patch, read it, and see that the victim is
X-CUBE-SUBG2's own Contiki-NG with guards added and nothing else.

## The three nodes

| role | board | how modified | why |
|---|---|---|---|
| victim | NUCLEO-F401RE + X-NUCLEO-S2915A1 | 62 added lines, 0 deletions | the node under attack, so it has to be stock |
| coordinator | NUCLEO-F401RE + X-NUCLEO-S2915A1 | freely | only a traffic source, never attacked |
| listener | NUCLEO-L152RE + X-NUCLEO-S2915A1 | wholly ours | the attacker; no assumptions apply |

The attack targets the victim, not the coordinator. The oracle is the data
frame to ACK turnaround, and the AES-CCM* *decrypt* inside it belongs to
whoever receives the frame and acknowledges it. Two qualifications: the key is
the network-wide LLSEC key, so breaking it at the victim also opens the
coordinator, and the roles are fixed only by which node runs `MAC_GEN` - point
the generator the other way and the coordinator becomes the target with nothing
else changed.

## The patch, in full

| file | + | what it does |
|---|---:|---|
| `Inc/project-conf.h` | 23 | `#ifndef` on three `LOG_CONF_LEVEL_*`; `#ifdef RIG_KEY` sets the LLSEC key |
| `Inc/radio-driver.h` | 12 | `#ifndef` on `CHANNEL_NUMBER`, `DATARATE`, `FREQ_DEVIATION`, `BANDWIDTH` |
| `Inc/contiki-conf.h` | 9 | `#ifndef` on `IEEE802154_CONF_PANID` and `CSMA_CONF_MAX_BE` |
| `Src/contiki-platform.c` | 18 | `#ifdef NODE_MAC_FIXED` pins the EUI-64 instead of deriving it from the STM32 UID |

Every hunk is a guard or a new `#ifdef` block, so with no `-D` flags the victim
compiles to upstream behaviour exactly. Verify rather than believe:

```bash
git -C deps/x-cube-subg2 apply demos/ota_802154/victim/rig.patch
git -C deps/x-cube-subg2 diff --numstat -- '*UDP_Client*'   # deletions must be 0
git -C deps/x-cube-subg2 checkout -- .
```

`build_rig.sh` prints that same numstat, and then `verify_build.py` reads the
values back out of the linked images, because `make` exiting 0 does not mean a
`-D` landed. Nothing in `radio-driver.c`, `csma-output.c`, `stm32f4xx_it.c`,
`stm32f4xx_nucleo.c` or `udp-client.c` is touched. In particular the victim
carries no instrumentation and no wait-state amplification, and the running
board reads `FLASH_ACR = 0x00000702` - LATENCY 2, prefetch, I-cache and D-cache
all on, which is ST's stock setting for 84 MHz.

## The coordinator's extra changes, and why they are not cheating

```
Src/udp-server.c    +119   MAC_GEN traffic generator
Src/csma-output.c   +9 -1  standard CSMA backoff instead of ST's Cooja compensation
```

plus `CSMA_CONF_MAX_BE=5` and `QUEUEBUF_CONF_NUM=16`. All of it is
transmit-side and measured to matter:

| coordinator | records/s | data frames never ACKed |
|---|---:|---:|
| upstream defaults | 10.9 | 18.6 % |
| `MAX_BE=5`, 16 queuebufs | 49.9 | 0.09 % |

The victim keeps upstream's values, because its soft ACK is a direct
`NETSTACK_RADIO.send` that never passes through `csma_output`, so nothing on
the measured path depends on them.

What *is* an assumption about the deployment, and is stated rather than tuned:
the traffic shape. A 24-byte payload every 20 ms is a "device reports
periodically" model. A passive attacker cannot make a device transmit, so that
is a property of the network rather than an attacker capability - and 24 bytes
is also the measured optimum for a passive listener, beating both 16 and 48, so
there is nothing further to gain by tuning it.

No image ships in this directory. The LLSEC key is compiled into all three of
them, so a built image carries a key, and the only one that would be safe to
commit is a published test key nobody should be flashing anyway.

## Read the row offset off the image you just built

`build_rig.sh` prints it for the victim and the coordinator, and it is the one
number you must not inherit:

```
   victim   row offset 4   AES S-box sbox @ 0x08017ce4 (.rodata, EXPOSED)
```

`static const uint8_t sbox[256]` carries no alignment attribute, so GCC gives
the section 4-byte alignment on ARM and the offset is link-order luck out of
{0, 4, 8, 12}. The two captures in `../vectors/` are the same sources at 4 and
at 12. Getting it wrong costs about 2.2x in traces and does not announce
itself; `aligned(16)` is not a fix either, since it moves the offset to 0,
which is if anything cleaner for the attacker.

## Gotchas, all of which fail silently

* The shell brace-expands `-DFOO={a,b,c}` into separate `-D` flags, leaving the
  macro defined as its last byte. All the list-valued macros (`RIG_KEY`,
  `NODE_MAC_FIXED`, `SNIFF_DST`, `MAC_GEN_DST`) therefore take bare comma
  lists, and the braces are added at the use site.
* `core.longpaths=true` is not optional on Windows: several MDK-ARM and CubeIDE
  paths in this package exceed `MAX_PATH` and a checkout fails half-done
  without it. `deps/fetch.sh` sets it; `tools/verify.sh` is what catches a tree
  that looks complete and is not.
* The vendor tree is patched IN PLACE and put back on the way out, because
  `tools/verify.sh` fails on a dependency with edits in it. `--keep` leaves it
  patched, and then it is yours to revert.
* `grep -c` exits 1 when the count is zero, so under `set -e` a perfectly clean
  build aborts the script. `|| true`, every time.
* `EXTRA_DEFINES` is not tracked by the Makefile, so a rebuild with different
  flags happily reuses stale objects. `build_rig.sh` removes the output tree
  for each image rather than relying on that.
* A debug probe clears `DEMCR.TRCENA` on disconnect, which freezes
  `DWT->CYCCNT` on the listener. It re-arms within one record, but check a
  fresh capture before trusting it: a frozen counter produces a healthy-looking
  record stream in which every interval is zero.
* Reads of peripheral registers on a *running* target are unreliable through a
  probe. `FLASH_ACR` and `PLLCFGR` both returned `0x00000000` while the core
  ran, and zero is the reset default for `FLASH_ACR`, so it reads as a
  plausible answer. Halt the core first.
