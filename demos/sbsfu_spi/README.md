# A secure bootloader's own SPI flash as the oracle

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

ST's X-CUBE-SBSFU stages an encrypted firmware image in an off-chip serial
flash and reads it back chunk by chunk, decrypting between reads. The victim is
the bus master: chip-select goes low, it clocks the bytes it wants, it goes
high, the chunk is decrypted, and it goes low again. The gap between those
edges contains the AES and nothing else that depends on the data - no host on
the critical path, no polling loop, no USB frame to average out, which is what
makes this the cheapest oracle in this repository.

**Who drives the edges differs by board, and it decides how the capture is
taken.** On the SAM D21 and the L152 chip-select is an ordinary GPIO, so the
driver's own C opens and closes every envelope. On the B-L475E-IOT01A the
memory is on QUADSPI and the IP drives nCS per command - the envelope is still
one per read and still visible to a probe, but the victim does not produce the
edge, and the status "poll" is a hardware train rather than one envelope.

Three ports, and they are not interchangeable:

| port | board | how it is timed | what came out |
|---|---|---|---|
| [`victim/l475`](victim/l475) | B-L475E-IOT01A | **both**: the bootloader times itself in `DWT->CYCCNT`, and a NUCLEO-F303RE on the memory's CS pin times a build with **no instrumentation in it** | the key, both ends of the cipher, from either observer. **Both are replayable here** |
| [`victim/samd21`](victim/samd21) | SAM D21 Xplained Pro | a NUCLEO-F303RE clipped to the serial flash's chip select | the key, with **nothing on the victim** - and this part has no data cache at all |
| [`victim/l152`](victim/l152) | NUCLEO-L152RE | the same external probe | the key, through SBSFU's realistic install path |

## Try it with no hardware, and no probe

```bash
python tools/replay.py demos/sbsfu_spi/vectors/l475_flash_5110.npz --controls
python tools/replay.py demos/sbsfu_spi/vectors/l475_bus_3048.npz
```

The second is the same board and the same key from **a probe on the chip
select against a victim with nothing added to it** - `make INSTR=0`, which
`make instrcheck` asserts leaves both patched files byte-identical to ST's and
the image carrying no instrumentation symbol.

```
   geometry    line_off=0 line_shift=1  (row of a lookup is (x+0)>>1)
   oracle      DWT->CYCCNT across one chunk: 5110 kept, n/a modes, spread 85.9
   controls    5110 intervals (  163520 blocks):  36/120 pairs, 16/16 masked bytes consistent
   note        residual search: 8388608 candidates (2**23.0)
   note        found after 6127616 candidates in the 2**23 residual
   recovered   4f454d5f4b45595f434f4d50414e5931
   EXACT  as expected in 14s
```

`4f454d5f4b45595f434f4d50414e5931` is ASCII `OEM_KEY_COMPANY1`, ST's own
published demo key, and the search that finds it is scored against
[`vectors/fw.plain`](vectors) - the genuine update an attacker holds, not a key
file. There is no key field in the capture at all.

## The L475 port is timed both ways, and the two agree

It was the port that recovers a key with no second board and also the one
with the weaker claim. It now has both arms, and the weaker one turned out to
be a good approximation of the stronger.

On the L152 and the SAM D21 the serial flash hangs off an SPI peripheral with
chip-select on an ordinary GPIO, so the driver's own C opens and closes every
envelope and a Nucleo clipped to that line times the gaps from outside. On the
B-L475E-IOT01A the MX25R6435F is on **QUADSPI** and nCS is driven by the IP per
command: the envelope is still one per read and still visible to anyone with a
probe, but the victim cannot produce the edge itself. So this port starts from
the other side and has the bootloader time its own gap, between the return of
`BSP_QSPI_Read` and the command that opens the next chunk's status poll.

What that is worth, now that both arms exist:

* The software bracket misses a fixed head and a fixed tail - the HAL's
  wait-for-complete before the clock starts, its command setup after it stops.
  A fixed offset is invisible to an attack that scores differences between
  intervals, so the self-timed arm was argued to be an UPPER BOUND on a
  bus-side attacker: less noise, the same signal.
* **That argument has been tested rather than left standing.** Known-key
  control, same build and same table addresses: **-51.4 ns per collision from
  the probe against -54.1 ns from the victim's own clock**, residuals
  1 054.1 ns and 1 031.6 ns. About 5 % of the effect and 2 % of the noise, so
  the bound was tight. The constant the bracket misses comes out at 8.7 us.
* **The outside measurement now exists**, against a victim built `INSTR=0`:
  nothing of this port's is in the decrypt path, and the key comes out. So
  "an attacker outside the package can do this" is a claim this board can
  make on its own, at ST's own chunk size.
* **The comparison needed the tables pinned.** `INSTR=0` takes ~1.1 KB of
  `.text` out, which moves `RT0` from `mod 8 == 0` to `mod 8 == 4` - and
  `mod 8` is the attack's `line_off`. `TABLEPAD=20` puts a stock image back on
  the instrumented build's phases, so the observer is the only difference.
* **Neither arm's trace floor is a reliable number**, and that is worth more
  than either floor: the ladder is non-monotone. One bus capture gives the key
  at 3 048 intervals, NOT at its own full 4 064, and again at 6 096 pooled.
  The scorer takes a prefix, so those are nested samples and it is the solver
  landing in a wrong fixed point, not the data. Quote the control, not the
  first rung that worked.
* Until then it is the cheapest way to find out whether wiring a probe to this
  board is worth the afternoon, and it is the only route in this demo that
  someone with no probe and no second board can run end to end.

The two ports that ARE bus-side measured their key from outside the package.
Their captures are hundreds of megabytes and stay on the bench, with a row
each in [`captures/MANIFEST.tsv`](../../captures/MANIFEST.tsv); what ships here
is their firmware, their scorer and their numbers.

## What the attack actually identifies

Round **one** of a **decryption**. mbedTLS's inverse cipher XORs the ciphertext
with the last round key and indexes the inverse T-table with the result
directly, so the index is `c ^ k` with no S-box in the way - and what collides
therefore identifies key-byte **differences**, never absolute bytes. Handing
these traces to a last-round scorer tests a relation the access stream does not
have and returns a clean null, which is a failure this project has paid for
twice.

The absolute key comes out of a small offline residual: one reference byte and
fifteen low bits, 2^23, ranked against the genuine image's plaintext. Fourteen
seconds.

## The geometry is two candidates here, not one

| scored at | effect | residual |
|---|---|---|
| the **8-byte read latch**, two four-byte entries to a line | the real one | **2^23** |
| the 32-byte data cache's conflict period | four times smaller | 2^53 |

`RT0` lands at `0x0802a488`, which is `mod 8 == 0` and `mod 32 == 8`, so those
two are genuinely different partitions of the same table. The vector names
`scorer_geometry` for that reason rather than leaving it to a default.

## The controls

* [`vectors/l475_ramtwin_5110.npz`](vectors) - the same bodies, the same
  passes, the same analysis, `make RAMTABLES=1` so mbedTLS computes its tables
  into SRAM instead. That is ST's shipped default, and one documented `#define`
  separates the two. Across-chunk spread falls from 83.1 cycles to 22.5 on
  an instrument floor of 18.5, the resolved pairs go from 36 of 120 to **0**,
  and no key comes out. It is marked slow because saying no costs the whole
  2^23 search.
* `host/attack_self.py --control` is the known-key control, and
  `--check-ref` scores the reference model's own stream both ways and refuses
  to continue if the two disagree. They do not: identical guesses on 24 of 24
  same-table pairs at 400 000 simulated blocks.
* `--sim` runs the whole scorer against the chunked-oracle simulation with no
  board at all, which is how it was validated before it was pointed at silicon.

## Building a victim

```bash
./deps/fetch.sh sbsfu stm32cube-l1      # the pinned X-CUBE-SBSFU, and the L1 HAL
cd demos/sbsfu_spi/victim/l475 && ./gen_keys.sh && make
grep . build/tables.txt                 # the table addresses, generated per build
```

There is no fetch script inside a port: `deps/fetch.sh` already pulls
X-CUBE-SBSFU at the pin `deps/PINS` names, with one sparse list that serves all
three, and a second fetch path would be a second pin to keep in step. Each port
keeps `diff_vs_stock.sh`, which is how "this is ST's code plus these hunks" is
checkable rather than asserted.

`stage_headers.sh` in each port looks like something to simplify away and is
not. A quoted `#include` searches the including file's own directory first,
which no `-I` order overrides, so ST's `app_sfu.h` wins over the port's unless
every header the build sees lives in one flat staged tree. It bit twice, one
level apart.

## What this does not settle

* The shipped crypto configuration is not quite the shipped build.
  `MBEDTLS_AES_ROM_TABLES` is commented out in what ST ships, so stock SBSFU
  computes its tables into `.bss` and this path has no flash-table channel at
  all. Uncommenting it is mbedTLS's own documented flash-saving option and the
  largest deviation all three ports make - and it is exactly the twin above,
  which is why one build serves as both.
* Secure Engine isolation is off in these ports, through ST's own
  development switch. That is a structural limit of the rigs, not a preference.
* ST's chunk size is free, but the body length is not. 512 bytes needed no
  change on the L475, where both other ports had to bring it down - but an
  interval still sums 32 decryptions, so 31 blocks' worth of signal becomes
  noise on the 32nd.
* Nothing here is a measurement of a shipping product. It is ST's reference
  application, built from ST's package, with the deviations listed above.
