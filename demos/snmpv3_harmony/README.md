# SNMPv3 on Microchip Harmony: a key, and the build it needs

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

**Read this before the numbers: the build Microchip ships is a null.** On a
PIC32MZ2048EFH144 running Harmony 3's own SNMPv3 agent with wolfCrypt on
FreeRTOS, the shipped configuration gave nothing at 3 000 000 exchanges, at
every one of the sixteen table alignments. What breaks is a build with the data
cache off, which on this part is a deliberate change and not a default. So this
demo is two results and a gap between them, and the gap is the point:

| | what was measured | result |
|---|---|---|
| the cipher's own clock, cache **off** | CP0 Count around `wc_AesCfbEncrypt`, 60 000 traces | the exact privacy key. **Shipped here as a vector** |
| the cipher's own clock, build **as shipped** | the same probe, 10 500 traces | 11 distinct values, no data dependence, pooled z `-0.56`. Shipped here as the control |
| over the wire, cache off + an uncached S-box read | 3 000 000 exchanges -> 591 674 IV-averaged traces | the exact privacy key after 19 285 candidate keys. **Not shipped**: the pool is 32 MB and stays on the bench, see `captures/MANIFEST.tsv` |

The last row is the one that matters for a threat model and it is also the one
that needs the most caveats. It is not one flash-controller field away from
shipping: the uncached read is a source change to wolfCrypt, and `PFMWS = 7`
with the reads still cached is a clean null at the same depth across all
sixteen line offsets.

## Try it with no hardware

```bash
python tools/replay.py demos/snmpv3_harmony/vectors/pic32mz_cacheoff_60k.npz --controls
```

```
   geometry    line_off=0 line_shift=4  (row of a lookup is (x+0)>>4)
   conditioned aes_tick: 60000 traces kept, 1 modes, spread 53.9
   pooled z    -12.74   (the effect over the 120 pairs, given the key)
   shuffled    +1.85   (control: timing permuted)
   wrong key   +0.58   (control: labels from a key that is not it)
   note        vote got 15/16 round-key bytes (validation only)
   note        brute-forced byte positions [0, 2] (all 120 pairs, 2^16 each)
   recovered   543363833d108c6a8f5a258c23bc4c97
   EXACT  as expected in 27s
```

And the shipped build, same probe, same geometry, same analysis:

```
   conditioned aes_tick: 10253 traces kept, 2 modes, spread 1.7
   pooled z    +0.25
   note        vote got 0/16 round-key bytes (validation only)
   recovered   nothing
   no key  as expected in 48s
```

Spread 1.7 cycles against 53.9. With the cache on there is nothing at the call
to lose, which is why the wire-level null on the shipped build is a null for
the right reason rather than a measurement that failed.

## Why the oracle is the cipher and not the wire

Because a remote null is ambiguous. "The cipher does not leak" and "the leak is
swamped on the way out" look identical from a capture that recovers nothing,
and the only way to tell them apart is to put a clock on the cipher and
difference the two. That is what this probe is, and on this victim it settles
it: cache on, nothing leaks at the call; cache off, the key falls at the call
in 60 000 traces and the wire can still barely see it.

Two things about the probe that are results rather than details:

* Interrupts must be masked while it counts. With them on, ISRs landing
  inside the measured window added 27 percent to the median and 300 times the
  variance - and that contamination is not shared with the reply, so it made
  the cipher look uncorrelated with the wire when it is not.
* The probe moves the table. The interrupts-masked build puts `Tsbox` at
  `0x9D044580`; the cache-off and `PRECON` arms leave it at `0x9D044398`, and
  one arm that formed an uncached alias shifted `.rodata` by 24 bytes. Read the
  address off every build. On this victim it is not a scale factor on the trace
  count - the shipped build fails at all sixteen offsets - so a count without
  the address is not under-specified here, it is meaningless.

## The read order is a property of the image

wolfCrypt's `WOLFSSL_AES_SMALL_TABLES` last round reads `ct[0] ct[1] ct[2]
ct[3]` per output word in the source. XC32 v6.00 at `-O1` does not emit them
that way: from the shift amounts in this image the order is
**`ct[0] -> ct[3] -> ct[1] -> ct[2]`**, so the output-byte pairs that can share
a 16-byte flash row are `(0,3)`, `(1,3)` and `(1,2)`, and the two pairs the
source order suggests cannot collide at all.

That was found the expensive way. Scored on the full wire pool, the three
adjacent sets gave 8 of 24 round-10 bytes and the three non-adjacent ones gave
0 of 24 - the model's signal and control sets had been exactly swapped. Four
correct bytes out of 256 candidates each is about 1e-8 against chance, so it
was never a marginal call, just a misfiled one.

The replay here scores all 120 pairs, which includes the right ones and needs
no disassembly. If you narrow the vote on another image, derive the order from
that image's shift amounts and not from `aes.c`.

## The trace unit is not an exchange

Harmony derives its privacy salt from the clock, so identical AES inputs repeat
in runs of about five. One IV-averaged trace costs 5.07 EXCHANGES on the
wire, which is why the wire row above reads 591 674 traces and 3 000 000
exchanges. The packer prints how many repeated inputs it saw in its sample, and
the shipped-build control is shallower than it looks for the same reason.

## Rebuilding the victim

`victim/` holds the arms as scripts that apply and revert in place against a
Harmony checkout, preserving its CRLF endings, with the resulting diff beside
each one. The Harmony tree is not a clone and not in `deps/`: MPLAB X's Content
Manager installs it, one versioned component at a time.

```bash
python demos/snmpv3_harmony/victim/arm_b_cache_off.py apply
python demos/snmpv3_harmony/victim/arm_f_aes_probe.py apply
cd <harmony>/net_apps_pic32mz/apps/snmpv3_nvm_mpfs/firmware/pic32mz_ef_sk_freertos.X
make CONF=pic32mz_ef_sk_freertos
```

MPLAB X **v6.20**, not v6.25 or later: that dropped support for this board's
Gen-3 PKOB debugger. Arms B and F touch different files, so applying both gives
the cache-off cipher probe, which is the arm that recovers. Reverting both and
rebuilding gave a hex byte-identical to the original, which is how the tree is
known to be clean.

Two arms from the campaign are deliberately not here: one formed the uncached
alias and moved the table, so it is not a single-variable comparison, and one
wrote `PRECON` before `SYS_Initialize`, which overwrites it on the next line -
it ran with the shipped `PRECON` rather than the one its name claimed.

## What this does not settle

* The shipped build. It is a null at 3 000 000 exchanges, and nothing here
  says otherwise. Everything that recovers is a build this project made.
* Whether the wire recovery generalises. It needed the cache off *and* an
  uncached alias read of the S-box, which is a source change to wolfCrypt, and
  what unlocked it was not more traces but summing the pair sets' score
  surfaces instead of taking the best one per set - worth 2^49.
* The flash controller on its own. `PFMWS = 7` with the reads still cached
  is a clean null across every offset, so the wait state is a gain factor on a
  channel that has to already exist.
* The control's depth. 10 500 traces against 60 000, and the IV runs make
  the distinct-input count lower still. Its claim rests on between-input
  variation (1.94 cycles) being smaller than same-input variation (4.12), not
  on a failed deep recovery.
