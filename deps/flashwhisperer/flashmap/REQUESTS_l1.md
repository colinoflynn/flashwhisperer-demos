# Requests from the L152RE shim

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

What `rigs/fw_map_l1/` needs from the host package (`device.py`,
`experiments.py`, `infer.py`, `report.py`, `__main__.py`) and from
`PROTOCOL.md`, neither of which I own. Both items below are worked around in
the shim, so nothing here blocks a `map` run - but item 1 produced a wrong
answer, not an inconvenience, and is marked as such.

Evidence: `research/targets/stm32l152.md` §2, `flashmap/l152re.json`.

The part this comes from is the least accelerated one the protocol has met:
STM32L152RE, Cortex-M3, no cache of any kind, and a `LATENCY` field that is
one bit wide. Both items are consequences of that, and both will recur on
any F1/L0/L1-class part.

---

## 1. A knob with a precondition is not an axis - WRONG ANSWER (worked around by not advertising it)

Measured, STM32L152RE. `K` advertises knobs as independent axes and the
host sweeps the cross-product. This part's `FLASH_ACR` is not a set of
independent bits: RM0038 §3.9.1 makes `LATENCY = 1` and `PRFTEN = 1` legal
only while `ACC64 = 1`, and clearing `ACC64` requires clearing both first.

A shim that advertises `waitstates`, `prefetch` and `acc64` therefore gets
asked for `acc64=0, waitstates=1`, which the silicon will not hold. It has two
options and both are bad:

* Refuse the write. The host's wait-state calibration then finds no setting
  at which a miss is resolvable, and every structural claim comes back
  `unknown` - on a part that has a perfectly measurable 8-byte latch.
* Satisfy the precondition (what the first version of this shim did, and
  what the reference manual tells you to do). The cell is then measured
  correctly and *labelled wrongly*. Four of the host's eight configurations
  were duplicates of the `acc64=1` cells carrying the name `acc64=0`, and the
  verdict was

  ```
  acc64 -> read_width : unknown      no complete pair of configs
  acc64 -> latch      : unknown      no complete pair of configs
  ```

  which reads as "64-bit access reaches nothing" and is really "this axis was
  never varied". Confirmed on the board:

  ```
  S acc64 0      -> ok acc64=0       K: waitstates 0  prefetch 0  acc64 0
  S waitstates 1 -> ok waitstates=1  K: waitstates 1  prefetch 0  acc64 1
  ```

  The readback contract is honoured at every step - `S waitstates` reports
  `waitstates=1`, truthfully - and the host is still misled, because nothing in
  the protocol lets a reply say *"and this also moved `acc64`"*.

Worked around by not advertising `acc64` and holding `ACC64 = 1`. That is
sound on this part for a reason that will not generalise: `ACC64 = 0` forces
`LATENCY = 0`, and at zero wait states every flash structure reads flat by
construction (`MEASURING_CHANNELS.md` B3), so the dropped corner is one where
the instrument has no resolution anyway. On a part where the dependent knob
*is* separately measurable, dropping it loses a real axis.

What would fix it. Any of these, in order of preference:

1. Let `K` declare a constraint alongside the values, e.g.
   `acc64 0,1 1 requires:waitstates=0|acc64=1`, and have the host skip cells
   that violate it. Cheapest for shims, and the host already parses the line.
2. Let `S` reply with every knob it moved - `ok acc64=1 waitstates=1` - and
   have the host re-label the cell from the reply rather than from the request.
   This is strictly more honest than the current contract and costs one loop.
3. Failing both, have the host issue `K` after every `S` and label cells from
   that. No protocol change at all, one extra round trip per cell, and it would
   have caught this.

Until one of them exists, `PROTOCOL.md`'s *Adding a part* section should say:
do not advertise a knob whose legal values depend on another knob's value.

---

## 2. `read_width` has no instrument on a part with a one-bit `LATENCY`

Measured, STM32L152RE. `infer` fits the read width from the saturation
point of a cold forward `walk`, and needs the flash penalty to clear a
threshold. The capture warning reads:

```
no advertised wait-state setting delivered a 4-cycle flash penalty
(measured 0:0 1:0.032)
```

`LATENCY = 1` is the largest setting this part has. It is worth a clean
1 cycle on the single-shot `reread` sweep - enough for `latch` to resolve
`8 B × 1` from 89/89 offsets at high confidence - and 0.032 cycles per
access on the cold walk. The two disagree by a factor of thirty, and the walk
loses for a reason specific to it: a sequential forward walk is exactly what a
2 × 64-bit prefetch buffer covers, so the wait state is already hidden by the
time the walk can measure it.

So the report carries `read_width = unknown [none]` beside
`latch = 1 entry x 8 B [high]`, which is correct as a statement about two
separate claims from two separate primitives, and is confusing as a summary of
a part whose flash read width is plainly 8 bytes.

This is not the nRF52840's `_miss_scale` problem from
`REQUESTS_h7_nrf.md` §1 - that was a loop-body artefact that a better-written
walk fixed, and this walk is already written that way. Here there is genuinely
no wait state left to over-program.

What would fix it. Either:

1. When the latch resolves a granularity at high confidence and the walk does
   not saturate, let `read_width` inherit the latch's granularity with its own
   confidence and a stated basis (`"from latch granularity; walk did not
   saturate"`). The six parts measured so far agree on granularity = read width
   six times out of six, so this is a documented inference and not a guess.
2. Or keep them separate but have `report` say *why* `read_width` is unknown in
   the one-line summary, rather than only in the caveat block.

Option 1 also unblocks everything downstream: `cache`, `fill_unit` and every
`data_reuse` verdict in `knob_map` currently come back `unknown` on this part
solely because the eviction surface has no line to be fitted at.

---

## 3. A data point for the `alt` vs `reread` note - the gap is `loopmem`

Not a request; a measurement the protocol note should have.

`PROTOCOL.md` warns that the amplified `alt` probe and the single-shot `reread`
disagree, and records the F429's direction: `alt` reads `LATENCY − 1` and
`reread` reads `LATENCY`. On the L152RE the disagreement runs the *other* way,
and it is entirely a `loopmem` effect:

| probe | `loopmem` | cycles per access at `LATENCY = 1` |
|---|---:|---:|
| `reread` (single shot) | 0 | 1 |
| `alt` (20 000 reps × 32) | 0 | 1.49988 |
| `alt` (20 000 reps × 32) | 1 | 0.99997 |

With the probe loop in flash - sharing the array with its own instruction
fetch - the amplified probe agrees with the single shot to four decimal places
and with `LATENCY` exactly. The half cycle is contributed by the *SRAM*
resident loop, which is the configuration every structural claim is taken from.

So "`alt` and `reread` disagree" is not a fixed per-part offset to be
calibrated out; it moves with a knob the protocol already defines. Worth one
line in the note, because a shim author reading the F429 number will expect a
*negative* offset and get a positive one.

For the record, the same sweep says the flash data path has no hit/miss cost
whatsoever at `LATENCY = 0` - `+0.00000` cycles per access in all four flash
configurations, both `loopmem` values, with a clean-zero SRAM twin. That is
`MEASURING_CHANNELS.md` B3 confirmed at five decimal places by the amplified
probe, and it is what makes `research/targets/stm32l152.md` §4 a result rather than a
measurement error: the AES leaks one cycle at `LATENCY = 0` in a configuration
where the data path, measured on its own, does not.
