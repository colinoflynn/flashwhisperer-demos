# Reproducing these, in order, and the ways it fails quietly

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

Four stages, each of which is worth doing before the next one. Most of what
goes wrong goes wrong silently, so the order is chosen to make the failures
distinguishable rather than to get to a board quickly.

## 1. No hardware

```bash
./deps/fetch.sh --tools
pip install -e deps/flashwhisperer
./tools/verify.sh
python demos/00_no_hardware/run.py
```

If a key comes out, the analysis half is right and the vectors are intact. If
one does not, nothing further is worth trying, because every later stage ends
in the same recovery.

## 2. The instrument, against something that is not the victim

For the wired demos, point `ethtimer` at any DNS resolver first:

```bash
cd deps/ethtimer
tools/fetch_sdk.sh f746 && make -C firmware BOARD=f746
python -m ethtimer.cli --target dns --n 20000 --ip ... --gw ... --victim ...
```

A capture that comes back empty is nearly always the link, the IP, the cable or
the firmware - not the attack. This step is the only cheap way to tell that
apart from an adapter that is wrong, and those two failures look identical from
a capture with no records in it.

## 3. The victim

Build it, flash it, and then READ the table's address off the ELF before
capturing anything:

```python
>>> from flashleak import placement
>>> placement.row_offset_from_image("demos/<demo>/victim/Build/victim.elf")
(12, 134287884, 'AES S-box sbox @ 0x0801120c (.rodata, EXPOSED)')
```

Put that number in the vector's json. A rebuild moves it, a toolchain change
moves it, and an attack scored at the wrong offset can be a complete null on a
victim that leaks.

## 4. The capture, and then the key

Capture, pack, replay. The pack step is where the compression gets checked:
`host/make_vector.py` regenerates every block it is about to drop and refuses
to write a vector that does not reproduce byte for byte.

## The ways this fails without telling you

* A clone that exceeded MAX_PATH. On Windows a deep clone aborts part way
  through the checkout and leaves a tree that looks complete. Clone somewhere
  short with `core.longpaths=true`, and run `./tools/verify.sh`, which checks
  one sentinel file per dependency for exactly this.
* A dependency at the wrong commit. `git submodule update --init --depth 1`
  clones the default branch and lands on something that is not the pin, which
  for a vendor SDK builds fine and measures something else. `./deps/fetch.sh`
  fetches the pinned commit; `verify.sh` checks HEAD against `deps/PINS`.
* A vendor tree with edits in it. These demos rest on the victim being the
  vendor's own code. `verify.sh` fails if a dependency is dirty, and each demo
  keeps its deviations in its own directory so a diff against a fresh fetch is
  the check.
* The row offset. See stage 3. This is the one that has actually cost a
  result rather than an afternoon.
* A victim whose console is on. A diagnostic line on the victim corrupts
  whole groups of traces and the statistics still look fine. Print on request,
  never on a timer.
* A statistic instead of a channel. A pooled z of -20 that yields 0/16 key
  bytes is not a channel. Run the recovery, and run the control.
