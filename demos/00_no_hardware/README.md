# Start here: recover a key with nothing plugged in

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

```bash
pip install -e deps/flashwhisperer
python demos/00_no_hardware/run.py
```

That replays every capture in `demos/*/vectors/`, recovers the key where there
is one to recover, and checks each result against what that vector's `.json`
says should happen. It takes a couple of minutes and needs no board, no
toolchain, no vendor SDK and no network.

It is also the repository's own regression test, which is why it runs in CI:
if the analysis half moves under us, a vector that used to give up a key stops
doing it here.

## What it checks, and why the controls are half of it

A failed recovery and a null are the same thing to look at, so each demo ships
at least one vector that must NOT yield a key, and `run.py` fails if one
does. For OSCORE that control is the same firmware with its S-box copied into
RAM: one changed line, same instrument, same security context, same analysis,
same table geometry. If the attack recovered a key from that, the attack would
be finding something other than the flash.

Three more controls print beside each recovery, all of them labelled with the
key and therefore diagnostics rather than attacks:

* the effect itself, as a pooled z over the byte pairs;
* the same with the timing permuted, which has to go flat;
* the same with a key that is not the victim's, which also has to go flat.

And the sign matters: a flash-row collision makes a trace FASTER, so a real
effect here is negative. A two-sided "signal" is a sign that something else is
being measured.

## What a green run does NOT mean

* Nothing was measured. This is arithmetic on numbers that were measured
  once, on one bench, by one instrument. Every claim about what leaks rests on
  that bench run.
* It does not check the firmware. No image is built and no ELF is read, so
  nothing here confirms that the table address in a vector's json is the
  address in the image the capture came from.
* It does not check the compression. `host/make_vector.py` is what verifies
  that a packed vector regenerates its capture byte for byte, and it does that
  when the vector is made, refusing to write one that does not.
* One capture, conditioned one way, per claim. The trace counts are rungs
  on a ladder, not thresholds.
