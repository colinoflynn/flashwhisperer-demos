# The victim: stock RIOT, one build flag

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

A RIOT GNRC node on an nRF52840-DK that answers ICMPv6 echo and secures its
replies at the link layer. **Nothing in RIOT is patched.** The whole victim is
the three files here plus a generated one-line key header, and `diff` against a
fresh `./deps/fetch.sh riot` finds no change in the vendor tree.

Three things make that possible, and all three are RIOT's own doing:

* **The key is a build flag.** `CONFIG_IEEE802154_SEC_DEFAULT_KEY` is guarded
  by `#if !defined` at `sys/include/net/ieee802154_security.h:105`, so defining
  it from the application's `CFLAGS` is the supported way in. Leave the header
  out and the build runs on RIOT's own published default, the string
  `pizza_margherita`.
* **The channel and the PAN id are already right.**
  `CONFIG_IEEE802154_DEFAULT_CHANNEL` is 26 and
  `CONFIG_IEEE802154_DEFAULT_PANID` is `0x0023` at this pin
  (`sys/include/net/ieee802154.h:319,389`). Nothing to set.
* **Outbound security is on by default.** `netdev_ieee802154_reset`
  (`drivers/netdev/ieee802154.c`) calls `ieee802154_sec_init` and then sets
  `NETOPT_ENCRYPTION` to `NETOPT_ENABLE` whenever `MODULE_IEEE802154_SECURITY`
  is used. So a node that has been switched on is already securing its
  replies; there is no runtime step and no shell command in the capture path.

## Build and flash

```bash
./deps/fetch.sh riot                                  # the pin, sparse
python demos/riot_802154/victim/gen_key.py            # a fresh random key
cd demos/riot_802154/victim && ./build.sh             # prints the geometry
make flash BOARD=nrf52840dk RIOTBASE=../../../deps/riot
```

`build.sh` ends with the two things the attack needs and cannot guess:

```
image      bin/nrf52840dk/riot_802154_echo.bin
sha256     6d607d66edd5f09750d69bae3c68860599ed2cf54a67a40070c82a4362de1de3
Te0        0x0000f5f8  1024 bytes  section .text
geometry   line_shift=2 line_off=2  (row of a lookup is (index+2)>>2)
           in flash, so the read latch is in the path
```

**Read that `line_off` off your own build and do not copy it from here.** Te0
landed at `0x0000f5f8` in the build this demo's vector came from, which is 8
bytes into a 16-byte flash row, so `line_off` is 2 and not the 0 the
campaign's own earlier image happened to have. The offset is a property of
wherever the linker put the table, it moves when anything ahead of it in
`.text` changes size, and getting it wrong costs between two and ten times the
traces. `verify_build.py` is the only thing that should ever tell you.

`gen_key.py` prints the key, on purpose: the demo's claim is that the key comes
back out of the radio timing, and you cannot check that against a key you never
knew. `demo_key.h` is gitignored.

## The build is not quite the shipped binary, and here is the honest list

* `DEVELHELP=0`, which is RIOT's own default for a release build.
* The application is a shell and a message queue. A product would have its own
  application, which changes the code ahead of Te0 in `.text` and therefore
  moves `line_off` -- that is the point of reading it off the ELF.
* The key is a known one, because this is a demo.

What is NOT on that list: the cipher, AES-CCM*, the link-security module, the
radio driver, the table's contents, the compiler flags RIOT chooses, and the
read order the compiler emits. Those are the pin's.

## The control build, and what this demo did not re-measure

Moving `Te0` into RAM takes the channel away, and that is the one control that
speaks to the mechanism rather than to the trace count. It is also **the only
place this demo touches RIOT's source**, because a vendor table cannot be
relocated without editing the declaration that puts it in `.rodata`:
[`table_to_ram.py`](table_to_ram.py) does that one edit, keeps the original
bytes and takes `--restore`. `verify_build.py` then prints `NOTE: that address
is RAM`, and a capture taken against it must recover nothing.

**This demo ships no SRAM vector.** The re-run here took the flash arm only,
and saying so is better than shipping a control that looks like evidence. The
campaign that preceded it did measure the arm, and its numbers are the reason
to believe the mechanism: the internal encryption time went constant to the
cycle -- **14,058 cycles on every one of 994 of 998 frames**, the four
exceptions being upward interruptions -- and the slot-adjusted reply moved
67.78 µs earlier against a 67.21 µs internal change, with a return-to-flash
run restoring both. That is in the campaign write-up, not in this repository's
vectors.

## Optional: the victim's own cycle counter

[`OPTIONAL_DWT_PATCH.md`](OPTIONAL_DWT_PATCH.md) adds a linker-wrapped DWT
measurement of each `ieee802154_sec_encrypt_frame` call. **The attack does not
use it and the capture host never reads it.** It is there for when you want to
see how big the internal effect is before trying to see it from the air, which
is a reasonable first question and a much easier measurement. Adding it means
two lines in this Makefile and one file; the demo's own numbers were taken
without it.
