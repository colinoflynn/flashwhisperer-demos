# `fw_riot_fido2_hid` — arm B: the stock RIOT authenticator, over USB

Arm B of the CTAP2 lead in
[`the demo README`](../../the demo README)
§1. **There is no firmware in this directory.** The victim is RIOT's own
`tests/sys/fido2_ctap_hid`, unmodified, on an nRF52840-DK; this directory holds
the build wrapper, the optional trigger patch, and the reasons.

Host side: [`demos/fido2_usb/host/ctap_probe.py`](../../demos/fido2_usb/host/ctap_probe.py).
Arm A, the on-chip ground truth on the same cipher, is
[`the on-chip arm (not shipped here)`](the on-chip arm).

## What the probe does, and why it is free

`authenticatorGetAssertion` with an allow list of forged 165-byte credential
blobs (`ctap_cred_id_t` = 136 B ciphertext + 16 B MIC + 13 B nonce, and RIOT's
parser bounds the copy with `sizeof`, so any other length never reaches the
cipher). For each entry the authenticator runs a full AES-CCM unwrap under
`_state.cred_key`, and:

* the nonce comes out of the attacker's own blob;
* `_find_matching_rks` runs at `ctap.c:632`, **before** the PIN check at `:638`
  and **before** the user-presence test at `:678`;
* `options.up = false` skips the presence test entirely — it is inside
  `if (req.options.up)` — so no button is pressed and no human is involved;
* a failing MIC still answers, `CTAP2_ERR_NO_CREDENTIALS` at `:701`;
* the allow list holds up to `CTAP_MAX_EXCLUDE_LIST_SIZE = 0x14` entries, so one
  USB request buys of order 400 chosen-input AES block operations.

Line numbers are quoted against RIOT commit
`f59dcdace51d34218c24339d299ebc3777ec45bc`; the Makefile warns if the checkout
is elsewhere.

## Hardware

nRF52840-DK with **two** USB cables:

* **J2** — interface MCU: SWD flashing and the debug VCOM.
* **J3** — the nRF52840's own USB: this is the authenticator the host talks to.
  Arm B does not work without it, and it is the one cable this bench may not
  already have plugged in.

Optional: a scope or logic analyser on **P0.13 (LED1)** for the trigger arm.
`boards.py: nrf52840`, probe `1050219420`. Claim the board before flashing.

## Build

```bash
make RIOTBASE=~/RIOT flash                   # stock, UP disabled as the test app ships it
make RIOTBASE=~/RIOT UP=keep flash           # UP enabled: proves options.up=false is enough
make RIOTBASE=~/RIOT trigger                 # + a pin around the unwrap loop
```

Then, from the repository root:

```bash
python demos/fido2_usb/host/ctap_probe.py info
python demos/fido2_usb/host/ctap_probe.py grid --n 200
```

Run `grid` first. It exists because of the one number that decides this arm.

## The blocker on Windows: a FIDO HID device is invisible without elevation

The stock authenticator builds, flashes, boots (`main(): This is RIOT!` on the
debug UART) and **enumerates**: `Get-PnpDevice` shows
`HID-compliant fido`, `HID\VID_1209&PID_7D01`, status OK, and the nRF's own
`POWER->USBREGSTATUS = 0x00000003` (VBUSDETECT | OUTPUTRDY) confirms the J3 cable
is live. On-chip, `USBD->ENABLE = 1` and `USBD->USBPULLUP = 1`.

And yet `hid.enumerate()` returns **no** device with usage page `0xF1D0` and none
at `1209:7D01`. That is Windows policy, not a fault: since Windows 10 1903 a
non-elevated process may not open a HID device on the FIDO usage page, and
hidapi's enumeration — which opens each device to read its attributes — therefore
**omits it silently**. Absence from `hid.enumerate()` says nothing about whether
the device is there.

So arm B needs **one elevated shell**:

```bash
python demos/fido2_usb/host/ctap_probe.py info
python demos/fido2_usb/host/ctap_probe.py grid --n 200
```

run from an Administrator prompt. If even elevated access is refused, the
Windows FIDO stack is holding the device exclusively, and the routes are then
(a) `usbipd-win` (installed on this bench) to attach the device to WSL, where
Linux applies no such policy, or (b) the USB analyser. Do **not** "fix" this by
changing the report descriptor's usage page: that is no longer the stock
authenticator, and the exclusivity is a property of every real FIDO device.

**This elevated run is now also the fastest diagnostic for the host rig.**
[`../fw_f4_ctaphost/`](../fw_f4_ctaphost) reaches the authenticator over its own
USB — VBUS, enumeration, descriptors and bulk transfers all working — and gets no
CTAPHID reply. One successful elevated run would say whether the device replies to
*any* host, which decides whether that rig is debugging its own framing or the
firmware's.

## The route that fixes both problems at once: be the host

An MCU host removes the Windows policy *and* most of the quantisation, because
**`bInterval` is a host scheduling policy, not a property of the link**. A host
that does not implement periodic scheduling simply places IN tokens where it
likes; the device NAKs until it is ready, and on the STM32 OTG core a
non-periodic channel **halts on NAK and reports it in `HCINT`** — a one-bit
"done yet?" comparator at a cadence we choose.

This bench has already built and measured exactly that, for a different target:
[`its predecessor USB-host rig/`](its predecessor USB-host rig) is a bare-metal OTG FS host on a
NUCLEO-F429ZI that enumerates a device and drives an oracle, and against sboot's
DFU it measured **IQR 444 ns where the Windows host gave 42 400 ns** — ~100× —
resolving **+36.9 µs per additional AES block**
([`../../results/sboot/SBOOT_RESULTS.md`](../../results/sboot/SBOOT_RESULTS.md)
§ *Timing: better than predicted*). Against our 0.54 µs per-unwrap signal that
is a usable oracle rather than a statistical siege.

**Prefer the F429 over an H7 for this.** The rig exists for the F4, with
a shared CMSIS header behind it; the H7 rigs run off a hand-written
`stm32h7_min.h` with no OTG definitions, so an H723 host means writing the
OTG_HS register set *and* the H7 USB clock path (PLL3/HSI48 48 MHz, `PWR`
USB regulator) before the first token goes out. The measurement gains nothing
from the faster core — resolution is set by the wire and by TIM2, not by CPU
clock. Choose the H7 only if the F429 is unavailable.

Three things are new relative to the sboot host, and the first is the one that
will bite:

1. **VBUS.** sboot's target ran with `NOVBUSSENS`, so that host never had to
   supply 5 V. The nRF52840 will not pull up without VBUS — `USBREGSTATUS` read
   `0x3` only because the PC was feeding it. A NUCLEO-144 host must enable its
   own port power switch (`PG6` on/`PG7` overcurrent on this board family,
   worth confirming against the schematic) or feed 5 V into the cable.
2. **CTAPHID is an interrupt endpoint pair** (OUT `0x01`, IN `0x81`, 64-byte
   reports). Driving them as *non-periodic* channels is what buys the NAK
   comparator; the token on the wire is just IN or OUT, so the device does not
   care, but this is the one design choice to verify early rather than assume.
3. ~~**Whether hammering IN costs the victim anything.** On the nRF52840 an IN
   endpoint with nothing queued is expected to NAK in hardware…~~ **Measured, and
   the premise was wrong**: an unarmed interrupt IN endpoint on this device
   answers with a **zero-length packet** (`XFRC`, 0 bytes), not a NAK, and it does
   so indefinitely. Two consequences — a NAK count is *not* the free poll-count
   metric it looked like, and whether a ZLP costs the victim CPU time is still
   open. See [`../fw_f4_ctaphost/README.md`](../fw_f4_ctaphost/README.md).

Also inherited from that campaign, and worth reading before starting: the
**frame-phase artifact** and the frame gate that removes it, plus that **IQR is
not the sigma that drives recovery** (sd was 7.5 µs over the same traces, so
median-over-repeats).

## Two build traps, both of which read as a broken toolchain

Recorded because each cost a cycle and neither error message points at its cause:

1. **Clone RIOT from inside WSL, not from Windows.** A Windows-git clone applies
   CRLF to RIOT's shell scripts, and the build dies with
   `/bin/sh^M: bad interpreter` from
   `dist/tools/generate_pp_successor_header/generate_pp_successor_header.sh`.
   This is the same hazard `CLAUDE.md` pins `.gitattributes` for in this
   repository; RIOT has no such protection. `git -c core.autocrlf=false clone`
   inside WSL, into a WSL-side path (which is also much faster to build in than
   `/mnt/c`).
2. **Never pass `CFLAGS=` as a make ARGUMENT to a RIOT app.** A command-line
   variable assignment overrides every internal assignment in the sub-make, so
   it wipes RIOT's own CFLAGS — including the `-DCPU_MODEL_*` define its CPU
   headers dispatch on. The symptom is
   `cpu_conf.h: #error "The CPU_MODEL of your board is currently not supported"`
   followed by a hundred undeclared-CMSIS errors, which looks like a missing
   CMSIS package and is not. This Makefile puts it in the **environment**
   instead, where RIOT's `CFLAGS +=` appends to it.

## The number that decides this arm: `bInterval = 5`

RIOT sets both HID interrupt endpoints to a 5-frame polling interval
(`sys/usb/usbus/hid/hid.c:127` and `:138`). On full-speed USB — which is what
the nRF52840 is — the host therefore looks for the reply on a **5 ms grid**,
while a single credential unwrap is **828 µs** of work at 64 MHz — measured, see
[`demos/fido2_usb/host/RESULTS.md`](../../demos/fido2_usb/host/RESULTS.md) §4.

So the USB-visible latency is **quantised far above the effect**. The first
draft of this file called that a **threshold** oracle like Wi-SUN's saturating
clamp in [`the demo README, CLOSURES.md`](the demo README, exposure/CLOSURES.md).
**That was wrong, and the difference matters for how this arm is run.** Wi-SUN's
clamp is genuinely zero below its threshold. A poll grid is not: the work still
pushes the reply into a later frame, so with the request phase dithered across
the poll period the **expected frame count is linear in the work**, and
averaging recovers the fine structure at `(σ_eff / δ)²` traces with
`σ_eff ≤ 5 ms/√12 ≈ 1.44 ms`. Lossy channel, large constant — not a wall.

Three consequences:

* **The allow-list is an amplifier, not a parking brake.** Each entry adds ~20
  chosen-input block operations while the quantisation noise stays fixed, so 20
  entries buy ~20× the signal for free. They cannot *park* the mean on a frame
  boundary: one entry is 828 µs, about 17 % of a grid period, and the only
  finer dial in the request is the `rp_id` length, which feeds a single SHA-256
  in `_find_matching_rks` and spans tens of µs. `sweep` measures the curve
  because its **slope** is the amplifier's gain, not because a step in it is the
  operating point.
* **Dither the inter-request gap on purpose.** Back-to-back requests can
  phase-lock to the poll grid, and a constant phase turns the quantiser into the
  pure threshold this file first mistook it for. `grid` is what shows whether
  the phase is wandering; if the histogram collapses to one mode, insert a
  randomised delay before blaming the channel.
* **The quantity per candidate is a mean frame count**, over many repetitions.
  How many is unmeasured; the envelope in
  [`the demo README`](../../the demo README)
  §1 is 10⁶–10⁷ requests, i.e. hours to days, and it is arithmetic on an
  unmeasured per-collision cost rather than a result.

What could still close this arm is **not** the grid but the victim's own
non-cipher variance — flash writes, thread scheduling, USB interrupt handling —
all of which sit inside the same interval.

The trigger arm is what tells you whether the loss is the USB grid or something
else: raise the pin around the unwrap, time it on-chip, and compare against the
same requests' USB latency. That comparison — probe-visible interval versus
wire-visible interval — is the measurement the ledger's wM-Bus rows say to make
before claiming an attack.

## What this arm does not settle

* **The probe has never spoken to the device.** The firmware runs and the device
  enumerates; the host side is blocked on elevation (above). The 5 ms figure is
  still read from RIOT's source, not measured on the wire.
* **`hid` is not the only shape of host-side access.** The CBOR request the probe
  builds was validated offline by decoding it back (clean parse, `allowList` of
  165-byte ids, `options.up = false`), so the encoder is not the unknown here —
  access is.
* **`hid` versus a USB analyser.** Host-side timestamps include the host's own
  scheduling. If `grid` shows the reply pinned to the grid with no usable
  structure, the next step is a hardware USB capture, not more repetitions.
* **The authenticator's flash writes.** `fido2_ctap_mem_write_state_to_flash`
  runs on some paths and costs milliseconds; the probe's chosen path (unwrap
  fails, no credential made) should not touch it, but that is an inference from
  reading `ctap.c`, not a measurement.
* **Whether a real FIDO2 deployment would run RIOT's authenticator at all.**
  This is a research implementation. The cipher findings in
  [`the demo README`](../../the demo README)
  do not depend on that; this arm's practical severity does.
