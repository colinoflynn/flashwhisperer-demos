# RIOT FIDO2 on the nRF52840 **Dongle** — the realistic target

The campaign measured the channel on an nRF52840-**DK**
([`../../demos/fido2_usb/host/RESULTS.md`](../../demos/fido2_usb/host/RESULTS.md)). This rig
builds the same RIOT authenticator for the nRF52840 **Dongle**, which is a more honest
target for one reason: **it has no on-board debugger.** Everything has to go through the
USB port, which is what the threat model claims.

## What you need to attach

**Nothing but the Dongle in a USB port.** No J-Link, no SWD wiring, no debug probe.

The Dongle ships with Nordic's Open USB Bootloader, and RIOT flashes through it:
`boards/nrf52840dongle/Makefile.include` sets `PROGRAMMER ?= nrfutil`, with a static MBR in
the first 4 KB, a 128 KB bootloader at the end, and 892 KB for the application
(`ROM_OFFSET = 0x1000`, `ROM_LEN = 0xdf000`).

1. Put it in DFU mode: press the **RESET** button (the small side button, SW2). The green
   LED pulses when the bootloader is running.
2. Note the serial port it appears as.
3. `make flash PORT=COM_n_` (or `/dev/ttyACM0`), which runs
   `nrfutil dfu usb-serial --port=$(PORT) --package=<hex>.zip`.

You need `nrfutil` on the path. Nothing else.

> **This overwrites whatever is on the Dongle**, including any SoftDevice — the Nordic
> bootloader layout RIOT targets leaves no room for one. Use a Dongle you are happy to
> repurpose.

## Two builds, and why both

```bash
make                  # user presence ENABLED  -- the shipping default
make DISABLE_UP=1     # user presence disabled -- what RIOT's own test app does
```

RIOT's `tests/sys/fido2_ctap/Makefile` hardcodes `CONFIG_FIDO2_CTAP_DISABLE_UP=1`, and that
single flag is the difference between a demonstration and a realistic target. The two halves
of the attack respond to it differently, which
[`the demo README, exposure/FIDO2_STANDARD_VIEW.md`](the demo README, exposure/FIDO2_STANDARD_VIEW.md)
works through:

* **The timing oracle survives user presence.** CTAP 2.0 §5.2 locates allowList credentials
  in **step 1** and collects consent in **step 7**, so the decryptions the attack measures
  have already happened — and an attacker sends `up: false`, which the standard sanctions for
  pre-flight probes, so step 7 never runs at all.
* **Obtaining a credential ID does not.** `makeCredential` requires consent, so an attacker
  with only their own USB host cannot mint one. They get one by being, observing, or phishing
  the relying party instead — a credential ID is handed to the RP by design.

Build `DISABLE_UP=1` to reproduce the campaign, and the default to test the realistic case.

## What the missing debugger costs the bench (not the attacker)

Two things the DK harness used are unavailable, and neither is an attacker capability:

| DK harness used | on the Dongle | replacement |
|---|---|---|
| reset the victim over SWD between probes | no SWD | the host **cuts VBUS** — `vbus_set()` in [`../fw_f4_ctaphost/main.c`](../fw_f4_ctaphost/main.c), with over-current sensing. A real attacker's host can do exactly this. |
| write a known `cred_key` to score each stage | no SWD | **give it up.** The Dongle generates its own key on first registration, the run is blind, and the only verdict is whether the search finds a key satisfying the oracle. |

Losing per-stage scoring is a real loss of *diagnostics*, not of validity: a wrong key cannot
satisfy a 128-bit oracle block, so the final search is self-validating. What it means in
practice is that a failed run says "no key" without saying which stage was wrong — so the
DK should stay in the loop for method development, and the Dongle used to demonstrate.

`set_cred_key.py` will not work against this board, and neither will `reset_boards()`'s SWD
path. Use the `m` command on the host rig to capture a credential ID and
[`../../demos/fido2_usb/host/capture_cred.py`](../../demos/fido2_usb/host/capture_cred.py) to
derive the oracle from it — that path needs no secret and no debugger.

## How it builds

The build happens **in RIOT's own app directory**, with its Makefile patched and restored
around it. An out-of-tree staged copy was tried first and is not worth the trouble: RIOT's
test apps chain relative includes (`../Makefile.sys_common` →
`../../Makefile.tests_common`), so a copy has to sit at exactly the right depth or the chain
breaks, and reconstructing the module list by hand fails with *"Required modules were
disabled using DISABLE_MODULE: auto_init_usbus"* because that include is what wires the USB
stack up. The `restore` step runs even when the build fails.

RIOT is fetched, not vendored — point `RIOT=` at a checkout. The campaign used
`f59dcdace51d34218c24339d299ebc3777ec45bc`.

**If the build dies with `/bin/sh^M: bad interpreter`**, the RIOT checkout has CRLF line
endings — the trap [`../../CLAUDE.md`](../../CLAUDE.md) records for this repo's own firmware.
Normalise the shebang scripts under `dist/` to LF.

## What this rig does not settle

It builds and flashes.

> **Superseded 2026-09-29.** A full attack has now been run on this board and it is the
> campaign's headline result: a 13-stage gated ladder of ~19.5 h plus a 5 h `k[15]`
> matched filter and 12 minutes of offline search recovered
> `cred_key = 353bc17144c02ceebca79dc4e634ab13`, and with it the ECDSA P-256 private key
> of a credential the rig captured over USB — on a board with **no debugger of any
> kind**. See [`../../demos/fido2_usb/host/RESULTS.md`](../../demos/fido2_usb/host/RESULTS.md)
> §5m. The VBUS power-cycle **was** exercised as the reset for the whole of it, with
> **zero escalations across 13 stages**.
>
> Two facts a reader of this rig now needs, neither recorded below: this build is
> **pad 0** (`Te0` at `0x0000cc50`, and `0x0000ce90` for the other UP variant, both read
> off the flashed image), and pad 0 is the **only** pad whose flash lines are XOR cosets,
> which is what makes the relation arithmetic exact here.

The original caveat, kept for the record:

* no attack had been run against a Dongle when this was written. In particular the
VBUS power-cycle has not been exercised as a substitute for the SWD reset in a long
unattended campaign, and that is the one substitution most likely to behave differently
under thousands of repetitions — the DK campaign's escalation ladder exists precisely
because reset paths misbehave at scale.
