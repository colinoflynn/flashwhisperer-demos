# `fw_f4_ctaphost` — a bare-metal USB host that drives RIOT's CTAP2 authenticator

Arm B of the CTAP2 lead in
[`the demo README`](../../the demo README)
§1, on a NUCLEO-F429ZI driving the nRF52840-DK's own USB. Built on
[`its predecessor USB-host rig/`](its predecessor USB-host rig)'s proven OTG bring-up; everything from the
includes down to the CTAPHID section is that rig unchanged.

**Why a host rig rather than the PC:** Windows will not let a non-elevated
process open a HID device on the FIDO usage page, and — the better reason —
`bInterval` is a *host scheduling policy*, not a property of the link. RIOT asks
for 5, which on a PC host quantises every reply onto a 5 ms grid. A host that
does not implement periodic scheduling does not pay that, and this one does not.

## Status: the oracle works, and the FLASH-LINE footprint is now measurable through it

The headline moved on 2026-09-24: not just "the host can see the AES" (below) but
**the host can see which flash lines the AES touched** — the rate at which the reply
beats the earlier poll goes from 14.0 % under a pseudorandom CCM nonce to 99.0 %
when the twelve chosen nonce bytes collapse the round-1 lookups onto one line,
`z = 16.8`, and a random nonce never beat it at all in 179 probes against a
non-zero key. Numbers, controls and bounds:
[`../../demos/fido2_usb/host/RESULTS.md`](../../demos/fido2_usb/host/RESULTS.md) §5c.
The rest of this section is the transport result that had to come first.

## The oracle works, over our own USB

Measured 2026-09-24. `f429_other` (COM19) CN13 ↔ nRF52840-DK J3; the DK's J2
stays on the PC for SWD. Victim is RIOT's **stock** `tests/sys/fido2_ctap_hid`.

The full chain runs: VBUS → enumeration → CTAPHID channel → `getAssertion` with
forged credential blobs → **`0x2E = CTAP2_ERR_NO_CREDENTIALS`**. That status is
the oracle: to produce it the authenticator parsed the request, ran
`_find_matching_rks`, AES-CCM-unwrapped every attacker-supplied blob under
`_state.cred_key`, found no match, and answered — with no PIN, no button, and no
user in the loop.

**And the reply time moves with the cipher work:**

| allow-list entries | request bytes | reply latency | Δ vs 1 entry |
|---|---|---|---|
| 1 | 244 | **11 861 µs** | — |
| 3 | 616 | **14 187 µs** | +2 326 µs (≈1.16 ms/entry) |

Arm A measured one unwrap at **828 µs** on-chip
([`../../demos/fido2_usb/host/RESULTS.md`](../../demos/fido2_usb/host/RESULTS.md) §4),
so ~1.16 ms per entry is the same quantity seen through the transport with the
per-entry loop overhead on top. **The host can see the AES.**

Timing is TIM2 at 72 MHz, 13.9 ns/tick, from the last OUT report being accepted
to the first IN that returns data.

## Six bugs, all mine, each recorded because none of them looked like itself

1. **Every "HID" transaction went to endpoint 0.** `g_ep_out`/`g_ep_in` are set
   only by `read_config_desc()`, and a test sequence that skipped `C` left them
   at 0. The device's hardware ACKs data on EP0 and the software correctly
   ignores a data packet with no SETUP — so this reads as *"the authenticator
   never answers"*, with `XFRC|ACK` on every OUT, ZLPs on every IN, and **no
   debug output at all on the victim**. `ensure_ready()` now enumerates and parses
   the descriptors before anything talks HID, and `hid_out`/`hid_in` refuse
   endpoint 0 outright.
2. **RIOT validates canonical CBOR before parsing a single field.**
   `ctap_cbor.c:826` calls `cbor_value_validate(&it, CborValidateCanonicalFormat)`,
   and canonical CBOR orders map keys by encoded **length** first, then bytewise —
   so in an allow-list entry `"id"` (text(2)) must precede `"type"` (text(4)).
   Getting it backwards returns `CTAP2_ERR_CBOR_PARSING` (0x10) **with no debug
   output**, because it fails before the parse loop that carries the `DEBUG()`
   lines. It is also why only requests *with* an allowList failed: the options map
   has one key and is trivially ordered.
3. **A NAKed IN can still deliver a full report.** Measured
   `IN[3] -> NAK got=64 [NAK]`. Test `got` before the return code, or a perfectly
   good reply is discarded — the same family as the `XFRC|NAK` trap
   [`its predecessor USB-host rig/main.c`](its predecessor USB-host rig/main.c) already documents, one
   level down.
4. **…and its twin on OUT: an ACKed packet can be reported as NAK.** Resending it
   makes RIOT see a duplicate sequence number and answer
   `CTAP_HID_ERR_INVALID_SEQ` (0x04). Accept `HCINT.ACK` as success.
5. **`hc_halt()`'s 200 000-iteration wait for `CHENA` is ~25 ms, and a NAKed
   interrupt poll spends all of it.** That made the reply time a *constant*
   50 137 ticks for 1 entry and for 10 — a measurement entirely of our own
   spinning. The poll path now uses a bounded guard (`g_fast_halt`); the control
   path keeps the long one, because that is what made enumeration reliable.
   **This is the bug that would have produced a confident null result.**
6. **A receive buffer that `hc_txn` never wrote looked like a valid reply.**
   `ctaphid_recv`'s buffer occupied the same stack addresses as `ctaphid_send`'s,
   so a decoded "INIT reply with our nonce echoed" was stale send data.
   Sentinel-filling every receive buffer before use is what exposed it, and it
   stays.

Two facts about the device, both measured rather than assumed:

* **PG6 is active-high** on this board: `P 1` → the nRF reports
  `POWER->USBREGSTATUS = 0x3` (VBUSDETECT | OUTPUTRDY). Read off the *device* over
  SWD, which is the only instrument that settles a switch polarity we have no
  schematic for. The sboot host never needed this — its target set `NOVBUSSENS`.
* **An unarmed interrupt IN endpoint answers with a zero-length packet, not a
  NAK.** So a ZLP is a *poll*, not a result, and returning it to a parser hands it
  an untouched buffer. (This corrects an expectation written in
  [`../fw_riot_fido2_hid/README.md`](../fw_riot_fido2_hid/README.md).)

## Commands

| cmd | effect |
|---|---|
| `V` | version, address, endpoints, CID, port and VBUS state |
| `P <0\|1>` | port power switch (PG6) |
| `O` / `R` | report / reset port |
| `E` | enumerate **and** parse the configuration descriptor |
| `C` | configuration descriptor, parsed, every endpoint printed |
| `I` | CTAPHID INIT |
| `K <len>` | CTAPHID PING of `len` bytes, echo compared byte for byte — transport test with no CBOR in the way |
| `B <n>` | dump the request bytes, so the host can decode what the firmware really built |
| `G <entries> [idlen]` | one timed `getAssertion`; `G 0` omits the allowList (single packet, the control) |
| `T <seed> <entries> <count>` | batch: `ticks naks ftrem status` per line, recovering from a wedged channel rather than abandoning the run |
| `F <us>` | per-poll timeout — the knob that decides whether the measurement sees the cipher |
| `D <us> <in-guard> <out-guard>` | post-send dither span, then the channel-halt guards **per direction**. The split is load-bearing: see below |
| `J <us>` | per-poll jitter span — a random gap before each IN token, which is what makes the reply time averageable |
| `N <v>` | force every chosen nonce byte of every credential id to `v`; `v > 255` leaves them pseudorandom. The amplifier, and only sound because the victim's key is zero — see [`../../demos/fido2_usb/host/RESULTS.md`](../../demos/fido2_usb/host/RESULTS.md) §5c |
| `Y <2\|3>` | channel type: bulk (non-periodic) or interrupt |
| `X` / `Z [n]` / `W <entries>` | raw single transaction / IN trace after an INIT / IN trace after a getAssertion |

## It is visible now — what it took

Superseded by [`../../demos/fido2_usb/host/RESULTS.md`](../../demos/fido2_usb/host/RESULTS.md)
§5c: the reply time resolves **which flash lines** the victim's AES touched, at
**t = 34** over 751 probes, with a clean split-half null. Three of the four things
the section below asked for turned out to be needed, and the fourth was wrong:

* **amplification was the decisive one**, and it was blocked by this rig's own
  halt guard rather than by the protocol (see *What this rig does not settle*);
* **a known key** made an equal-fill probe an amplifier at all — RIOT's `cred_key`
  is zero on a never-used authenticator;
* **the poll grid was never the obstacle**: the work difference simply shows up as
  extra polls (72.0 against 74.6), which is the linear regime, not a threshold;
* **deliberate dither was NOT needed and hurt** — `J 150` with bounded recovery
  read 48 % faults at 0.9 probe/s, against 1.9 probe/s and a usable spread with
  both off. The spread the averaging needs was already there from the host's
  round trips.

The section below is kept because the reasoning in it is how the fixes were
chosen, and because its σ arithmetic is still the right way to cost the next one.

## Why the collision term was not visible at first, quantitatively

The oracle answers and the reply time tracks how much AES ran. The *per-collision*
term — arm A's **0.54 µs** of input-dependent spread per unwrap — does not reach
the bus through this loop, and the reason is measurable rather than mysterious.

`G` prints the start time of each IN poll. From a clean state:

```
poll starts (us): 4 429 813 821 1209 1592 1600 1989 2372 2380
```

Intervals repeat as **~385, ~385, 8 µs**: the fast ones are polls issued straight
after a NAK, the slow ones pay `hc_prep_bulk`'s halt. The reply arrives on poll
9–10, at 2 449 µs.

And six consecutive probes with different inputs returned **identical** latencies
(2 450 µs, one 2 500). That is the finding: **the observable is deterministic and
385 µs-granular.** The host's polls and the device's processing are both driven
off the same OUT transaction, so they are phase-locked — there is no dither, and
**without dither there is no averaging gain at all**. Collecting more probes of an
identical number buys nothing, whatever the sample size.

So two properties of *this host loop*, not of the link, stand between the rig and
the goal:

| fix | effect on σ | requirement for Δ ≈ 0.76 µs (random input pair) |
|---|---|---|
| today: deterministic, 385 µs granular | no dither → **no averaging gain** | unreachable at any N |
| randomise the pre-request delay | σ_q = 385/√12 ≈ 111 µs | ~4×10⁵ probes |
| + tighten the poll loop to ~20 µs | σ_q ≈ 5.8 µs | ~10³ probes |
| + amplify to 20 entries (Δ ≈ 2.4–10 µs) | unchanged | **~10² probes** |

All three together put it within reach of a single afternoon; any one alone does
not. The tighter poll loop is the highest-value change because it attacks σ
directly, and the 8 µs gaps prove the core can issue tokens that fast — the 385 µs
is our own halt bookkeeping, not the bus.

## What this rig does not settle

* ~~**The multi-packet ceiling is a TRANSPORT bug in the OUT path**~~ — **found,
  and it was this rig's own channel-halt guard.** `hc_prep_bulk()` halts the
  channel before every transaction in *either* direction, so the short guard added
  to make the poll loop fine-grained was also applied to OUT. A continuation
  packet written into a channel the core has not finished disabling goes out
  twice, the peer sees a duplicate sequence number, and it answers
  `CTAP_HID_ERR_INVALID_SEQ` (0x04). The guard is now **per direction** — short on
  IN, where it sets the measurement's granularity, long on OUT, where it is
  correctness — and with that:

  | request | before the split | after |
  |---|---|---|
  | `G 2 16` (3 packets) | **0x04** | ok, 3 354 µs |
  | `G 5 16` (4 packets) | **0x04** | ok, 6 654 µs |
  | `G 20 16` (13 packets) | **0x04** | ok, 23 275 µs |
  | `G 12 164` (full-length ids) | never reached | ok, 14 789 µs |

  So the CTAP2 allow list really does carry its documented 20 entries, and the
  amplifier the exposure analysis costed is available. Two corrections follow from
  this: the "fails at 5 entries or more" line was measuring the host, and the
  500-byte PING failure has the same cause — nothing was wrong with RIOT. What is
  *not* fixed is a residual **~30 % fault rate** at 8 entries, unchanged across OUT
  guards from 4 000 to 400 000 iterations, still `0x04`, and costly because each
  fault buys a re-INIT: it holds the probe rate near 2/s against a 10 ms probe.
  That is now the throughput limit and the next thing to attack.
* **Run-to-run stability is the biggest open problem, and it has a clear
  signature.** A probe sequence run **immediately after a flash** works; the same
  sequence after a plain `boards.reset` of the host stalls after the first few
  probes, with the host script blocked and the device silent. So something a flash
  does and a reset does not (a longer power-down of the OTG core, or the DK's USB
  re-enumerating) is load-bearing. Until that is understood, take captures in the
  same command that flashes — which is what
  [`../../demos/fido2_usb/host/usbhost_capture.py`](../../demos/fido2_usb/host/usbhost_capture.py)
  should be changed to do, and why the distribution below is thin.
* **Whether a 165-byte credential id is parseable at all.** 165 failed before the
  canonical-order fix, and the interesting hypothesis — TinyCBOR's
  `cbor_value_copy_byte_string` needs `len + 1`, so RIOT cannot parse back its own
  `sizeof(ctap_cred_id_t)` = 165-byte credential ids — has **not** been retested
  since. Do that before repeating it anywhere.
* **The distribution is thin.** Median 11 852 µs with **IQR 18.2 µs** is from
  n = 9 accepted probes plus a 6-probe run spanning 24 µs; a larger sample is in
  hand only for the transport, not yet for the statistic that matters. Two
  practical notes for whoever takes it further: the firmware's `T` batch stalls
  for minutes when the CTAPHID channel wedges, so
  [`../../demos/fido2_usb/host/usbhost_capture.py`](../../demos/fido2_usb/host/usbhost_capture.py)
  now issues **one `G` per probe** from the host and re-INITs on a bad line; and
  **never reset a board while its VCP is open** — that wedges the Windows CDC
  driver and the run hangs at 0 % CPU with no output, which cost two false
  diagnoses here.
* ~~**No key recovery over USB.**~~ **Superseded — this rig is the host that did it, twice.**
  `cred_key` recovered end to end on the nRF52840-DK
  ([`../../demos/fido2_usb/host/RESULTS.md`](../../demos/fido2_usb/host/RESULTS.md) §5i), and again
  on an nRF52840 Dongle with **no debugger of any kind** (§5m,
  `353bc17144c02ceebca79dc4e634ab13`), each verified by decrypting a credential the rig itself
  captured. The knobs the current results depend on are also missing from the command table
  below: `f <lo> <hi>` (the USB frame-phase gate, [`../../demos/fido2_usb/host/FRAME_PHASE.md`](../../demos/fido2_usb/host/FRAME_PHASE.md)),
  `g <us>` (inter-probe gap), `S <us>` (pre-poll silence) and `m` (capture a credential id).
* **`hc_txn` was modified** in two additive ways: it records the deciding `HCINT`
  in `g_hcint_last`, and `hc_halt`'s guard is switchable. Both are noted in the
  source at the point of change.
