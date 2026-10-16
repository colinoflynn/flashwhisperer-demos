# FIDO2 over USB: a credential key off an authenticator with no debugger

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be
human-edited for that real-life touch and typos.*

An nRF52840 Dongle runs RIOT's own `fido2_ctap_hid` test application,
unmodified, and answers CTAP2 requests over its own USB. A NUCLEO-F429ZI acting
as a bare-metal USB host sends `authenticatorGetAssertion` with an allow list of
forged credential blobs and times each reply. The authenticator's AES-128
`cred_key` came out of that timing: no debugger on the part, no trigger pin, no
console, and the key not known to the analyst while the ladder ran.

The probe is free in a way that is worth spelling out. `_find_matching_rks`
runs before the PIN check and before the user-presence test, `options.up =
false` skips presence entirely so no button is pressed and no human is
involved, a failing MIC still answers `CTAP2_ERR_NO_CREDENTIALS`, and the allow
list holds up to twenty entries - so one USB request buys of order four hundred
chosen-input AES operations from a device that is doing exactly what it is
supposed to do.

## Try it with no hardware

```bash
python tools/replay.py demos/fido2_usb/vectors/dongle_ladder_13stages.npz
```

```
   oracle      USB reply poll count, per forged credential blob: 1252646 kept, 13 stages
   relations   13/13 stages reproduce their recorded class, 0/13 with the labels
               shuffled, weakest margin 0.65 sigma
   RELATIONS  as expected in 0s
```

That says RELATIONS and not EXACT, and the difference is the demo rather than a
hedge.

## Two halves, and only one of them is cheap

| half | what it is | where |
|---|---|---|
| measurement | thirteen ladder stages, each sweeping 64 delta classes over forged blobs and taking the class with the lowest mean poll count. Six bits of a key-byte relation per stage | [`vectors/`](vectors), replayed above |
| search | the relations leave 2^44, and a CPU searcher at about 3 Gcandidate/s with VAES closes it - an hour and a half on ten cores | [`search/`](search), opt-in |

A replay checks the first. The second is twelve minutes to an hour and a half
of Rust, which is not a regression test, so it is not run here and not run in
CI. `expect_kind: relations` in the vector's json is how the suite knows that a
vector which yields no key is not therefore a control - this repository uses
`expect_recovery: false` for controls, and the two mean opposite things.

The key the search returned is `353bc17144c02ceebca79dc4e634ab13`, and it was
confirmed by unwrapping a captured credential rather than by comparing against
anything on disk. [`host/unwrap_credential.py`](host/unwrap_credential.py) is
that check, and it needs no secret: a candidate key either decrypts a real
credential id to something with CCM's structure or it does not.

## What the ladder measures, and the trap inside it

RIOT declares its `Te0` with no alignment attribute, and this victim's copy
lands at pad 4. So the line of entry `i` is `(i + 1) >> 2`, and what a
collision identifies is a shared four-entry **window** rather than an XOR
class: the same six bits of information in an algebra the search's constraint
file cannot express.
[`host/constraints_from_campaign.py`](host/constraints_from_campaign.py) says
so in its own docstring, in capitals, because its `diff6` values are only valid
at pad 0. The 2^44 figure comes from the window algebra, not from that file.

The constraint format carries a second condition that is easy to miss: it names
one anchor byte and gives every difference relative to it, so it can only
express relations that **reach** the anchor. A relation in a disconnected
component cannot be written down at all - which is how a ladder can know more
than its own output file, and why bridging stages were a requirement rather
than an optimisation.

## The null is the point, not the dip

An argmin over 64 classes is low by construction, so "margin over runner-up"
cannot be read directly.
[`host/stage_stats.py`](host/stage_stats.py) supplies the null by shuffling the
delta labels within the same capture, which preserves everything except the
association being tested, and it reports three things:

* the fraction of shuffles reaching the observed margin. On this Dongle that
  separated a gated stage at `p = 0.010` from an ungated one at `p = 0.590`
  **whose raw dip was larger**.
* the per-class spread of USB frame phase. The reply time depends on frame
  phase, so classes measured at different average phases can differ for a
  reason that has nothing to do with a collision. Ungated that read 1 330
  clocks and gated 25, which is what explained the two p-values above. A stage
  with a large spread is confounded whatever its p-value.
* the argmin in each phase half, which is an internal replication that costs
  nothing. The ungated stage's argmin moved between halves; the gated ones do
  not.

The replay above runs the cheap version of the first of those: shuffle once per
stage with a fixed seed, and none of the thirteen lands on its recorded class.

## Capturing it yourself

```bash
./deps/fetch.sh riot
make -C demos/fido2_usb/victim            # RIOT's own test app, unmodified
make -C instruments/ctaphost              # the USB host that drives it
python demos/fido2_usb/host/ctap_probe.py --help
python demos/fido2_usb/host/dongle_gated_campaign.py --help
```

An MCU host rather than a PC, for two reasons. Windows will not let a
non-elevated process open a HID device on the FIDO usage page - and the better
reason is that `bInterval` is a host scheduling policy rather than a property
of the link. RIOT asks for 5, which on a PC host quantises every reply onto a
5 ms grid; a host that implements no periodic scheduling does not pay that, and
this one does not. It is worth about 100x on jitter.

The Dongle needs no debugger and cannot be given one: connecting a debugger to
an nRF52840 with APPROTECT engaged mass-erases it. That is why this demo's
blind arm is the one that matters - the part cannot be read out first even in
principle.

## What this does not settle

* The search is not run here, so a replay proves the relations and takes the
  key on the record of a run that happened once, on one machine.
* It is one authenticator and one key. RIOT's `cred_key` is generated once
  and then used for every credential, which is what makes it worth 2^44 of
  anyone's time; a stack that rotates per credential is a different problem.
* The pad is this image's accident. A rebuild moves it, and at pad 0 the
  same ladder would produce XOR classes the constraint file can express
  directly - fewer steps, same measurement.
* The weakest stage is 0.65 sigma and it is in the chain. It reproduces its
  class here and it passed its own shuffle null when it was taken, but a ladder
  whose weakest link is that thin is one re-measurement away from a different
  relation.
* Nothing here was measured on a shipping authenticator. It is RIOT's test
  application, which is the point - it is the stack a vendor would start from.
