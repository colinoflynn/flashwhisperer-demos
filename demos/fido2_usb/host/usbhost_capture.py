#!/usr/bin/env python3
"""Arm B capture: time RIOT's CTAP2 credential unwrap from a bare-metal USB host.

Drives [the USB-host instrument](../../../instruments/ctaphost) on a NUCLEO-F429ZI whose
CN13 is cabled to the nRF52840-DK's J3. The victim is RIOT's **stock**
`tests/sys/fido2_ctap_hid`: nothing on it is modified or instrumented, and the
only thing this script needs from the DK is SWD, to reset it.

What makes the reply an oracle: `getAssertion` with forged credential blobs makes
the authenticator AES-CCM-unwrap every allow-list entry under its device-lifetime
`cred_key` **before** the PIN check and **before** the user-presence test, and it
answers `0x2E = CTAP2_ERR_NO_CREDENTIALS` when none match. See
[`../../the demo README`](../../the demo README)
§1.

Why a host rig rather than the PC: `bInterval` is a host scheduling policy, not a
property of the link. RIOT asks for 5, which quantises a PC host's view onto a
5 ms grid; this host does not implement periodic scheduling and measures ~18 µs
IQR instead.

    python demos/fido2_usb/host/usbhost_capture.py check
    python demos/fido2_usb/host/usbhost_capture.py batch --entries 1 --n 300 \
        --npz demos/fido2_usb/host/usbhost_e1_300.npz
    python demos/fido2_usb/host/usbhost_capture.py sweep --max-entries 4 --n 60

What this script does NOT do: recover a key. It captures reply latencies and the
per-trace covariates (poll count, frame phase, CTAP status); the input bytes are
generated on the device from a seed the host passes, and mirroring that PRNG on
the host is not implemented yet -- so these captures characterise the transport,
not the cipher.
"""
from __future__ import annotations

import os as _os
import sys as _sys

_REPO_ROOT = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
_sys.path.insert(0, _REPO_ROOT)
_sys.path.insert(0, _os.path.join(_REPO_ROOT, "hardware"))

import argparse
import statistics
import time

import numpy as np
import serial

import boards  # noqa: E402

HOST_BOARD = "f429_other"     # the USB host; see hardware/boards.py for why the name
# The authenticator. The DK is reset over SWD; the nRF52840 Dongle has no debugger at all
# and is reset by cutting VBUS, which is the whole point of it as a target. Override with
# FIDO_VICTIM=nrf52840dongle rather than editing this, so a Dongle run and a DK run are
# the same code.
VICTIM_BOARD = _os.environ.get("FIDO_VICTIM", "nrf52840")
TICK_NS = 1000.0 / 72.0       # TIM2 at 72 MHz


def _clean(b: bytes) -> str:
    return b.decode("ascii", "replace").replace("�", "?").rstrip()


def reset_boards() -> None:
    """Reset the victim then the host, with NO serial port open.

    Resetting the F429 while its ST-LINK VCP is open wedges the Windows CDC
    driver: a later read blocks forever regardless of the pyserial timeout, with
    the process at 0 % CPU and no output. Measured twice, each time as a "batch
    mysteriously hangs". So the resets happen first and the port is opened after.
    Victim first so its USB stack is settled before the host enumerates it.
    """
    # A victim with no debugger cannot be reset here at all: the only reset it has is
    # the host cutting VBUS, and that needs the host's console, which by the rule above
    # must not be open yet. So for such a victim this resets the host only, and the
    # power-cycle happens inside bring_up() once the port is open.
    if boards.BOARDS[VICTIM_BOARD].get("no_swd"):
        boards.reset(HOST_BOARD)
        time.sleep(1.4)
        return
    boards.reset(VICTIM_BOARD)
    time.sleep(1.8)
    boards.reset(HOST_BOARD)
    time.sleep(1.4)


class Host:
    """The F429 host's UART console. Construct AFTER reset_boards()."""

    # 0.5 s, and NOT a generous 30: cmd() below reads a fixed cap of bytes, and
    # pyserial's read(n) only returns early when it has all n -- so every command
    # whose reply is shorter than cap costs the WHOLE timeout. At 30 s that made
    # bring_up() alone take 90 s and looked exactly like a wedged board: no
    # output, no CPU, three commands in. Every call here sleeps for its own reply
    # first, so the timeout is a backstop, not the wait.
    def __init__(self, port: str, timeout: float = 0.5):
        self.s = serial.Serial(port, 115200, timeout=timeout, write_timeout=5.0)

    def cmd(self, line: str, wait: float, cap: int = 6000) -> str:
        self.s.write((line + "\n").encode())
        time.sleep(wait)
        return _clean(self.s.read(cap))

    def bring_up(self, verbose: bool = False) -> None:
        """Power VBUS, enumerate, open a CTAPHID channel (boards already reset).

        """
        self.s.reset_input_buffer()
        no_swd = bool(boards.BOARDS[VICTIM_BOARD].get("no_swd"))
        # A victim with no debugger gets its ONLY reset here: reset_boards() could not
        # power-cycle it, because that needs this port and the port must not be open while
        # the boards are reset. And a bus-powered victim has to BOOT after VBUS rises --
        # RIOT, its USB stack, the CTAP thread -- where the DK was already running off its
        # own supply. 1.2 s was enough for the DK and is not enough for the Dongle:
        # measured, bring_up died with "GET_DESC(8) -> TIMEOUT n=0" until it was raised.
        seq = ((("P 0", 1.0),) if no_swd else ()) + (
            ("P 1", 3.0 if no_swd else 1.2), ("E", 7.0), ("I", 3.5))
        for line, wait in seq:
            out = self.cmd(line, wait)
            if verbose:
                print(out)
            if line == "E" and "VID=1209" not in out:
                raise RuntimeError(f"enumeration did not find the authenticator:\n{out}")
            # "cid=0x" alone is NOT a success: the firmware prints
            # "CTAPHID INIT -> TIMEOUT cid=0x01000000" on FAILURE, so the substring test
            # accepts a timed-out handshake. Caught on the Dongle, where timeouts are
            # common enough for it to matter.
            if line == "I" and ("cid=0x" not in out or "TIMEOUT" in out.upper()):
                raise RuntimeError(f"CTAPHID INIT failed:\n{out}")


def cmd_check(args) -> int:
    boards.require(HOST_BOARD)
    boards.require(VICTIM_BOARD)
    reset_boards()
    h = Host(args.port or boards.BOARDS[HOST_BOARD]["port"])
    h.bring_up(verbose=True)
    for entries in (0, 1, 3):
        out = h.cmd(f"G {entries} {args.idlen}", 6.0)
        line = next((x.strip() for x in out.splitlines() if "entries=" in x), "(no reply)")
        print(f"G {entries}: {line}")
        if "status=0x2e" not in line:
            print("   ^ expected status=0x2e (CTAP2_ERR_NO_CREDENTIALS)")
    return 0


def _batch(h: Host, entries: int, n: int, seed: int, idlen: int,
           budget: float = 300.0) -> tuple[np.ndarray, int]:
    """Collect n timed probes by issuing one `G` per probe from the host.

    NOT the firmware's `T` batch mode. `T` is faster in principle but a single
    wedged CTAPHID channel inside it costs the whole run, and long `T` batches
    were observed to stall for minutes. One command per probe means a wedge costs
    one probe: the host sees the bad line, re-INITs, and carries on. The cost is
    a UART round trip per probe (~30 ms), which is irrelevant next to the 12 ms
    of device work being measured.

    Rows are (ticks, polls, ftrem, status).
    """
    h.cmd(f"G {entries} {idlen}", 3.0)          # sets idlen, and warms the path
    rows: list[tuple[int, int, int, int]] = []
    errs, t0 = 0, time.time()
    while len(rows) < n and time.time() - t0 < budget:
        h.s.reset_input_buffer()
        h.s.write((f"G {entries} {idlen}" + "\n").encode())
        line = ""
        deadline = time.time() + 3.0
        while time.time() < deadline:
            ln = _clean(h.s.readline())
            if "entries=" in ln:
                line = ln.strip()
                break
        if not line:
            errs += 1
            h.cmd("I", 2.5)                      # channel wedged: re-open it
            continue
        # "entries=N idlen=M reqlen=R -> OK status=0xXX ticks=T ... naks=P ftrem=F"
        f = {}
        for tok in line.replace("->", " ").split():
            if "=" in tok:
                k, _, v = tok.partition("=")
                f[k] = v
        try:
            st = int(f.get("status", "0xff"), 16)
            tk, pl, ft = int(f["ticks"]), int(f["naks"]), int(f["ftrem"])
        except (KeyError, ValueError):
            errs += 1
            continue
        if st != 0x2E or tk == 0:
            errs += 1
            h.cmd("I", 2.5)
            continue
        rows.append((tk, pl, ft, st))
    return np.array(rows, dtype=np.int64), errs


def _report(rows: np.ndarray, entries: int, errs: int) -> dict[str, float]:
    us = np.sort(rows[:, 0] * TICK_NS / 1000.0)
    q1, q3 = float(np.percentile(us, 25)), float(np.percentile(us, 75))
    stats = {
        "n": len(us), "median_us": float(np.median(us)), "iqr_us": q3 - q1,
        "sd_us": float(np.std(us)), "min_us": float(us[0]), "max_us": float(us[-1]),
        "polls_median": float(np.median(rows[:, 1])), "errors": errs,
    }
    print(f"entries={entries} n={stats['n']} recovered-errors={errs}")
    print(f"  median {stats['median_us']:.3f} us | IQR {stats['iqr_us']:.3f} us | "
          f"sd {stats['sd_us']:.3f} us | min {stats['min_us']:.3f} | max {stats['max_us']:.3f}")
    print(f"  polls median {stats['polls_median']:.0f} | "
          f"statuses {sorted(set(hex(int(v)) for v in rows[:, 3]))}")
    # IQR is not the sigma that drives recovery -- the sboot campaign's caveat,
    # and it applies here: print both and let the reader pick.
    return stats


def cmd_batch(args) -> int:
    boards.require(HOST_BOARD)
    boards.require(VICTIM_BOARD)
    reset_boards()
    h = Host(args.port or boards.BOARDS[HOST_BOARD]["port"])
    h.bring_up()
    rows, errs = _batch(h, args.entries, args.n, args.seed, args.idlen)
    if not len(rows):
        print("no rows: the batch produced nothing")
        return 1
    stats = _report(rows, args.entries, errs)
    if args.npz:
        np.savez_compressed(
            args.npz, ticks=rows[:, 0], polls=rows[:, 1], ftrem=rows[:, 2],
            status=rows[:, 3], entries=np.uint8(args.entries),
            idlen=np.uint16(args.idlen), seed=np.uint32(args.seed),
            tick_ns=np.float64(TICK_NS), errors=np.uint32(errs),
            host=HOST_BOARD, victim=VICTIM_BOARD,
            note="stock RIOT tests/sys/fido2_ctap_hid; bare-metal OTG host; "
                 "bInterval ignored by design",
            **{f"stat_{k}": np.float64(v) for k, v in stats.items()})
        print(f"wrote {args.npz}")
    return 0


def cmd_sweep(args) -> int:
    """Latency against allow-list length: the amplifier's gain curve.

    Each entry adds ~20 chosen-input AES block operations. The SLOPE is what an
    attack gets for free from the allow list; arm A puts one unwrap at 828 us.
    """
    boards.require(HOST_BOARD)
    boards.require(VICTIM_BOARD)
    reset_boards()
    h = Host(args.port or boards.BOARDS[HOST_BOARD]["port"])
    h.bring_up()
    out = []
    for entries in range(1, args.max_entries + 1):
        rows, errs = _batch(h, entries, args.n, args.seed, args.idlen, budget=120.0)
        if not len(rows):
            print(f"entries={entries}: nothing (the multi-packet send is the known "
                  f"limit above 3 entries)")
            continue
        s = _report(rows, entries, errs)
        out.append((entries, s["median_us"], s["iqr_us"], s["n"]))
    if len(out) > 1:
        print("\nentries  median_us     IQR_us   n     delta_vs_prev")
        prev = None
        for e, m, i, n in out:
            d = "" if prev is None else f"{m - prev:+9.1f}"
            print(f"{e:>7}  {m:>9.1f}  {i:>9.3f}  {n:>3}  {d}")
            prev = m
    if args.npz and out:
        a = np.array(out, dtype=np.float64)
        np.savez_compressed(args.npz, entries=a[:, 0], median_us=a[:, 1],
                            iqr_us=a[:, 2], n=a[:, 3], seed=np.uint32(args.seed))
        print(f"wrote {args.npz}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default=None, help="override the host's port")
    ap.add_argument("--seed", type=lambda s: int(s, 16), default=0x1234)
    ap.add_argument("--idlen", type=int, default=164,
                    help="credential-id bytes; 164 is the largest RIOT's CBOR "
                         "parser has been seen to accept")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="bring up and probe 0/1/3 entries")
    c.set_defaults(fn=cmd_check)

    b = sub.add_parser("batch", help="N timed probes at one allow-list length")
    b.add_argument("--entries", type=int, default=1)
    b.add_argument("--n", type=int, default=300)
    b.add_argument("--npz", default=None)
    b.set_defaults(fn=cmd_batch)

    s = sub.add_parser("sweep", help="latency vs allow-list length")
    s.add_argument("--max-entries", type=int, default=4)
    s.add_argument("--n", type=int, default=60)
    s.add_argument("--npz", default=None)
    s.set_defaults(fn=cmd_sweep)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
