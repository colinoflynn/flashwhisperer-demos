"""Read a listener log into the two arrays the attack wants, without the text.

The listener prints one line per acknowledged frame:

    S <rx_end> <ack_tx> <len> <hex of the first MPDU bytes> <drops> ...

`rx_end` and `ack_tx` are the listener's own cycle counter at the two ON-AIR
edges, so the gap between them is the victim's data-frame to ACK turnaround as
a third party measures it, and the AES-CCM* decrypt sits inside it.

STREAMING, because these logs are half a gigabyte. The first version of this
kept every record's hex as a Python string, which is about 165 bytes of object
overhead each: 0.9 GB at 5 M records. So it makes one short probe pass to fix
the frame length and the ciphertext offset, then streams into fixed numpy
buffers and never holds the text. Memory is ~24 bytes per record whatever the
run length.

WHAT THIS DOES NOT DO
  * It does not open a serial port. Capturing is the listener's own job and
    lives with the listener, in instruments/sniff802154/.
  * It keeps only the dominant frame length and says how many records that
    cost. Frame length shifts the turnaround by a large constant, and one
    length class in a fragmenting capture was pathological for a reason worth
    knowing: the fragment that completes a datagram sends it up the stack, so
    the NEXT datagram's first fragment arrives while the victim is still busy.
    That class showed a robust sd of 131 905 cycles against 206 for the others.
  * It does not sweep the row offset or know anything about keys.
"""
from __future__ import annotations

import io

import numpy as np

try:
    from . import frames
except ImportError:                      # imported by a script, no package
    import frames

W32 = 2 ** 32


def _probe(log_path, probe):
    """(dominant frame length, the field layout) from the first records."""
    lens = {}
    with io.open(log_path, encoding="ascii", errors="replace") as fh:
        for k, line in enumerate(fh):
            if k >= probe:
                break
            f = line.split()
            if len(f) < 5 or f[0] != "S":
                continue
            try:
                lens[int(f[3])] = lens.get(int(f[3]), 0) + 1
            except ValueError:
                continue
    if not lens:
        raise SystemExit("no S records in %s" % log_path)
    L = max(lens, key=lens.get)
    found = None
    with io.open(log_path, encoding="ascii", errors="replace") as fh:
        for k, line in enumerate(fh):
            if k >= probe:
                break
            f = line.split()
            if len(f) < 5 or f[0] != "S":
                continue
            try:
                if int(f[3]) != L:
                    continue
                lay = frames.layout(bytes.fromhex(f[4]))
            except ValueError:
                continue
            if lay:
                found = lay
                break
    if found is None:
        raise SystemExit("could not locate the aux security header in %s - "
                         "are these secured frames with extended addressing?"
                         % log_path)
    return L, found


def read_log(log_path, *, limit=None, skip=0, probe=20000, verbose=True):
    """Every usable record: the raw turnaround, the frame counter, the block.

    Returns a dict of numpy arrays plus the constants a vector needs to
    regenerate the AES output: the source EUI-64 and the security level, both
    of which are fixed for one capture and are asserted to be.

    `skip` counts raw records and `limit` counts records AFTER the skip, so
    (skip=N, limit=M) is the window [N, N+M). Analyses that compare a trend
    need DISJOINT windows: successive prefixes share most of their data, so
    their differences carry far bigger error bars than either.
    """
    L, lay = _probe(log_path, probe)
    ct_off, aux_off, src_at = lay["ct"], lay["aux"], lay["src_at"]
    if verbose:
        print("  probe: frame length %d, aux header at %d, ciphertext at %d"
              % (L, aux_off, ct_off))

    need = ct_off + 16
    gaps = []
    gbuf = np.empty(1 << 16, np.int64)
    hex_fc, hex_pay = [], []
    srcs, secs = {}, {}
    m = total = wrong_len = 0
    with io.open(log_path, encoding="ascii", errors="replace") as fh:
        for line in fh:
            f = line.split()
            if len(f) < 5 or f[0] != "S":
                continue
            total += 1
            if total <= skip:
                continue
            if limit and total - skip > limit:
                break
            try:
                if int(f[3]) != L:
                    wrong_len += 1
                    continue
                rx, ack = int(f[1]), int(f[2])
            except ValueError:
                continue
            h = f[4]
            if len(h) < 2 * need:
                continue
            gbuf[m] = (ack - rx) % W32
            hex_fc.append(h[2 * (aux_off + 1):2 * (aux_off + 5)])
            hex_pay.append(h[2 * ct_off:2 * (ct_off + 16)])
            s_hex = h[2 * src_at:2 * (src_at + 8)]
            c_hex = h[2 * aux_off:2 * (aux_off + 1)]
            srcs[s_hex] = srcs.get(s_hex, 0) + 1
            secs[c_hex] = secs.get(c_hex, 0) + 1
            m += 1
            if m == len(gbuf):
                gaps.append(gbuf)
                gbuf = np.empty(1 << 16, np.int64)
                m = 0
    if m:
        gaps.append(gbuf[:m])
    if not gaps:
        raise SystemExit("no usable records of length %d in %s" % (L, log_path))
    gap = np.concatenate(gaps)
    # One link, so one source address and one security level. A log can still
    # carry a few records that disagree, because at 921600 baud over USB CDC a
    # line arrives mangled now and then - two in 2.6 million on the capture
    # here. So take the dominant value rather than refusing, and let
    # make_vector's regeneration check drop the odd records: a block built on a
    # corrupted header cannot reproduce. Refuse only if the split is big enough
    # to mean this is two captures in one file.
    src_hex, src_n = max(srcs.items(), key=lambda kv: kv[1])
    sec_hex, sec_n = max(secs.items(), key=lambda kv: kv[1])
    for what, n, total_kept in (("source addresses", src_n, len(gap)),
                                ("security levels", sec_n, len(gap))):
        if n < total_kept - max(16, total_kept // 10000):
            raise SystemExit(
                "this capture mixes %s: the commonest covers %d of %d records, "
                "which is too many to be corrupt lines. One link per log."
                % (what, n, total_kept))

    fc4 = np.frombuffer(bytes.fromhex("".join(hex_fc)), np.uint8).reshape(-1, 4)
    fc = fc4.astype(np.int64) @ np.array([1, 1 << 8, 1 << 16, 1 << 24], np.int64)
    pay = np.frombuffer(bytes.fromhex("".join(hex_pay)), np.uint8).reshape(-1, 16)

    if verbose:
        print("  %d records scanned, %d of length %d usable (%d other lengths)"
              % (total, len(gap), L, wrong_len))
    return {"gap": gap, "frame_counter": fc, "payload": pay,
            "src": bytes.fromhex(src_hex), "sec_level": int(sec_hex, 16) & 7,
            "frame_len": L, "ct_off": ct_off, "scanned": total,
            "other_lengths": wrong_len}


def condition(gap, *, trim=6.0, highpass=0, verbose=True):
    """Turn raw turnarounds into the timing the attack scores. (y, keep mask).

    Two steps, in this order.

    Trim. Retries and deferrals land hundreds of thousands of cycles late and
    the collision statistic mean-centres the timing, so a handful of them
    swamps a one-cycle cache effect. The threshold is in robust sd, not sd.

    High-pass, which is optional and whose gain is smaller than it looks. The
    capture really does drift: robust sd grows with how long you look (37
    cycles inside a 33-record window, 64 over a whole nine-hour capture), the
    mean turnaround wanders 153 cycles peak to peak and consecutive records
    correlate at +0.449 at lag 1. Subtracting a centred moving median removes
    all of that. What it does NOT buy is the 1.9x to 3.1x in traces it first
    appeared to: the collision/non-collision split is essentially random per
    trace, both groups sample the same slow drift, and it cancels in the
    difference of means. So drift inflates `sd` without inflating the error on
    the effect, detrending shrinks sd, an iid z leaps and nothing real
    improves. Measured against the block-to-block spread of the effect itself
    it is worth about +12 % in z, i.e. ~20 % in traces, with a broad optimum at
    window 17 to 33. Keep it, but NEVER size a campaign on the iid z of a
    detrended set.
    """
    g = np.asarray(gap, float)
    med = np.median(g)
    rsd = 1.4826 * np.median(np.abs(g - med))
    # A capture whose turnaround is CONSTANT was taken with a stopped cycle
    # counter. DWT->CYCCNT runs only while DEMCR.TRCENA is set and a debug
    # probe clears that bit on disconnect, so any flash or reset stops the
    # counter of firmware that armed it once at boot. It freezes rather than
    # zeroing, so the stamps stay plausible and every interval comes out
    # exactly 0 - and the rest of this pipeline would happily run for hours on
    # it and report a very small sigma. Refuse instead.
    if rsd == 0.0 and len(g) > 100:
        raise SystemExit(
            "turnaround is CONSTANT (%g) over %d records: the listener's cycle "
            "counter was stopped (a debug probe clears DEMCR.TRCENA on "
            "disconnect). Power-cycle it and re-capture." % (med, len(g)))
    keep = (np.abs(g - med) <= trim * max(rsd, 1.0)) if trim else np.ones(len(g), bool)
    y = g[keep] - med
    if highpass and highpass > 1 and len(y) > 2 * highpass:
        from numpy.lib.stride_tricks import sliding_window_view
        half = highpass // 2
        pad = np.concatenate([y[:half][::-1], y, y[-half:][::-1]])
        y = y - np.median(sliding_window_view(pad, highpass), axis=1)[:len(y)]
    if verbose:
        rsd2 = 1.4826 * np.median(np.abs(y - np.median(y)))
        print("  median %.0f  robust sd %.1f -> %.1f  kept %d of %d"
              % (med, rsd, rsd2, int(keep.sum()), len(g)))
    return y, keep
