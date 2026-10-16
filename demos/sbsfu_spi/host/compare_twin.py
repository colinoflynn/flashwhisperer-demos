#!/usr/bin/env python3
"""Is the self-instrumented interval a function of the data, and is it the flash?

    python results/bootloader_spi/l475/compare_twin.py

Four captures, each two passes, ALL ON THE SAME TWO BODIES (--seed0 20261015,
so pass k's ciphertext is byte-identical everywhere):

  smoke_flash.npz        AES tables in flash  (MBEDTLS_AES_ROM_TABLES on)
  smoke_flash_repeat.npz the same build again
  smoke_ram.npz          AES tables in SRAM   -- ST'S SHIPPED CONFIGURATION,
                                                  and the RAM twin control
  smoke_ram_repeat.npz   the same build again

The two repeats are what make this a measurement rather than a comparison of
two numbers.  Each build is measured twice on identical inputs, so its own
jitter is observed rather than assumed, and the question becomes whether the
across-chunk spread is reproducible: a spread that repeats is a function of
the data, a spread that does not is the instrument.

WHAT THIS DOES NOT CLAIM.  A statistic is not a channel -- a pooled z of
-21.81 that yields 0/16 key bytes is not one, whatever its size
(research/mechanism/MEASURING_CHANNELS.md).  No key has been recovered on
this board.  What this answers is the cheaper question that decides whether a
campaign is worth the bench time.

At ST's shipped chunk size one interval sums 32 AES block decryptions plus
one SHA-256 update over 512 bytes, so a per-block effect is diluted 32-fold
and no single interval says anything.
"""
import os

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURES = (("tables in flash", "smoke_flash.npz", "smoke_flash_repeat.npz"),
            ("tables in SRAM ", "smoke_ram.npz", "smoke_ram_repeat.npz"))


def load(name):
    z = np.load(os.path.join(HERE, name))
    return dict(cycles=z["cycles"], polls=z["polls"], passno=z["passno"],
                ct=z["ct"], chunk=int(z["chunk"]), variant=str(z["variant"]),
                tampered=int(z["tampered"]))


def per_pass(d, p):
    """One pass's intervals, dropping any that saw a busy-poll retry.

    A retry means the memory reported itself busy and the driver issued a
    whole extra chip-select envelope -- tens of microseconds against a signal
    of a couple of cycles.  There were none in any of these captures, so the
    filter costs nothing here and is kept because the next capture may not be
    so lucky.
    """
    m = (d["passno"] == p) & (d["polls"] == 0)
    return d["cycles"][m].astype(float)


def main():
    loaded = {}
    for _, a, b in CAPTURES:
        for n in (a, b):
            loaded[n] = load(n)
    ref = loaded["smoke_flash.npz"]
    print("chunk = %d bytes = %d AES blocks per interval, tampered=%d"
          % (ref["chunk"], ref["chunk"] // 16, ref["tampered"]))
    for n, d in loaded.items():
        print("  %-24s %-26s %4d intervals" % (n, d["variant"], len(d["cycles"])))

    # The bodies have to be identical or nothing below is a comparison.
    # Checked rather than assumed: --seed0 was the same, but a seed is an
    # intention and the ciphertext is the fact.
    for n, d in loaded.items():
        if not np.array_equal(ref["ct"], d["ct"]):
            raise SystemExit("%s is not on the same bodies as smoke_flash" % n)
    print("  ciphertext identical across all four captures")

    print()
    print("%-16s %8s %8s %8s %8s" % ("", "median", "sd", "repeat", "corr"))
    print("%-16s %8s %8s %8s %8s"
          % ("", "cycles", "chunks", "diff sd", "same body"))
    rows = {}
    for tag, an, bn in CAPTURES:
        a, b = loaded[an], loaded[bn]
        cyc = np.concatenate([per_pass(a, 0), per_pass(a, 1)])
        difs, cors = [], []
        for p in (0, 1):
            x, y = per_pass(a, p), per_pass(b, p)
            n = min(len(x), len(y))
            difs.append(x[:n] - y[:n])
            cors.append(np.corrcoef(x[:n], y[:n])[0, 1])
        dif = np.concatenate(difs)
        rows[tag] = (np.median(cyc), cyc.std(ddof=1), dif.std(ddof=1),
                     float(np.mean(cors)))
        print("%-16s %8d %8.1f %8.1f %8.3f"
              % (tag, rows[tag][0], rows[tag][1], rows[tag][2], rows[tag][3]))

    print()
    fl, ra = rows["tables in flash"], rows["tables in SRAM "]
    print("The median difference is the cost of reading a table out of flash:")
    print("  %d - %d = %d cycles per 512-byte chunk = %.1f per AES block"
          % (fl[0], ra[0], fl[0] - ra[0], (fl[0] - ra[0]) / (ref["chunk"] // 16)))
    print("  That is a constant and carries nothing about the key.")
    print()
    print("The corr column is the result.  With the tables in flash the")
    print("interval repeats as a function of the chunk's contents (%.3f across"
          % fl[3])
    print("two independent captures of the same bodies) and the across-chunk")
    print("spread is %.1fx its own repeat floor.  With the tables in SRAM the"
          % (fl[1] / fl[2]))
    print("spread is no larger than that build's own jitter and the")
    print("correlation is %.3f -- nothing reproducible to attack." % ra[3])

    print()
    xs = np.concatenate([per_pass(loaded["smoke_flash.npz"], p) for p in (0, 1)])
    ys = np.concatenate([per_pass(loaded["smoke_ram.npz"], p) for p in (0, 1)])
    print("Cross-build correlation on identical bodies: %+.3f"
          % np.corrcoef(xs, ys)[0, 1])
    print("  So the flash build's data dependence is not something both builds")
    print("  share -- not the SHA-256 update, not the cipher's own control")
    print("  flow, not the QSPI driver.  Those run identically in both.")


if __name__ == "__main__":
    main()
