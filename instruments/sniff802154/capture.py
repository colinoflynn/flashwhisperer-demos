"""Read the listener's records into a log file, for as long as you want to.

The listener prints one line per paired record at 921600 and this appends them
to a plain text file: constant cost per record, no compression, no rewrite, and
the analysis can read the growing file while the capture keeps running.

    python instruments/sniff802154/capture.py --port COM25 \\
        --log passive.log --n 3000000 --wall 86400

WHY A TEXT LOG AND NOT AN NPZ. The first version of this checkpointed by
rewriting the whole accumulated set every 500 records, which is O(n^2) in the
record count - fine for 30 000, ruinous for 2.6 million. Worse, the rewrite
blocks the serial read, and a blocking writer on the measurement path is
exactly what inflated the turnaround's sd from 63 to about 950 cycles when the
console ran at 115200. A capture whose own bookkeeping perturbs the quantity it
records is not a capture.

WHAT THIS DOES NOT DO
  * It does not resolve a board. Pass the port; `instruments/hostlib` is there
    to find one by probe serial if you want that.
  * It does not check that the records are sane. `demos/ota_802154/host`
    does, and the one check worth running early is that the turnaround is not
    CONSTANT: a debug probe clears DEMCR.TRCENA on disconnect, which freezes
    DWT->CYCCNT, and every interval then comes out exactly zero while the
    stamps stay plausible.
  * It never learns the key, and the listener's own image does not contain
    one. verify_build.py in the demo checks that.
"""
from __future__ import annotations

import argparse
import io
import os
import sys
import time


def capture(port, log_path, n, baud=921600, wall=86400.0, flush_every=500):
    import serial                      # not a dependency of the analysis half
    s = serial.Serial(port, baud, timeout=5)
    time.sleep(0.3)
    s.reset_input_buffer()
    # append, so an interrupted run continues into the same log
    f = io.open(log_path, "a", encoding="ascii", newline="\n")
    got, bad, t0 = 0, 0, time.time()
    try:
        while got < n:
            now = time.time()
            if now - t0 > wall:
                print("  wall limit reached at %d records" % got, flush=True)
                break
            ln = s.readline().decode("ascii", errors="replace").strip()
            if not ln.startswith("S "):
                if ln:
                    bad += 1
                continue
            f.write(ln + "\n")
            got += 1
            if got % flush_every == 0:
                f.flush()
                os.fsync(f.fileno())
            if got % 5000 == 0:
                el = now - t0
                rate = got / max(el, 1e-6)
                print("  %d/%d  %.1f rec/s  elapsed %.0f min  eta %.1f h"
                      % (got, n, rate, el / 60.0,
                         (n - got) / max(rate, 1e-6) / 3600.0), flush=True)
    finally:
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
        f.close()
        s.close()
    print("captured %d records (%d malformed lines)" % (got, bad), flush=True)
    return got


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", required=True, help="the LISTENER's console")
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--log", required=True)
    ap.add_argument("--n", type=int, default=3000000)
    ap.add_argument("--wall", type=float, default=86400.0,
                    help="seconds to give up after; 2.6 M frames took 21 h")
    a = ap.parse_args()
    capture(a.port, a.log, a.n, a.baud, a.wall)
    return 0


if __name__ == "__main__":
    sys.exit(main())
