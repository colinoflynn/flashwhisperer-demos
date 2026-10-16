"""Device driver and sweeps for the flash-arbitration probe. Target-independent.

Speaks the one-line `key=value` protocol in rigs/fw_arb_common/arb_cmd.c, so it works
against any board that links that file.
"""
from __future__ import annotations

import time

import numpy as np

WIDTHS = (2, 4)
NS = tuple(range(0, 13))
PADS = (0, 2, 4, 6)
BIG_FILLERS = (16, 32, 64, 128, 256)


class ArbDevice:
    """One probe board."""

    def __init__(self, target, port=None, settle=0.8):
        import serial  # pyserial; lazy so the package installs without a bench
        self.t = target
        self.s = serial.Serial(port or target.port, 115200, timeout=3.0)
        time.sleep(settle)
        self.s.reset_input_buffer()
        b = self.cmd("V")
        if target.banner not in b:
            raise RuntimeError("expected %r on %s, got %r"
                               % (target.banner, self.s.port, b))
        self.banner = b
        v = self._kv(b)
        self.tab = int(v["tab"], 16)
        self.ramtab = int(v["ramtab"], 16)
        self.has_monitors = v.get("mon", "0") == "1"
        self.idx_a, self.idx_hit, self.idx_miss = target.pick_indices(self.tab)
        target.check_indices(self.tab, self.idx_a, self.idx_hit, self.idx_miss)

    # ---- transport -------------------------------------------------------------
    def cmd(self, c):
        self.s.write((c + "\n").encode())
        line = self.s.readline().decode(errors="replace").strip()
        while line == "":
            line = self.s.readline().decode(errors="replace").strip()
        return line

    @staticmethod
    def _kv(line):
        return dict(p.split("=", 1) for p in line.split() if "=" in p)

    def kv(self, c):
        return self._kv(self.cmd(c))

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

    # ---- primitives ------------------------------------------------------------
    def set_accel(self, v):
        return self.cmd("A %x" % v)

    def set_mhz(self, mhz):
        return self.cmd("Z %d" % mhz)

    def loop_offset(self, w, n, a):
        return int(self.kv("L %d %d %d" % (w, n, a))["mod8"])

    def time_kernel(self, w, n, a, idx_b, cnt, mem=0, counters=False):
        r = self.kv("%s %d %d %d %x %x %d %d"
                    % ("Q" if counters else "P", w, n, a, self.idx_a, idx_b, cnt, mem))
        return r

    def time_big(self, ni, a, idx_b, cnt, mem=0):
        return self.kv("G %d %d %x %x %d %d" % (ni, a, self.idx_a, idx_b, cnt, mem))

    def time_enc(self, e, a, idx_b, cnt, mem=0):
        return self.kv("E %d %d %x %x %d %d" % (e, a, self.idx_a, idx_b, cnt, mem))

    def monitors(self):
        if not self.has_monitors:
            return None
        r = self.kv("M")
        return int(r["hit"]), int(r["miss"])

    def monitors_reset(self):
        if self.has_monitors:
            self.cmd("R")

    # ---- the measurement -------------------------------------------------------
    def dip(self, runner, cnt, mem=0, best_of=3, idx_hit=None, idx_miss=None, **kw):
        """Cycles saved per iteration when the second load collides.

        Negative means the collision is cheaper, i.e. a channel. The quantity is an exact
        multiple of 1/cnt on the device, so `best_of` removes host-side capture jitter and
        not device variance - there is none to remove.

        `idx_hit`/`idx_miss` override the defaults for kernels whose load does not scale the
        index by the entry stride - see `indices_for_stride()`.
        """
        ih = self.idx_hit if idx_hit is None else idx_hit
        im = self.idx_miss if idx_miss is None else idx_miss
        h = min(int(runner(idx_b=ih, cnt=cnt, mem=mem, **kw)["cyc"]) for _ in range(best_of))
        m = min(int(runner(idx_b=im, cnt=cnt, mem=mem, **kw)["cyc"]) for _ in range(best_of))
        return (h - m) / float(cnt)

    def indices_for_stride(self, stride):
        """(a, hit, miss) valid for a load that scales the index by `stride`.

        The E4 kernels vary the addressing mode, so the entry-stride indices are wrong for
        two of the three: `ldrb rX,[rB,rI]` treats the index as a raw byte offset. On a
        16-byte read word the entry-stride triple 0x40/0x41/0x44 then lands entirely inside
        ONE word and the miss cannot miss - the F429 reported `+0.000` for those encodings
        even at LATENCY 2. Ask for indices that match the instruction, not the table.
        """
        if stride == self.t.entry_stride:
            return self.idx_a, self.idx_hit, self.idx_miss
        a = self.idx_a
        hit = a + 1
        for miss in range(a + self.t.read_width // stride, 256):
            try:
                self.t.check_indices(self.tab, a, hit, miss, stride=stride)
                return a, hit, miss
            except ValueError:
                continue
        raise ValueError("no usable indices at stride %d on %s" % (stride, self.t.name))


def align_spacing_map(dev, cnt=2000, mem=0, widths=WIDTHS, ns=NS, pads=PADS):
    """(width, spacing, alignment) -> cycles saved by a collision."""
    grid = np.zeros((len(widths), len(ns), len(pads)))
    for wi, w in enumerate(widths):
        for ni, n in enumerate(ns):
            for pi, a in enumerate(pads):
                grid[wi, ni, pi] = dev.dip(
                    lambda idx_b, cnt, mem, _w=w, _n=n, _a=a:
                        dev.time_kernel(_w, _n, _a, idx_b, cnt, mem),
                    cnt, mem)
    return grid


def working_set_sweep(dev, cnt=2000, pad=2, mem=0):
    """Loop-body size -> dip. Finds where an instruction cache stops covering the fetches."""
    out = []
    for ni, fillers in enumerate(BIG_FILLERS):
        d = dev.dip(lambda idx_b, cnt, mem, _ni=ni: dev.time_big(_ni, pad, idx_b, cnt, mem),
                    cnt, mem)
        out.append((fillers, 16 + 4 * fillers, d))
    return out


#: Index scaling applied by each E4 kernel's load instruction (probe.S, ARBENC macro):
#: enc 0 = `ldrb.w rX,[rB,rI,lsl#2]`, enc 1 = `ldrb.w rX,[rB,rI]`, enc 2 = `ldrb rX,[rB,rI]`.
ENC_STRIDE = (4, 1, 1)


def encoding_sweep(dev, cnt=2000, mem=0, pads=PADS):
    """Load encoding x alignment -> dip. enc 0/1/2 as documented in probe.S.

    Each encoding gets indices matching ITS addressing mode. Using one triple for all three
    silently voids the two unshifted rows on any part whose read word is wider than
    4 x entry_stride.
    """
    grid = np.zeros((3, len(pads)))
    for e in range(3):
        _a, ih, im = dev.indices_for_stride(ENC_STRIDE[e])
        for pi, a in enumerate(pads):
            grid[e, pi] = dev.dip(
                lambda idx_b, cnt, mem, _e=e, _a=a: dev.time_enc(_e, _a, idx_b, cnt, mem),
                cnt, mem, idx_hit=ih, idx_miss=im)
    return grid


def attribution(dev, cells, cnt=8):
    """For each (w, n, a): how a collision moves cycles, CPICNT and LSUCNT.

    The window must stay under 255 counts because the DWT profile counters are 8-bit, which
    is why `cnt` here is tiny next to the timing sweeps.
    """
    rows = []
    for (w, n, a) in cells:
        r = {}
        for lbl, ib in (("miss", dev.idx_miss), ("hit", dev.idx_hit)):
            v = [dev.time_kernel(w, n, a, ib, cnt, 0, counters=True) for _ in range(5)]
            r[lbl] = min(v, key=lambda x: int(x["cyc"]))
        rows.append(dict(w=w, n=n, a=a,
                         d_cyc=int(r["hit"]["cyc"]) - int(r["miss"]["cyc"]),
                         d_cpi=int(r["hit"]["dcpi"]) - int(r["miss"]["dcpi"]),
                         d_lsu=int(r["hit"]["dlsu"]) - int(r["miss"]["dlsu"])))
    return rows


def format_map(dev, grid, widths=WIDTHS, ns=NS, pads=PADS):
    """Render one (width, spacing, alignment) grid, labelled by the offsets the DEVICE
    reported rather than the pads that were asked for."""
    lines = []
    for wi, w in enumerate(widths):
        offs = [dev.loop_offset(w, 0, a) for a in pads]
        lines.append("  filler width %d bytes" % w)
        lines.append("    %-4s%s" % ("N", "".join("  off%-5d" % o for o in offs)))
        for ni, n in enumerate(ns):
            lines.append("    %-4d%s" % (n, "".join("  %+6.3f" % grid[wi, ni, pi]
                                                    for pi in range(len(pads)))))
    return "\n".join(lines)
