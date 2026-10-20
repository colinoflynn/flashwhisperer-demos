"""Drive the attacker board and record what it heard. Nothing else.

    python -m demos.riot_802154.host.capture --count 120000 \
        --prefix captures/riot_802154/run1 --target fe80::...%5

THE HOST TALKS TO THE ATTACKER AND TO NOTHING ELSE. There is no serial
connection to the victim here, no cycle counter read off it and no shell
command sent to it: the victim is a stock RIOT node that has been switched on.
That is the difference between this and the campaign's own capture script,
which also drove the victim's DWT wrapper -- see victim/OPTIONAL_DWT_PATCH.md
for what that buys and why it is not needed.

Each record holds the attacker's raw ping output and every radio END stamp it
latched, with the frame bytes for the request and the reply, so the derived
interval can be audited against the direction and the security bit rather than
trusted.

Batches, because: the attacker's stamp ring holds 64 records and its shell is
the only way out, so a run is a sequence of small files. They are opened with
exclusive creation, so an interrupted run cannot quietly overwrite evidence,
and --resume skips the batches that are already on disk. Run it in chunks under
an external timeout; a CDC port that stops accepting writes needs a replug, not
a retry.
"""

import argparse
import json
import re
import time
from pathlib import Path

import serial

STAMP_RE = re.compile(r"^(\d+),(\d+),(\d+),(\d+),([0-9a-fA-F]{2}),"
                      r"([0-9a-fA-F]{2}),(\d+),(\d+)$")
FRAME_RE = re.compile(r"^frame,(\d+),([0-9a-fA-F]+)$")


def command(port, line, timeout=3):
    """One shell line, read back to the prompt.

    `read(4096)` would wait out the whole port timeout on every command even
    when the short reply and the prompt have already arrived, which at ~19
    probes a second is most of the run.
    """
    port.reset_input_buffer()
    port.write((line + "\n").encode())
    deadline = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < deadline:
        data.extend(port.read(max(1, port.in_waiting)))
        if data.endswith(b"> "):
            return data.decode("utf-8", "replace")
    raise TimeoutError("%s: partial console output %r" % (line, bytes(data)))


def parse_stamps(text):
    stamps = []
    for line in text.splitlines():
        match = STAMP_RE.fullmatch(line.strip())
        if match:
            i, tick, direction, length, fcf0, fcf1, seq, crc = match.groups()
            stamps.append(dict(index=int(i), tick=int(tick),
                               direction=int(direction), length=int(length),
                               fcf0=int(fcf0, 16), fcf1=int(fcf1, 16),
                               seq=int(seq), crc=int(crc)))
        frame = FRAME_RE.fullmatch(line.strip())
        if frame:
            index, hex_bytes = frame.groups()
            index = int(index)
            if index >= len(stamps) or stamps[index]["index"] != index:
                raise ValueError("frame line out of order: %s" % line)
            stamps[index]["frame"] = hex_bytes.lower()
    return stamps


def summarize(stamps):
    """The two intervals, or None if this probe was not a clean exchange.

    A request is an unsecured data frame the attacker sent; a reply is a
    secured data frame it received. The ACK is matched on the request's own
    sequence number, because the reply has a sequence space of its own and
    retries break any assumed alignment.
    """
    requests = [s for s in stamps if s["direction"] == 1
                and (s["fcf0"] & 7) == 1 and not (s["fcf0"] & 8)]
    replies = [s for s in stamps if s["direction"] == 2
               and (s["fcf0"] & 7) == 1 and (s["fcf0"] & 8)]
    if len(requests) != 1 or len(replies) != 1:
        return None
    req, rep = requests[0], replies[0]
    ack = next((s for s in stamps if s["direction"] == 2
                and (s["fcf0"] & 7) == 2 and s["seq"] == req["seq"]), None)
    return dict(req_seq=req["seq"], rep_seq=rep["seq"],
                reply_ticks=(rep["tick"] - req["tick"]) & 0xffffffff,
                ack_ticks=(((ack["tick"] - req["tick"]) & 0xffffffff)
                           if ack else None),
                req_len=req["length"], rep_len=rep["length"])


def run_batch(port, path, first, count, target, iface, payload, timeout_ms):
    consecutive = 0
    with path.open("x") as out:
        for j in range(count):
            phase, ping, raw = "arm", "", ""
            try:
                command(port, "stamp arm")
                phase = "ping"
                ping = command(port, "ping -c 1 -s %d -W %d %s%%%s"
                               % (payload, timeout_ms, target, iface),
                               timeout=5)
                phase = "dump"
                raw = command(port, "stamp dump", timeout=5)
                phase = "parse"
                stamps = parse_stamps(raw)
                record = dict(i=first + j, ping=ping, stamps=stamps,
                              summary=summarize(stamps))
                consecutive = 0
            except (TimeoutError, ValueError) as exc:
                record = dict(i=first + j, ping=ping, stamps=[], summary=None,
                              capture_error="%s: %s" % (phase, exc),
                              raw_stamps=raw)
                consecutive += 1
            out.write(json.dumps(record) + "\n")
            out.flush()
            if consecutive >= 3:
                raise RuntimeError("three consecutive capture errors; "
                                   "batch saved. Check the attacker's CDC "
                                   "port -- a write timeout needs a replug")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", default="COM46",
                    help="the ATTACKER's CDC port. Never the victim's")
    ap.add_argument("--iface", default="5", help="attacker's netif number")
    ap.add_argument("--target", required=True,
                    help="the victim's link-local address, from its own "
                         "ifconfig during setup")
    ap.add_argument("--payload-size", type=int, default=64,
                    help="ICMPv6 echo payload bytes. 64 is four complete "
                         "AES-CTR blocks per reply and is the cheapest arm; "
                         "80 fragments at 6LoWPAN and leaves this regime")
    ap.add_argument("--ping-timeout-ms", type=int, default=30,
                    help="the attacker cannot authenticate the reply, so every "
                         "ping reports failure and waits this long")
    ap.add_argument("--count", type=int, required=True)
    ap.add_argument("--batch", type=int, default=250)
    ap.add_argument("--prefix", type=Path, required=True)
    ap.add_argument("--resume", action="store_true",
                    help="skip batches already on disk")
    ap.add_argument("--stop-file", type=Path,
                    help="finish the current batch and stop once this exists")
    args = ap.parse_args()
    if not 0 < args.batch or args.count <= 0:
        ap.error("need batch > 0 and count > 0")
    args.prefix.parent.mkdir(parents=True, exist_ok=True)

    with serial.Serial(args.port, 115200, timeout=0.05) as port:
        # The attacker sends in the CLEAR. Its own key is RIOT's default and
        # the victim's is not, so it authenticates nothing it hears back; the
        # radio hook records the frame before the MIC is checked.
        setting = command(port, "ifconfig %s -encrypt" % args.iface)
        if "success" not in setting:
            raise RuntimeError("could not clear the attacker's outbound "
                               "security flag: %s" % setting)
        done, batch_no = 0, 0
        t0 = time.monotonic()
        while done < args.count:
            count = min(args.batch, args.count - done)
            path = args.prefix.with_name("%s_%04d.jsonl"
                                         % (args.prefix.name, batch_no))
            if path.exists():
                if not args.resume:
                    raise FileExistsError("%s exists; pass --resume" % path)
            else:
                run_batch(port, path, done, count, args.target, args.iface,
                          args.payload_size, args.ping_timeout_ms)
            done += count
            batch_no += 1
            rate = done / max(time.monotonic() - t0, 1e-9)
            print("%d/%d  %s  %.1f probes/s" % (done, args.count, path.name, rate),
                  flush=True)
            if args.stop_file and args.stop_file.exists():
                print("stop file observed after a completed batch", flush=True)
                break


if __name__ == "__main__":
    main()
