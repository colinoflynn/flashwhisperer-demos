"""Print one captured request/reply pair field by field, with the CCM* blocks.

The frames come from the Dongle's radio ring, so these are the bytes that were
on the air. Everything printed here is derived from those bytes alone except
the lines marked KNOWN-KEY, which are there so the write-up can state what the
attacker gets right without the key and what the check was.

Used to build the frame tables in [`../README.md`](../README.md).
"""

import argparse
import json
from pathlib import Path

LEVELS = {0: "none", 1: "MIC-32", 2: "MIC-64", 3: "MIC-128",
          4: "ENC", 5: "ENC-MIC-32", 6: "ENC-MIC-64", 7: "ENC-MIC-128"}
ADDR_MODES = {0: "none", 1: "reserved", 2: "short", 3: "extended"}


def fcf(b0, b1):
    return dict(frame_type=b0 & 7, security_enabled=(b0 >> 3) & 1,
                frame_pending=(b0 >> 4) & 1, ack_request=(b0 >> 5) & 1,
                pan_id_compression=(b0 >> 6) & 1,
                dest_addr_mode=(b1 >> 2) & 3, frame_version=(b1 >> 4) & 3,
                src_addr_mode=(b1 >> 6) & 3)


def show(name, frame, secured):
    print(f"\n--- {name}: {len(frame)} bytes on the air "
          f"(plus a 2-byte FCS the radio checks and strips)")
    f = fcf(frame[0], frame[1])
    print(f"  [0:2]   FCF            {frame[0]:02x} {frame[1]:02x}   "
          f"type {f['frame_type']} (data), security_enabled "
          f"{f['security_enabled']}, ack_request {f['ack_request']}, "
          f"pan_id_compression {f['pan_id_compression']}, dest "
          f"{ADDR_MODES[f['dest_addr_mode']]}, src "
          f"{ADDR_MODES[f['src_addr_mode']]}, version {f['frame_version']}")
    print(f"  [2]     sequence       {frame[2]:02x}   ({frame[2]})")
    print(f"  [3:5]   PAN id         {frame[3]:02x} {frame[4]:02x}   "
          f"0x{int.from_bytes(frame[3:5], 'little'):04x}")
    print(f"  [5:13]  dest address   {frame[5:13].hex()}   little-endian EUI-64")
    print(f"  [13:21] src address    {frame[13:21].hex()}   little-endian EUI-64")
    off = 21
    if secured:
        sc = frame[21]
        print(f"  [21]    security ctrl  {sc:02x}   level {sc & 7} "
              f"({LEVELS[sc & 7]}), key id mode {(sc >> 3) & 3}, "
              f"frame counter suppression {(sc >> 5) & 1}")
        print(f"  [22:26] frame counter  {frame[22:26].hex()}   "
              f"{int.from_bytes(frame[22:26], 'little')} (little-endian, public)")
        off = 26
        body, mic = frame[off:-8], frame[-8:]
        print(f"  [{off}:{len(frame) - 8}] ciphertext     {len(body)} bytes")
        print(f"          {body.hex()}")
        print(f"  [{len(frame) - 8}:{len(frame)}] MIC            {mic.hex()}   "
              f"8 bytes, CBC-MAC over the header and the plaintext")
    else:
        body = frame[off:]
        print(f"  [{off}:{len(frame)}] payload        {len(body)} bytes, in clear")
        print(f"          {body.hex()}")
        print(f"          [0:2]  6LoWPAN IPHC   {body[0]:02x} {body[1]:02x}")
        print(f"          [2]    next header    {body[2]:02x}   "
              f"{body[2]} = ICMPv6")
        print(f"          [3]    ICMPv6 type    {body[3]:02x}   "
              f"{'echo request' if body[3] == 0x80 else 'echo reply'}")
        print(f"          [4]    ICMPv6 code    {body[4]:02x}")
        print(f"          [5:7]  checksum       {body[5:7].hex()}")
        print(f"          [7:9]  identifier     {body[7:9].hex()}")
        print(f"          [9:11] sequence       {body[9:11].hex()}")
        print(f"          [11:]  ping data      {len(body) - 11} bytes")
    return body


def counter_block(src_le, counter, level, index):
    """CCM* A_i: flags || nonce(src EUI, counter, level) || 2-byte block index."""
    return (bytes([1]) + bytes(src_le[::-1]) + counter.to_bytes(4, "big")
            + bytes([level]) + index.to_bytes(2, "big"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=Path)
    ap.add_argument("--probe", type=int, default=0)
    ap.add_argument("--key", help="KNOWN-KEY check only; never used to derive")
    args = ap.parse_args()

    record = None
    with args.capture.open() as stream:
        for line in stream:
            r = json.loads(line)
            if r["i"] == args.probe and r.get("summary"):
                record = r
                break
    if record is None:
        raise SystemExit(f"probe {args.probe} not in {args.capture}")

    req = next(bytes.fromhex(s["frame"]) for s in record["stamps"]
               if s["direction"] == 1 and "frame" in s and (s["fcf0"] & 7) == 1)
    rep = next(bytes.fromhex(s["frame"]) for s in record["stamps"]
               if s["direction"] == 2 and "frame" in s and (s["fcf0"] & 15) == 9)

    print(f"probe {record['i']} of {args.capture.name}")
    req_body = show("REQUEST, Dongle to DK, unsecured", req, False)
    rep_body = show("REPLY, DK to Dongle, secured", rep, True)

    print("\n--- what the attacker derives, from those bytes only")
    plain = bytearray(req_body)
    plain[3] = 0x81
    checksum = (int.from_bytes(plain[5:7], "big") - 0x0100) % 0xffff
    plain[5:7] = checksum.to_bytes(2, "big")
    print(f"  the reply's plaintext is the request's with two edits: ICMPv6 type"
          f"\n  {req_body[3]:#04x} -> {plain[3]:#04x} and checksum "
          f"{req_body[5:7].hex()} -> {plain[5:7].hex()} (ones-complement, "
          f"-0x0100)")
    counter = int.from_bytes(rep[22:26], "little")
    level = rep[21] & 7
    nblocks = len(rep_body) // 16
    print(f"  payload {len(rep_body)} bytes -> {nblocks} complete CTR blocks "
          f"and {len(rep_body) % 16} trailing bytes")
    for i in range(1, nblocks + 1):
        a = counter_block(rep[13:21], counter, level, i)
        ks = bytes(x ^ y for x, y in
                   zip(plain[16 * (i - 1):16 * i], rep_body[16 * (i - 1):16 * i]))
        print(f"    A{i} = {a.hex()}")
        print(f"    AES_K(A{i}) = {ks.hex()}   <- plaintext XOR ciphertext")
    if args.key:
        from flashattack import aesref  # noqa: E402
        import numpy as np
        pts = np.stack([np.frombuffer(counter_block(rep[13:21], counter, level, i),
                                      np.uint8) for i in range(1, nblocks + 1)])
        got = aesref.encrypt_blocks(bytes.fromhex(args.key), pts)
        print("\n  KNOWN-KEY check, after the fact:")
        for i in range(nblocks):
            ks = bytes(x ^ y for x, y in
                       zip(plain[16 * i:16 * i + 16],
                           rep_body[16 * i:16 * i + 16]))
            print(f"    block {i + 1}: AES_K(A{i + 1}) matches {bytes(got[i]) == ks}")


if __name__ == "__main__":
    main()
