"""
Vectorized AES-128 encryption that records the ordered sequence of table
memory accesses performed during encryption.

The point of this module is NOT to be a fast production cipher; it is to
produce, for N plaintexts at once, the exact ordered list of *table lookup
addresses* that a real firmware AES would issue, so that a flash-timing
model can turn them into a data-dependent cycle count.

Two table layouts are supported:

* "sbox"    : the classic 256-byte S-box. SubBytes issues 16 lookups/round
              (160 total for AES-128). Each entry is 1 byte, so a 128-bit
              (16-byte) flash line holds 16 consecutive S-box entries and the
              flash *line index* equals the top 4 bits of the lookup index.

* "ttable"  : the "T-table" (a.k.a. Te0..Te3) layout used by fast software
              AES. Rounds 1..9 replace SubBytes+ShiftRows+MixColumns with four
              1 KiB tables of 4-byte entries; the final round uses the S-box.
              Because each entry is 4 bytes, a 128-bit flash line holds only 4
              entries and the flash line index equals the top 6 bits of the
              lookup index - i.e. a T-table leaks *more* per lookup than an
              S-box does.

Only SubBytes / T-table lookups are treated as flash *data* accesses. The
round-key material is assumed precomputed and resident in RAM (the usual case
on a microcontroller), so the key schedule contributes no table traffic.

Byte/state convention: the 16-byte state is stored column-major, i.e. state
index j = row + 4*col, matching FIPS-197. This is validated against the
FIPS-197 test vector in tests/.
"""

from __future__ import annotations

import numpy as np

# --------------------------------------------------------------------------
# GF(2^8) and the AES S-box, built from first principles so the tables are
# auditable rather than copy-pasted magic numbers.
# --------------------------------------------------------------------------


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with the AES reduction polynomial 0x11B."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _build_sbox() -> np.ndarray:
    # multiplicative inverse table in GF(2^8)
    inv = np.zeros(256, dtype=np.uint8)
    for x in range(1, 256):
        for y in range(1, 256):
            if _gf_mul(x, y) == 1:
                inv[x] = y
                break
    sbox = np.zeros(256, dtype=np.uint8)
    for x in range(256):
        s = inv[x]
        # affine transform
        v = s ^ ((s << 1) | (s >> 7)) ^ ((s << 2) | (s >> 6)) \
            ^ ((s << 3) | (s >> 5)) ^ ((s << 4) | (s >> 4))
        sbox[x] = (v & 0xFF) ^ 0x63
    return sbox


SBOX = _build_sbox()

# Round constants for the key schedule.
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# Precompute xtime (multiply by 2) and multiply-by-3 lookup for MixColumns.
_XT = np.array([_gf_mul(x, 2) for x in range(256)], dtype=np.uint8)
_X3 = np.array([_gf_mul(x, 3) for x in range(256)], dtype=np.uint8)

# ShiftRows permutation on the column-major 16-byte state.
# new[r,c] = old[r,(c+r)%4]  ->  as flat indices j = r + 4*c
_SHIFT_ROWS = np.array(
    [(j % 4) + 4 * ((j // 4 + (j % 4)) % 4) for j in range(16)], dtype=np.intp
)


def key_expansion(key16: bytes) -> np.ndarray:
    """Return the 11 round keys as an (11, 16) uint8 array (column-major).

    Works at 32-bit word granularity (a "word" is one AES column). Flattening
    the 44 words yields byte order j = row + 4*col, matching the state layout.
    """
    assert len(key16) == 16
    words = [list(key16[4 * i : 4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [int(SBOX[b]) for b in temp]     # SubWord
            temp[0] ^= _RCON[i // 4 - 1]            # Rcon
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
    flat = bytes(b for word in words for b in word)
    return np.frombuffer(flat, dtype=np.uint8).reshape(11, 16).copy()


# --------------------------------------------------------------------------
# Vectorized encryption over N states, recording SubBytes-input bytes.
# --------------------------------------------------------------------------


def _mix_columns(state: np.ndarray) -> np.ndarray:
    """state: (N,16) uint8 column-major. Returns MixColumns(state)."""
    s = state.reshape(-1, 4, 4)          # (N, col, row)? we stored col-major:
    # flat j = row + 4*col  -> reshape(-1,4,4) gives [n, col, row]
    out = np.empty_like(s)
    a0, a1, a2, a3 = s[:, :, 0], s[:, :, 1], s[:, :, 2], s[:, :, 3]
    out[:, :, 0] = _XT[a0] ^ _X3[a1] ^ a2 ^ a3
    out[:, :, 1] = a0 ^ _XT[a1] ^ _X3[a2] ^ a3
    out[:, :, 2] = a0 ^ a1 ^ _XT[a2] ^ _X3[a3]
    out[:, :, 3] = _X3[a0] ^ a1 ^ a2 ^ _XT[a3]
    return out.reshape(state.shape)


def encrypt_trace(plaintexts: np.ndarray, round_keys: np.ndarray):
    """
    Encrypt N plaintexts and record the SubBytes-input byte of every table
    lookup, in issue order.

    Parameters
    ----------
    plaintexts : (N,16) uint8
    round_keys : (11,16) uint8   (from key_expansion)

    Returns
    -------
    ciphertext : (N,16) uint8
    sub_in     : (N, 10, 16) uint8
        For each of the 10 rounds, the 16 state bytes *presented to the table*
        (i.e. after that round's AddRoundKey, before substitution), in state
        index order 0..15. These byte values are the lookup indices; the two
        layouts differ only in how index -> address -> flash-line is computed.
    """
    state = plaintexts.astype(np.uint8, copy=True)
    N = state.shape[0]
    sub_in = np.empty((N, 10, 16), dtype=np.uint8)

    state ^= round_keys[0]                              # initial AddRoundKey
    for rnd in range(10):
        sub_in[:, rnd, :] = state                      # lookup indices this round
        state = SBOX[state]                            # SubBytes
        state = state[:, _SHIFT_ROWS]                  # ShiftRows
        if rnd != 9:
            state = _mix_columns(state)                # MixColumns (not last round)
        state ^= round_keys[rnd + 1]                   # AddRoundKey
    return state, sub_in


# --------------------------------------------------------------------------
# Map recorded lookups to ordered flash-line sequences for each layout.
# --------------------------------------------------------------------------

# T-table access order inside a round: for output column c (0..3), for row
# r (0..3), access table Te_r at the ShiftRows-selected state position.
# Precompute (position, table_id) for the 16 accesses of a T-table round.
_TT_POS = np.array(
    [(r + 4 * ((c + r) % 4)) for c in range(4) for r in range(4)], dtype=np.intp
)
_TT_TAB = np.array([r for c in range(4) for r in range(4)], dtype=np.intp)


def line_sequence(sub_in: np.ndarray, layout: str, line_bytes: int = 16):
    """
    Convert recorded SubBytes-input bytes into an ordered (N, L) array of
    *flash line numbers* for the requested table layout.

    layout == "sbox":
        single 256-byte table at line 0; entry size 1 byte.
        accesses in state-index order 0..15 each round, 10 rounds -> L=160.

    layout == "ttable":
        Te0..Te3 (1 KiB each, 4-byte entries) laid out consecutively, then the
        final-round S-box after them. Rounds 1..9 use Te_r, round 10 uses S-box.
        L = 160.

    Returns
    -------
    lines : (N, L) int32   flash line index of every data lookup, in order.
    meta  : dict           layout metadata (entries_per_line, index_bits_leaked...)
    """
    N = sub_in.shape[0]
    epl = line_bytes  # entries per line for 1-byte entries

    if layout == "sbox":
        # order: round r, position j=0..15 ; index value = sub_in[:,r,j]
        vals = sub_in.reshape(N, 160).astype(np.int32)    # (N,160), rounds*16
        lines = (vals // epl).astype(np.int32)            # base line 0
        meta = dict(
            layout="sbox", entry_bytes=1, entries_per_line=epl,
            table_lines=256 // epl, index_bits_leaked=8 - int(np.log2(epl)),
        )
        return lines, meta

    if layout == "ttable":
        epl4 = line_bytes // 4                             # entries per line (4B)
        lines_per_table = 256 // epl4                      # e.g. 64 for 16B lines
        seq = []
        for rnd in range(10):
            if rnd != 9:
                # T-table round: 16 accesses in (_TT_POS order), table _TT_TAB
                vals = sub_in[:, rnd, _TT_POS].astype(np.int32)   # (N,16) indices
                base = (_TT_TAB * lines_per_table).astype(np.int32)  # base line
                ln = base[None, :] + (vals // epl4)
            else:
                # final round: S-box, placed AFTER the four T-tables
                sbox_base = np.int32(4 * lines_per_table)
                vals = sub_in[:, rnd, :].astype(np.int32)  # (N,16) state order
                ln = sbox_base + (vals // epl)
            seq.append(ln.astype(np.int32))
        lines = np.concatenate(seq, axis=1)               # (N,160)
        meta = dict(
            layout="ttable", entry_bytes=4, entries_per_line=epl4,
            table_lines=lines_per_table,
            index_bits_leaked=8 - int(np.log2(epl4)),
        )
        return lines, meta

    raise ValueError(f"unknown layout {layout!r}")


def random_plaintexts(n: int, rng: np.random.Generator) -> np.ndarray:
    return rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
