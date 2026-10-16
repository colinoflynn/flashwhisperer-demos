"""
Key-recovery attacks and leakage analysis for flash-timing side channels.

Primary attack: a Bernstein-style correlation (profiled) attack.

  * Profiling ("study") phase: with a *known* key k0 (typically all zeros),
    build for each plaintext byte position i a timing template
        study_i[v] = mean encryption cycles over plaintexts with byte i == v.
  * Attack phase: with the *unknown* key k, build the same templates
        attack_i[v] = mean cycles over plaintexts with byte i == v.
  * Because the timing depends on the S-box/T-table input state byte
        s_i = p_i XOR k_i,
    we have attack_i[p] ~ study_i[p XOR (k_i XOR k0_i)]. The key byte is
    recovered as the XOR shift g that best correlates the two templates:
        k_i = k0_i XOR argmax_g  corr( attack_i[.], study_i[. XOR g] ).

This is model-agnostic: it does not assume any particular cache geometry, only
that the per-byte timing signature is a function of the state byte. That makes
it the honest way to ask "is this a *useful* attack?" - run it and see how many
traces it needs, and whether it needs any at all.

Also provided: `first_round_line_leakage`, an analytic look at exactly what a
single flash-line hit/miss reveals (top n bits of p XOR k), used in the writeup.
"""

from __future__ import annotations

import numpy as np


# --------------------------------------------------------------------------
# Profiling templates
# --------------------------------------------------------------------------


def byte_templates(plaintexts: np.ndarray, cycles: np.ndarray):
    """
    Return (16, 256) mean-cycles templates and (16,256) counts.

    templates[i, v] = mean of `cycles` over traces whose plaintext byte i == v.
    """
    N = plaintexts.shape[0]
    tmpl = np.zeros((16, 256), dtype=np.float64)
    cnt = np.zeros((16, 256), dtype=np.int64)
    c = cycles.astype(np.float64)
    for i in range(16):
        b = plaintexts[:, i]
        sums = np.bincount(b, weights=c, minlength=256)
        counts = np.bincount(b, minlength=256)
        with np.errstate(invalid="ignore", divide="ignore"):
            tmpl[i] = sums / np.maximum(counts, 1)
        cnt[i] = counts
    return tmpl, cnt


# --------------------------------------------------------------------------
# Correlation attack
# --------------------------------------------------------------------------


def _xor_shift_matrix(vec: np.ndarray) -> np.ndarray:
    """Return M (256,256) with M[g, p] = vec[p XOR g]."""
    p = np.arange(256)
    idx = p[None, :] ^ np.arange(256)[:, None]   # idx[g,p] = p^g
    return vec[idx]


def _corr_rows(mat: np.ndarray, vec: np.ndarray) -> np.ndarray:
    """Pearson correlation of each row of `mat` (G,256) with `vec` (256,)."""
    m = mat - mat.mean(axis=1, keepdims=True)
    v = vec - vec.mean()
    num = (m * v).sum(axis=1)
    den = np.sqrt((m * m).sum(axis=1) * (v * v).sum() + 1e-30)
    return num / den


def recover_key(study_tmpl, attack_tmpl, k0=None):
    """
    Recover all 16 key bytes.

    Returns
    -------
    best_key : (16,) int      argmax guess per byte (already XORed with k0)
    scores   : (16,256) float correlation score per byte per candidate key value
    """
    if k0 is None:
        k0 = np.zeros(16, dtype=np.int64)
    best = np.zeros(16, dtype=np.int64)
    scores = np.zeros((16, 256), dtype=np.float64)
    for i in range(16):
        M = _xor_shift_matrix(study_tmpl[i])       # M[g,p] = study_i[p^g]
        corr = _corr_rows(M, attack_tmpl[i])       # corr over p, per g
        # k_i = k0_i XOR g  -> reindex scores by candidate key value
        g = np.arange(256)
        key_vals = g ^ int(k0[i])
        s = np.zeros(256)
        s[key_vals] = corr
        scores[i] = s
        best[i] = int(np.argmax(s))
    return best, scores


def key_byte_ranks(scores, true_key):
    """Rank (0 = best) of the correct value for each key byte."""
    ranks = np.zeros(16, dtype=np.int64)
    for i in range(16):
        order = np.argsort(-scores[i])              # high score first
        ranks[i] = int(np.where(order == int(true_key[i]))[0][0])
    return ranks


# --------------------------------------------------------------------------
# Analytic first-round leakage
# --------------------------------------------------------------------------


def _shift_bits(layout: str, line_bytes: int):
    """(shift, bits) for a flash line of `line_bytes`. index >> shift == line;
    `bits` = key-difference bits a collision reveals = 8 - shift."""
    entry = 1 if layout == "sbox" else 4          # table entry size in bytes
    epl = line_bytes // entry                     # entries per flash line
    shift = int(np.log2(epl))
    return shift, 8 - shift


def collision_pairs(layout: str, line_bytes: int = 16, kind: str = "natural"):
    """
    Round-1 lookup pairs that can share a flash line, i.e. that a cache-collision
    attack can exploit. Each pair recovers the top `bits` of (k_a XOR k_b).

    Returns a list of dicts: {a, b, shift, bits}.
      a, b  : plaintext / key byte indices whose round-1 lookups may collide.
      shift : index >> shift == flash line (depends on line width & entry size).
      bits  : number of key-difference bits recovered (8 - shift).

    The granularity depends on the flash line width: a wider line (more entries)
    reveals fewer bits, a narrower one reveals more. E.g. a 64-bit (8-byte) line
    holds 8 S-box entries -> reveals 5 bits, vs 4 bits for a 128-bit line.

    layout "sbox":  a single table, so any two round-1 lookups can collide. With
                    a single line buffer only *adjacent* lookups (j, j+1) do;
                    kind="natural" returns those, kind="all" returns every pair.
    layout "ttable": lookups only collide inside the *same* Te table. kind is
                    ignored; same-table byte pairs are returned.
    """
    shift, bits = _shift_bits(layout, line_bytes)
    if layout == "sbox":
        if kind == "all":
            pairs = [(a, b) for a in range(16) for b in range(a + 1, 16)]
        else:
            pairs = [(j, j + 1) for j in range(15)]      # adjacent in access order
        return [dict(a=a, b=b, shift=shift, bits=bits) for a, b in pairs]

    if layout == "ttable":
        from . import aes
        groups = {
            l: [int(aes._TT_POS[i]) for i in range(16) if aes._TT_TAB[i] == l]
            for l in range(4)
        }
        pairs = []
        for bs in groups.values():
            for i in range(len(bs)):
                for j in range(i + 1, len(bs)):
                    pairs.append(dict(a=bs[i], b=bs[j], shift=shift, bits=bits))
        return pairs

    raise ValueError(layout)


def collision_attack(plaintexts: np.ndarray, cycles: np.ndarray, pairs,
                     rng: np.random.Generator | None = None):
    """
    For each pair, recover the top bits of (k_a XOR k_b).

    A collision (same flash line for the two lookups) turns a miss into a hit,
    which *lowers* the encryption time. So for the byte pair (a,b) we group
    traces by the top bits of (p_a XOR p_b) and pick the group with the lowest
    mean time - that group is where the lookups landed on the same line, which
    happens exactly when (p_a XOR p_b) top bits == (k_a XOR k_b) top bits.

    Returns
    -------
    guesses : list[int]   guessed top-bits value of (k_a XOR k_b) per pair
    scores  : list[np.ndarray]  mean cycles per candidate (for diagnostics)
    """
    if rng is None:
        rng = np.random.default_rng(0)
    c = cycles.astype(np.float64)
    guesses, scores = [], []
    for pr in pairs:
        a, b, shift = pr["a"], pr["b"], pr["shift"]
        d = (plaintexts[:, a].astype(np.int32) ^ plaintexts[:, b].astype(np.int32)) >> shift
        ng = 1 << pr["bits"]
        sums = np.bincount(d, weights=c, minlength=ng)
        cnts = np.bincount(d, minlength=ng)
        means = sums / np.maximum(cnts, 1)
        # Break exact ties randomly so a *no-signal* channel (all group means
        # equal) reports as random guessing rather than always picking index 0.
        tiebreak = rng.random(ng) * 1e-9
        guesses.append(int(np.argmin(means + tiebreak)))
        scores.append(means)
    return guesses, scores


def collision_score(guesses, pairs, true_key) -> dict:
    """How many key-difference tops the collision attack got right."""
    ok = 0
    for g, pr in zip(guesses, pairs):
        truth = (int(true_key[pr["a"]]) ^ int(true_key[pr["b"]])) >> pr["shift"]
        ok += int(g == truth)
    return dict(recovered=ok, total=len(pairs),
                frac=ok / max(len(pairs), 1))


def residual_entropy_bits(layout: str, line_bytes: int = 16) -> dict:
    """
    Key bits left unknown after an ideal first-order cache-collision attack.

    The attack recovers, for connected byte pairs, the top `bits` of the key
    XOR difference. That fixes the top `bits` of all 16 key bytes relative to
    one reference byte, leaving:
      * the reference byte's top bits  (unknown): `bits`
      * every byte's low (8-bits) bits (unknown): 16 * (8 - bits)
    """
    _, bits = _shift_bits(layout, line_bytes)
    low = 8 - bits
    residual = bits + 16 * low
    return dict(layout=layout, bits_per_diff=bits,
                residual_key_bits=residual,
                full_key_bits=128,
                recovered_key_bits=128 - residual)


def first_round_line_leakage(entries_per_line: int) -> dict:
    """
    What does a single flash-line hit/miss on a first-round lookup reveal?

    A lookup at index x = p XOR k lands in flash line x // entries_per_line, so
    the line number equals the top (8 - log2(entries_per_line)) bits of p XOR k.
    A hit against a *known* previously-latched line therefore reveals those bits
    of p XOR k, i.e. of the key byte (p is known).
    """
    bits = 8 - int(np.log2(entries_per_line))
    return dict(
        entries_per_line=entries_per_line,
        line_bits=bits,
        key_candidates_after_one_hit=1 << (8 - bits),  # remaining ambiguity
        note=f"one line hit fixes the top {bits} bits of (p XOR k)",
    )
