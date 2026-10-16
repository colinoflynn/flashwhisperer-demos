// The hot loop.
//
// One candidate costs a full AES-128 key schedule plus one block encryption,
// and on this shape the schedule is the expensive half. Both are done with the
// AES units:
//
//   * SubWord(RotWord(w3)) ^ Rcon is computed as
//         vpshufb   -> every dword of the register becomes RotWord(w3)
//         vaesenclast(.., rcon)
//     ShiftRows is the identity on a register whose four columns are equal, so
//     aesenclast degenerates to SubBytes ^ roundkey, which is exactly SubWord.
//     This replaces AESKEYGENASSIST, which on Intel is ~12 cycles of reciprocal
//     throughput and would dominate everything else.
//
//   * The prefix XOR w4..w7 is two byte-shifts and two XORs.
//
//   * The last round takes `rk10 ^ expected_keystream` as its round key, so the
//     result is already ciphertext^expected: a candidate matches iff it is zero,
//     and the comparison costs nothing.
//
// Rejection is by folding those differences over a group of candidates with an
// unsigned byte-wise MIN and testing the group once. A hit drives every byte of
// the accumulator to zero; the reverse needs each of the sixteen byte positions
// to be zeroed by *some* candidate in the group, which for a group of 48 is
// about 2^-41. Groups that trip are re-scanned with the reference AES, so the
// fast path may be approximate while the answer stays exact.
//
// (MIN, not AND: ANDing 32 unrelated values leaves zero almost surely, which
// would flag every group and quietly turn the whole search into the scalar
// rescan. That is exactly what the first version of this file did.)
//
// With VAES each 256-bit register carries two independent candidates; the
// AES-NI path is the same code one candidate at a time.

#![allow(unused_macros)]

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[repr(align(32))]
pub struct A32<T>(pub T);

const fn rcon_table() -> [u8; 320] {
    let rc = [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut t = [0u8; 320];
    let mut r = 0;
    while r < 10 {
        // Rcon lands in byte 0 of each of the eight dwords (four per 128-bit lane).
        let mut d = 0;
        while d < 8 {
            t[r * 32 + d * 4] = rc[r];
            d += 1;
        }
        r += 1;
    }
    t
}

pub static RCON32: A32<[u8; 320]> = A32(rcon_table());

/// Per 128-bit lane: each dword := bytes 13,14,15,12 = RotWord(w3).
pub static ROT32: A32<[u8; 32]> = A32([
    13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12,
    13, 14, 15, 12, 13, 14, 15, 12,
]);

/// Independent candidate registers in flight. Enough to cover the ~60-cycle
/// dependency chain through the ten schedule steps; beyond that the register
/// file runs out and the compiler starts spilling.
pub const UNROLL: usize = 8;

/// Vectors folded into one accumulator before the group is tested. A multiple
/// of UNROLL so the group is covered entirely by the unrolled path. At 48
/// candidates per lane a spurious trip has probability about 2^-41 - roughly
/// once per day of searching, and it costs only a re-scan.
pub const GRP: usize = 48;

/// A group of candidate indices whose accumulator went to zero, i.e. one that
/// may contain a hit. Half-open: [start, start + count).
pub type Suspect = (usize, usize);

// ---------------------------------------------------------------------------
// VAES / AVX2: two candidates per register, U registers in flight
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "vaes,avx2")]
pub unsafe fn kernel_vaes<const U: usize>(
    kbase: &[u8; 16],
    tab: *const u8,
    n_cand: usize,
    p: &[u8; 16],
    exp: &[u8; 16],
    sus: &mut Vec<Suspect>,
) {
    // One key-expansion step, on U independent keys at a time.
    macro_rules! ex {
        ($k:expr, $rc:expr, $rot:expr) => {{
            let k = $k;
            let t = _mm256_shuffle_epi8(k, $rot);
            let t = _mm256_aesenclast_epi128(t, _mm256_load_si256($rc as *const __m256i));
            let x = _mm256_xor_si256(k, _mm256_bslli_epi128::<4>(k));
            let x = _mm256_xor_si256(x, _mm256_bslli_epi128::<8>(x));
            _mm256_xor_si256(x, t)
        }};
    }

    let kb = _mm256_broadcastsi128_si256(_mm_loadu_si128(kbase.as_ptr() as *const __m128i));
    let pb = _mm256_broadcastsi128_si256(_mm_loadu_si128(p.as_ptr() as *const __m128i));
    let eb = _mm256_broadcastsi128_si256(_mm_loadu_si128(exp.as_ptr() as *const __m128i));
    let rot = _mm256_load_si256(ROT32.0.as_ptr() as *const __m256i);
    let rcon = RCON32.0.as_ptr();
    let ones = _mm256_set1_epi32(-1);
    let zero = _mm256_setzero_si256();

    let n_vec = n_cand / 2;
    let mut j = 0usize;

    while j < n_vec {
        let g = if n_vec - j >= GRP { GRP } else { n_vec - j };
        let mut acc = ones;
        let mut i = 0usize;

        while i + U <= g {
            let q = tab.add((j + i) * 32);
            let mut k = [zero; U];
            let mut s = [zero; U];
            for u in 0..U {
                k[u] = _mm256_or_si256(kb, _mm256_load_si256(q.add(u * 32) as *const __m256i));
                s[u] = _mm256_xor_si256(pb, k[u]);
            }
            for r in 0..9 {
                let rc = rcon.add(r * 32);
                for u in 0..U {
                    k[u] = ex!(k[u], rc, rot);
                }
                for u in 0..U {
                    s[u] = _mm256_aesenc_epi128(s[u], k[u]);
                }
            }
            let rc = rcon.add(9 * 32);
            for u in 0..U {
                k[u] = ex!(k[u], rc, rot);
            }
            for u in 0..U {
                let d = _mm256_aesenclast_epi128(s[u], _mm256_xor_si256(k[u], eb));
                acc = _mm256_min_epu8(acc, d);
            }
            i += U;
        }

        while i < g {
            let mut ka = _mm256_or_si256(kb, _mm256_load_si256(tab.add((j + i) * 32) as *const __m256i));
            let mut sa = _mm256_xor_si256(pb, ka);
            for r in 0..9 {
                ka = ex!(ka, rcon.add(r * 32), rot);
                sa = _mm256_aesenc_epi128(sa, ka);
            }
            ka = ex!(ka, rcon.add(9 * 32), rot);
            acc = _mm256_min_epu8(acc, _mm256_aesenclast_epi128(sa, _mm256_xor_si256(ka, eb)));
            i += 1;
        }

        // A lane is suspect when all four of its dwords are zero. Test the two
        // lanes separately: a hit in one says nothing about the other.
        let m = _mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpeq_epi32(acc, zero)));
        if (m & 0x0f) == 0x0f || (m & 0xf0) == 0xf0 {
            sus.push((j * 2, g * 2));
        }
        j += g;
    }
}


// ---------------------------------------------------------------------------
// AES-NI / SSE: one candidate per register (fallback for CPUs without VAES)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse4.1,ssse3")]
pub unsafe fn kernel_aesni(
    kbase: &[u8; 16],
    tab: *const u8,
    n_cand: usize,
    p: &[u8; 16],
    exp: &[u8; 16],
    sus: &mut Vec<Suspect>,
) {
    macro_rules! ex {
        ($k:expr, $r:expr, $rot:expr) => {{
            let k = $k;
            let t = _mm_shuffle_epi8(k, $rot);
            let t = _mm_aesenclast_si128(
                t,
                _mm_load_si128(RCON32.0.as_ptr().add($r * 32) as *const __m128i),
            );
            let x = _mm_xor_si128(k, _mm_slli_si128::<4>(k));
            let x = _mm_xor_si128(x, _mm_slli_si128::<8>(x));
            _mm_xor_si128(x, t)
        }};
    }

    let kb = _mm_loadu_si128(kbase.as_ptr() as *const __m128i);
    let pb = _mm_loadu_si128(p.as_ptr() as *const __m128i);
    let eb = _mm_loadu_si128(exp.as_ptr() as *const __m128i);
    let rot = _mm_load_si128(ROT32.0.as_ptr() as *const __m128i);
    let ones = _mm_set1_epi32(-1);

    let mut j = 0usize;
    while j < n_cand {
        let g = if n_cand - j >= 2 * GRP { 2 * GRP } else { n_cand - j };
        let mut acc = ones;
        let mut i = 0usize;

        while i + 4 <= g {
            let q = tab.add((j + i) * 16);
            let mut ka = _mm_or_si128(kb, _mm_load_si128(q as *const __m128i));
            let mut kc = _mm_or_si128(kb, _mm_load_si128(q.add(16) as *const __m128i));
            let mut ke = _mm_or_si128(kb, _mm_load_si128(q.add(32) as *const __m128i));
            let mut kg = _mm_or_si128(kb, _mm_load_si128(q.add(48) as *const __m128i));
            let mut sa = _mm_xor_si128(pb, ka);
            let mut sc = _mm_xor_si128(pb, kc);
            let mut se = _mm_xor_si128(pb, ke);
            let mut sg = _mm_xor_si128(pb, kg);
            macro_rules! rnd {
                ($r:expr) => {
                    ka = ex!(ka, $r, rot);
                    kc = ex!(kc, $r, rot);
                    ke = ex!(ke, $r, rot);
                    kg = ex!(kg, $r, rot);
                    sa = _mm_aesenc_si128(sa, ka);
                    sc = _mm_aesenc_si128(sc, kc);
                    se = _mm_aesenc_si128(se, ke);
                    sg = _mm_aesenc_si128(sg, kg);
                };
            }
            rnd!(0);
            rnd!(1);
            rnd!(2);
            rnd!(3);
            rnd!(4);
            rnd!(5);
            rnd!(6);
            rnd!(7);
            rnd!(8);
            ka = ex!(ka, 9, rot);
            kc = ex!(kc, 9, rot);
            ke = ex!(ke, 9, rot);
            kg = ex!(kg, 9, rot);
            let da = _mm_aesenclast_si128(sa, _mm_xor_si128(ka, eb));
            let dc = _mm_aesenclast_si128(sc, _mm_xor_si128(kc, eb));
            let de = _mm_aesenclast_si128(se, _mm_xor_si128(ke, eb));
            let dg = _mm_aesenclast_si128(sg, _mm_xor_si128(kg, eb));
            acc = _mm_min_epu8(acc, _mm_min_epu8(da, dc));
            acc = _mm_min_epu8(acc, _mm_min_epu8(de, dg));
            i += 4;
        }
        while i < g {
            let mut ka = _mm_or_si128(kb, _mm_load_si128(tab.add((j + i) * 16) as *const __m128i));
            let mut sa = _mm_xor_si128(pb, ka);
            macro_rules! rnd1 {
                ($r:expr) => {
                    ka = ex!(ka, $r, rot);
                    sa = _mm_aesenc_si128(sa, ka);
                };
            }
            rnd1!(0);
            rnd1!(1);
            rnd1!(2);
            rnd1!(3);
            rnd1!(4);
            rnd1!(5);
            rnd1!(6);
            rnd1!(7);
            rnd1!(8);
            ka = ex!(ka, 9, rot);
            acc = _mm_min_epu8(acc, _mm_aesenclast_si128(sa, _mm_xor_si128(ka, eb)));
            i += 1;
        }

        if _mm_testz_si128(acc, acc) == 1 {
            sus.push((j, g));
        }
        j += g;
    }
}
