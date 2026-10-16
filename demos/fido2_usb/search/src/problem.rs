// Constraint file -> a fully-specified search space.
//
// Reconstruction (verbatim from the brief):
//   k[anchor] = (anchor_top6 << 2) | low2[anchor]
//   k[i]      = ((diff6[i] ^ anchor_top6) << 2) | low2[i]   for reached bytes
//   k[j]      = 0..=255                                     for unreached bytes
//
// A key is therefore  kbase(anchor_top6)  OR  a pattern of free bits, where the
// free bits are two per byte in `unknown_low2_bytes` and eight per byte in
// `unreached_bytes`. kbase holds zeros wherever a free bit lands, so the two
// parts compose with a plain OR - which is what lets the hot loop be a table
// load and one vpor.

use crate::aes;
use crate::json::J;

#[derive(Clone, Copy, Debug)]
pub struct Digit {
    pub byte: usize,
    pub radix: u32, // 4 for a low-2 pair, 256 for an unreached byte
}

#[derive(Clone, Debug)]
pub struct Problem {
    pub name: String,
    pub anchor: usize,
    pub diff6: [Option<u8>; 16],
    pub known_low2: [u8; 16],
    pub digits: Vec<Digit>,
    pub oracle: Vec<([u8; 16], [u8; 16])>,
    pub answer: Option<[u8; 16]>,
    pub declared_bits: Option<u32>,
    /// Bytes the victim's table sits into its 16-byte flash line. 0 = aligned,
    /// which is every vector written before 2026-09-26 and the only case the
    /// `diff6` XOR form is exact for.
    pub pad: u8,
    /// The input byte written to each reached position during the sweep that
    /// placed it. Only meaningful when `pad != 0`: at pad 0 the inputs cancel
    /// into the XOR difference and `diff6` carries everything.
    pub inputs: [u8; 16],
    /// The flash line each reached byte is constrained to, when the file gives
    /// them explicitly. `None` means the old behaviour: ONE line shared by every
    /// reached byte, enumerated as the outermost field.
    ///
    /// Real ladders do not produce one shared line. The RIOT FIDO2 campaign's
    /// sixteen relations occupy THREE (RESULTS.md section 5h): byte 14's input is
    /// fixed by CCM, so its line is whatever the key makes it and no choice of
    /// inputs moves it onto the anchor group's. The line assignment is instead
    /// pinned by the "link" bytes that appear on two lines at two different
    /// inputs, and the caller enumerates those across a family of vectors.
    ///
    /// When this is given there is nothing left to enumerate per line, so the
    /// OR-mask table stops depending on one -- which is also what lets the GPU
    /// take a padded problem.
    pub lines: Option<[u8; 16]>,
}

/// Table entries sharing flash line `l`, for a table `pad` bytes into a line.
///
/// `line(e) = (4*e + pad) / 16`, so the entries on line `l` are the integers `e`
/// with `16*l <= 4*e + pad < 16*l + 16`. At pad 0 that is the aligned quadruple
/// `4l..4l+3`; at pad 4 it is `4l-1 ..= 4l+2`, four CONSECUTIVE integers that
/// straddle a multiple of four -- which is exactly why no XOR class describes
/// them and why this function exists at all.
///
/// The first and last lines are short (three entries and one at pad 4), so the
/// result is padded by repeating its first element to keep a fixed radix of 4.
/// That generates a duplicate candidate or two on those two lines out of 65,
/// which costs a little work and can never miss a key.
pub fn window(l: u8, pad: u8) -> [u8; 4] {
    let lo = (16i32 * l as i32 - pad as i32 + 3).div_euclid(4);
    let mut v: Vec<u8> = (lo..lo + 4)
        .filter(|e| (0..=255).contains(e))
        .filter(|e| (4 * e + pad as i32).div_euclid(16) == l as i32)
        .map(|e| e as u8)
        .collect();
    if v.is_empty() {
        v.push(0);
    }
    let first = v[0];
    while v.len() < 4 {
        v.push(first);
    }
    [v[0], v[1], v[2], v[3]]
}

impl Problem {
    /// How many values the outermost field takes: the anchor's top six bits at
    /// pad 0, or the shared LINE index at any other pad -- and a padded table
    /// spans 65 lines, not 64, because both end lines are partly filled.
    pub fn n_lines(&self) -> u32 {
        if self.pad == 0 {
            64
        } else if self.lines.is_some() {
            1 // every line is given; nothing to enumerate
        } else {
            65
        }
    }

    /// True when the OR-mask table does not depend on the enumerated line, which
    /// is the condition the GPU needs: it uploads one table per problem.
    pub fn masks_are_static(&self) -> bool {
        self.pad == 0 || self.lines.is_some()
    }

    pub fn space(&self) -> u128 {
        let mut n: u128 = self.n_lines() as u128;
        for d in &self.digits {
            n *= d.radix as u128;
        }
        n
    }

    /// The value of byte `i` at shared line `l` and window position `t`.
    ///
    /// This is the one place the two line models differ, and everything else in
    /// the search is written against it.
    ///
    /// * pad 0: `k[i] = ((diff6[i] ^ l) << 2) | t` -- the top six bits come from
    ///   the XOR difference and `t` is the low-two field, so the value composes
    ///   with a plain OR and the kernels' mask table is independent of `l`.
    /// * pad != 0: `k[i] = window(l)[t] ^ input[i]`, because the constraint is
    ///   that `input[i] ^ k[i]` lands on line `l` and the window is not an XOR
    ///   coset. The whole byte comes from the table, so `kbase` contributes zero
    ///   there and the mask table has to be rebuilt per line.
    #[inline]
    pub fn cand(&self, i: usize, l: u8, t: u8) -> u8 {
        if self.pad == 0 {
            let top6 = self.diff6[i].unwrap_or(0) ^ l;
            (top6 << 2) | t
        } else {
            // A per-byte line ignores the enumerated one entirely.
            let line = match self.lines {
                Some(ls) => ls[i],
                None => l,
            };
            window(line, self.pad)[(t & 3) as usize] ^ self.inputs[i]
        }
    }

    /// Which bytes carry any enumerated bit.
    pub fn free_mask(&self) -> [bool; 16] {
        let mut f = [false; 16];
        for d in &self.digits {
            f[d.byte] = true;
        }
        f
    }

    /// kbase for a given anchor_top6: every bit that is *not* enumerated.
    pub fn kbase(&self, a: u8, free: &[bool; 16]) -> [u8; 16] {
        let mut k = [0u8; 16];
        for i in 0..16 {
            if self.diff6[i].is_none() {
                k[i] = 0; // unreached: the whole byte is a free field
            } else if self.pad != 0 {
                // The window position supplies the WHOLE byte, so a searched byte
                // has no base to contribute. A byte whose position is PINNED --
                // `known_low2` holds a window position, not a low-two field, when
                // the table is padded -- contributes its whole value here and is
                // not enumerated at all. That is what carries the link bytes.
                k[i] = if free[i] { 0 } else { self.cand(i, a, self.known_low2[i]) };
            } else {
                let top6 = self.diff6[i].unwrap() ^ a;
                k[i] = (top6 << 2) | if free[i] { 0 } else { self.known_low2[i] };
            }
        }
        k
    }

    /// Rebuild a key from explicit field values - the definition the SIMD kernel
    /// is checked against.
    pub fn rebuild(&self, a: u8, vals: &[u32]) -> [u8; 16] {
        let mut k = self.kbase(a, &self.free_mask());
        for (d, v) in self.digits.iter().zip(vals) {
            // At pad != 0 a reached byte's field is a window POSITION and the
            // table supplies the whole byte; an unreached byte is still a plain
            // 0..255 field, at either pad.
            let bits = if self.pad != 0 && d.radix == 4 {
                self.cand(d.byte, a, *v as u8)
            } else {
                *v as u8
            };
            k[d.byte] |= bits;
        }
        k
    }
}

fn hexpair(o: &J) -> Result<([u8; 16], [u8; 16]), String> {
    let cb = o
        .get("counter_block_hex")
        .and_then(|x| x.str())
        .ok_or("oracle entry missing counter_block_hex")?;
    let ks = o
        .get("keystream_hex")
        .and_then(|x| x.str())
        .ok_or("oracle entry missing keystream_hex")?;
    Ok((aes::from_hex16(cb)?, aes::from_hex16(ks)?))
}

pub fn load(v: &J) -> Result<Problem, String> {
    let name = v.get("name").and_then(|x| x.str()).unwrap_or("unnamed").to_string();
    let anchor = v.get("anchor_byte").and_then(|x| x.usize()).ok_or("missing anchor_byte")?;
    if anchor >= 16 {
        return Err(format!("anchor_byte {} out of range", anchor));
    }

    let d6 = v.get("diff6").and_then(|x| x.arr()).ok_or("missing diff6")?;
    if d6.len() != 16 {
        return Err(format!("diff6 has {} entries, expected 16", d6.len()));
    }
    let mut diff6 = [None; 16];
    for (i, e) in d6.iter().enumerate() {
        if !e.is_null() {
            let n = e.usize().ok_or("diff6 entry is neither null nor a number")?;
            if n > 63 {
                return Err(format!("diff6[{}] = {} does not fit in six bits", i, n));
            }
            diff6[i] = Some(n as u8);
        }
    }

    let unreached: Vec<usize> = v
        .get("unreached_bytes")
        .and_then(|x| x.arr())
        .ok_or("missing unreached_bytes")?
        .iter()
        .map(|x| x.usize().ok_or_else(|| "unreached_bytes entry not a number".to_string()))
        .collect::<Result<_, _>>()?;
    let unknown_low2: Vec<usize> = v
        .get("unknown_low2_bytes")
        .and_then(|x| x.arr())
        .ok_or("missing unknown_low2_bytes")?
        .iter()
        .map(|x| x.usize().ok_or_else(|| "unknown_low2_bytes entry not a number".to_string()))
        .collect::<Result<_, _>>()?;

    // diff6 must be null exactly on the unreached bytes.
    for i in 0..16 {
        let null = diff6[i].is_none();
        let listed = unreached.contains(&i);
        if null != listed {
            return Err(format!(
                "byte {}: diff6 null={} but unreached_bytes membership={}",
                i, null, listed
            ));
        }
    }
    if diff6[anchor] != Some(0) {
        return Err(format!("diff6[anchor={}] is {:?}, must be 0", anchor, diff6[anchor]));
    }
    for i in &unknown_low2 {
        if unreached.contains(i) {
            return Err(format!("byte {} is in both unknown_low2_bytes and unreached_bytes", i));
        }
    }

    let oracle: Vec<_> = v
        .get("oracle")
        .and_then(|x| x.arr())
        .ok_or("missing oracle")?
        .iter()
        .map(hexpair)
        .collect::<Result<_, _>>()?;
    if oracle.is_empty() {
        return Err("oracle is empty - nothing to test candidates against".into());
    }

    let answer = match v.get("answer_key_hex").and_then(|x| x.str()) {
        Some(s) => Some(aes::from_hex16(s)?),
        None => None,
    };

    // `known_low2` is given data: the low two bits of every reached byte the
    // problem is not asking us to search, keyed by byte index as a string. Empty
    // for full-2^44, where no low bit is known.
    let mut known_low2 = [0u8; 16];
    let mut pinned = [false; 16];
    if let Some(J::Obj(m)) = v.get("known_low2") {
        for (k, val) in m {
            let b: usize = k.parse().map_err(|_| format!("known_low2 key {:?} is not an index", k))?;
            if b >= 16 {
                return Err(format!("known_low2 key {:?} out of range", k));
            }
            let n = val.usize().ok_or_else(|| format!("known_low2[{}] is not a number", k))?;
            if n > 3 {
                return Err(format!("known_low2[{}] = {} does not fit in two bits", k, n));
            }
            known_low2[b] = n as u8;
            pinned[b] = true;
        }
    }

    // Every byte index must appear in exactly one of the three sets. The
    // generator asserts this; if it does not hold, the file is the bug.
    let mut under = Vec::new();
    let mut over = Vec::new();
    for i in 0..16 {
        let n = unknown_low2.contains(&i) as u32 + unreached.contains(&i) as u32 + pinned[i] as u32;
        if n == 0 {
            under.push(i);
        } else if n > 1 {
            over.push(i);
        }
    }
    if !under.is_empty() || !over.is_empty() {
        let mut msg = format!("vector `{}` does not account for every byte exactly once:", name);
        if !under.is_empty() {
            msg += &format!(
                " bytes {:?} appear in none of unknown_low2_bytes / known_low2 / unreached_bytes, \
                 so their low two bits are neither given nor searched",
                under
            );
        }
        if !over.is_empty() {
            msg += &format!(" bytes {:?} appear in more than one of them", over);
        }
        return Err(msg);
    }

    // Field list ordered by byte index: the kernel makes the low bytes the
    // innermost digits so a run of candidates shares w1..w3 of the schedule.
    let mut digits = Vec::new();
    for b in 0..16usize {
        if unreached.contains(&b) {
            digits.push(Digit { byte: b, radix: 256 });
        } else if unknown_low2.contains(&b) {
            digits.push(Digit { byte: b, radix: 4 });
        }
    }

    let declared_bits = v.get("search_space_bits").and_then(|x| x.usize()).map(|x| x as u32);

    // The table's offset inside its 16-byte flash line. Absent means 0, which is
    // what every vector written before 2026-09-26 means and the only case the
    // `diff6` XOR form is exact for.
    let pad = match v.get("pad").and_then(|x| x.usize()) {
        Some(n) if n < 16 && n % 4 == 0 => n as u8,
        Some(n) => return Err(format!("pad {} must be 0, 4, 8 or 12", n)),
        None => 0,
    };
    let mut inputs = [0u8; 16];
    if pad != 0 {
        let arr = v.get("inputs").and_then(|x| x.arr()).ok_or(
            "pad != 0 needs `inputs`: the byte written to each reached position during \
             the sweep that placed it. At pad 0 those cancel into diff6; at any other \
             pad they do not, because the line map is not a function of the XOR.",
        )?;
        if arr.len() != 16 {
            return Err(format!("inputs has {} entries, expected 16", arr.len()));
        }
        for (i, e) in arr.iter().enumerate() {
            if !e.is_null() {
                let n = e.usize().ok_or("inputs entry is neither null nor a number")?;
                if n > 255 {
                    return Err(format!("inputs[{}] = {} does not fit in a byte", i, n));
                }
                inputs[i] = n as u8;
            } else if diff6[i].is_some() {
                return Err(format!("inputs[{}] is null but byte {} is reached", i, i));
            }
        }
    }

    // Optional per-byte line assignment. Given it, nothing is enumerated per line
    // and a reached byte may have its window position PINNED via known_low2 --
    // which is how the link bytes that tie two lines together are carried.
    let mut lines: Option<[u8; 16]> = None;
    if let Some(arr) = v.get("lines").and_then(|x| x.arr()) {
        if pad == 0 {
            return Err("`lines` is only meaningful with pad != 0".into());
        }
        if arr.len() != 16 {
            return Err(format!("lines has {} entries, expected 16", arr.len()));
        }
        let mut ls = [0u8; 16];
        for (i, e) in arr.iter().enumerate() {
            if !e.is_null() {
                let n = e.usize().ok_or("lines entry is neither null nor a number")?;
                if n > 64 {
                    return Err(format!(
                        "lines[{}] = {} is out of range: a padded 1 KB table spans lines \
                         0..=64",
                        i, n
                    ));
                }
                ls[i] = n as u8;
            } else if diff6[i].is_some() {
                return Err(format!("lines[{}] is null but byte {} is reached", i, i));
            }
        }
        lines = Some(ls);
    }
    if pad != 0 && lines.is_none() {
        // Without explicit lines every reached byte must sit on the single
        // enumerated one, so none of them can be pinned.
        let bad: Vec<usize> = (0..16)
            .filter(|&i| diff6[i].is_some() && !unknown_low2.contains(&i))
            .collect();
        if !bad.is_empty() {
            return Err(format!(
                "pad != 0 without `lines`: reached bytes {:?} are not in \
                 unknown_low2_bytes. With one shared enumerated line there is no \
                 low-two field to pin, so every reached byte must be searched over its \
                 four window positions. Give `lines` if you mean to pin some.",
                bad
            ));
        }
    }

    let p = Problem {
        name,
        anchor,
        diff6,
        known_low2,
        digits,
        oracle,
        answer,
        declared_bits,
        pad,
        inputs,
        lines,
    };

    if let Some(bits) = p.declared_bits {
        let want = 1u128 << bits;
        // A padded space is 65 * 4^n, which is not a power of two, so an exact
        // match is only required of the aligned case.
        let ok = if p.pad == 0 { p.space() == want } else { p.space() >= want && p.space() < want * 2 };
        if !ok {
            return Err(format!(
                "computed search space {} != declared 2^{} = {} - constraint file is inconsistent",
                p.space(),
                bits,
                want
            ));
        }
    }
    Ok(p)
}
