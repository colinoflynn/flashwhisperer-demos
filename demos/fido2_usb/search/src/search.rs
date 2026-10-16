// Driver: split the space, hand chunks to CPU threads and to the GPU, re-check
// whatever a kernel flags with the reference AES.
//
// Layout of the enumeration
// -------------------------
// The free fields are ordered by byte index. The lowest few - enough to make at
// least ~8k candidates - become the *inner* block and are precomputed once into
// a table of OR-masks; everything else, plus anchor_top6, is the *outer* index.
// Making the low bytes innermost means a whole inner block shares w1..w3 of the
// key, and the table is built once for the entire run because the free bits do
// not depend on anchor_top6.
//
// Sharing work between devices
// ----------------------------
// There is one atomic cursor over the outer range and every worker - each CPU
// thread and the GPU - takes chunks from it. The GPU takes far larger chunks
// because each launch is a host round trip, but nothing schedules the split: a
// device that is twice as fast simply comes back for chunks twice as often. That
// is what makes `--gpu` additive rather than a replacement, and it is why the
// reported rate is broken out per device instead of being quoted as one number.
//
// Surviving a long run
// --------------------
// 2^50 is tens of hours, so `--checkpoint` records how far the scan has got and
// `--resume` picks it up. The recorded watermark is the end of the *contiguous*
// prefix of completed chunks, not the cursor: chunks finish out of order, and
// resuming from the cursor would skip whatever was still in flight. Chunks handed
// out but unfinished at the moment of a crash are simply redone.

use crate::aes;
use crate::gpu::{self, Gpu};
use crate::kernel::{self, Suspect};
use crate::problem::Problem;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[repr(align(32))]
#[derive(Clone, Copy)]
pub struct Blk(pub [u8; 32]);

pub struct Plan {
    pub n_inner_digits: usize,
    pub n_inner: usize,
    pub n_outer: u64,
    /// One OR-mask table per shared line. At pad 0 the masks are plain low-two
    /// fields and do not depend on the line, so this holds a single table and
    /// `tab_for` ignores its argument -- byte-identical to the behaviour before
    /// pad support existed. At pad != 0 a reached byte's four candidates are not
    /// an XOR coset, so the whole byte comes from the mask and the table is
    /// per-line: 65 of them, a few MB, built once.
    pub tabs: Vec<Vec<Blk>>,
    pub free: [bool; 16],
}

impl Plan {
    #[inline]
    pub fn tab_for(&self, line: u8) -> &[Blk] {
        if self.tabs.len() == 1 {
            &self.tabs[0]
        } else {
            &self.tabs[line as usize]
        }
    }
}

const INNER_MIN: usize = 8192;
const INNER_MAX: usize = 65536;

pub fn plan(p: &Problem) -> Plan {
    let mut n_inner: usize = 1;
    let mut n_inner_digits = 0usize;
    for d in &p.digits {
        if n_inner >= INNER_MIN {
            break;
        }
        if n_inner * d.radix as usize > INNER_MAX {
            break;
        }
        n_inner *= d.radix as usize;
        n_inner_digits += 1;
    }

    let mut n_outer: u64 = p.n_lines() as u64; // anchor_top6, or the shared line
    for d in &p.digits[n_inner_digits..] {
        n_outer = n_outer.saturating_mul(d.radix as u64);
    }

    // Table of OR-masks: entry j holds candidate 2j in lane 0, 2j+1 in lane 1.
    let n_tabs = if p.pad == 0 { 1 } else { p.n_lines() as usize };
    let mut tabs = Vec::with_capacity(n_tabs);
    for line in 0..n_tabs {
        let mut tab = Vec::with_capacity(n_inner.max(2) / 2);
        if n_inner >= 2 {
            for j in 0..n_inner / 2 {
                let mut b = Blk([0u8; 32]);
                for lane in 0..2 {
                    let mut idx = 2 * j + lane;
                    for d in &p.digits[..n_inner_digits] {
                        let r = d.radix as usize;
                        let t = (idx % r) as u8;
                        // At pad 0 this is the low-two field itself; at pad != 0
                        // a reached byte's mask is the whole candidate value and
                        // an unreached byte's is still the raw 0..255 field.
                        b.0[lane * 16 + d.byte] = if p.pad != 0 && d.radix == 4 {
                            p.cand(d.byte, line as u8, t)
                        } else {
                            t
                        };
                        idx /= r;
                    }
                }
                tab.push(b);
            }
        }
        tabs.push(tab);
    }

    Plan { n_inner_digits, n_inner, n_outer, tabs, free: p.free_mask() }
}

/// Decode an outer index into (anchor_top6, kbase).
pub fn kbase_for(p: &Problem, pl: &Plan, o: u64) -> (u8, [u8; 16]) {
    let mut x = o;
    let mut raw = [0u8; 16];
    for d in &p.digits[pl.n_inner_digits..] {
        let r = d.radix as u64;
        raw[d.byte] = (x % r) as u8;
        x /= r;
    }
    // The line index is the outermost field, so it is only known after the
    // others have been divided out -- which is why the window mapping of the
    // outer digits happens here rather than in the loop above.
    let line = x as u8;
    let mut extra = [0u8; 16];
    for d in &p.digits[pl.n_inner_digits..] {
        extra[d.byte] = if p.pad != 0 && d.radix == 4 {
            p.cand(d.byte, line, raw[d.byte])
        } else {
            raw[d.byte]
        };
    }
    let a = x as u8; // 0..64 at pad 0, the shared line 0..=64 otherwise
    let mut kb = p.kbase(a, &pl.free);
    for i in 0..16 {
        kb[i] |= extra[i];
    }
    (a, kb)
}

/// The candidate key at one inner index of a given kbase.
#[inline]
pub fn key_at_line(pl: &Plan, line: u8, kb: &[u8; 16], inner: usize) -> [u8; 16] {
    let mut k = *kb;
    let blk = &pl.tab_for(line)[inner / 2].0;
    let off = (inner % 2) * 16;
    for i in 0..16 {
        k[i] |= blk[off + i];
    }
    k
}

pub struct Outcome {
    pub hits: Vec<[u8; 16]>,
    pub candidates: u64,
    pub seconds: f64,
    pub cpu_candidates: u64,
    pub gpu_candidates: u64,
    /// Candidates a resumed checkpoint let us skip. Not included in `candidates`.
    pub skipped: u64,
    /// Set when the run did not cover the whole space, with the reason. A caller
    /// must not read "0 hits" as "no key exists" when this is set.
    pub aborted: Option<String>,
    /// Matches the GPU reported that the reference AES then disagreed with. Any
    /// non-zero value means the kernel is wrong, not that the file is.
    pub gpu_false_hits: u64,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Backend {
    Vaes,
    AesNi,
    Scalar,
}

pub fn backend_name(b: Backend) -> &'static str {
    match b {
        Backend::Vaes => "VAES/AVX2 (2 candidates per register)",
        Backend::AesNi => "AES-NI/SSE (1 candidate per register)",
        Backend::Scalar => "portable scalar (no AES instructions found)",
    }
}

/// 0 = auto, 1 = force VAES, 2 = force AES-NI, 3 = force scalar. Set once from
/// the command line so the fallback paths can be exercised on a CPU that has
/// the fast one.
static FORCE_BACKEND: AtomicU8 = AtomicU8::new(0);

pub fn force_backend(name: &str) -> Result<(), String> {
    let v = match name {
        "auto" => 0,
        "vaes" => 1,
        "aesni" => 2,
        "scalar" => 3,
        _ => return Err(format!("unknown backend {:?}: use auto, vaes, aesni or scalar", name)),
    };
    FORCE_BACKEND.store(v, Ordering::Relaxed);
    Ok(())
}

pub fn pick_backend() -> Backend {
    match FORCE_BACKEND.load(Ordering::Relaxed) {
        1 => return Backend::Vaes,
        2 => return Backend::AesNi,
        3 => return Backend::Scalar,
        _ => {}
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("vaes") && is_x86_feature_detected!("avx2") {
            return Backend::Vaes;
        }
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse4.1") {
            return Backend::AesNi;
        }
    }
    Backend::Scalar
}

/// Re-check a flagged range exactly, against every oracle pair.
fn rescan(p: &Problem, pl: &Plan, line: u8, kb: &[u8; 16], s: Suspect, out: &mut Vec<[u8; 16]>) {
    let base = pl.tab_for(line).as_ptr() as *const u8;
    for idx in s.0..(s.0 + s.1).min(pl.n_inner) {
        let mut k = *kb;
        unsafe {
            let m = base.add(idx * 16);
            for i in 0..16 {
                k[i] |= *m.add(i);
            }
        }
        if p.oracle.iter().all(|(cb, ks)| &aes::encrypt_block(&k, cb) == ks) {
            out.push(k);
        }
    }
}

/// Whole-space scalar search, used when the space is too small to be worth a
/// table (and as a cross-check of the SIMD path).
fn search_scalar_all(p: &Problem) -> Vec<[u8; 16]> {
    let free = p.free_mask();
    let mut hits = Vec::new();
    let radices: Vec<u32> = p.digits.iter().map(|d| d.radix).collect();
    let mut vals = vec![0u32; radices.len()];
    for a in 0..64u8 {
        let kb = p.kbase(a, &free);
        loop {
            let mut k = kb;
            for (d, v) in p.digits.iter().zip(&vals) {
                k[d.byte] |= *v as u8;
            }
            if p.oracle.iter().all(|(cb, ks)| &aes::encrypt_block(&k, cb) == ks) {
                hits.push(k);
            }
            // odometer
            let mut c = 0;
            loop {
                if c == radices.len() {
                    break;
                }
                vals[c] += 1;
                if vals[c] < radices[c] {
                    break;
                }
                vals[c] = 0;
                c += 1;
            }
            if c == radices.len() {
                break;
            }
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// Progress, and the watermark a checkpoint can be resumed from
// ---------------------------------------------------------------------------

struct Shared {
    next: AtomicU64,
    done: AtomicU64,
    cpu_done: AtomicU64,
    gpu_done: AtomicU64,
    active: AtomicU64,
    end_ns: AtomicU64,
    stop: AtomicBool,
    gpu_false_hits: AtomicU64,
    hits: Mutex<Vec<[u8; 16]>>,
    abort: Mutex<Option<String>>,
    /// Completed outer ranges, coalesced. Kept short: workers finish chunks in
    /// nearly the order they take them, so this holds a handful of entries.
    completed: Mutex<Vec<(u64, u64)>>,
}

impl Shared {
    fn fail(&self, msg: String) {
        let mut a = self.abort.lock().unwrap();
        if a.is_none() {
            *a = Some(msg);
        }
        self.stop.store(true, Ordering::Release);
    }

    fn mark_done(&self, start: u64, end: u64) {
        let mut c = self.completed.lock().unwrap();
        c.push((start, end));
        c.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(c.len());
        for &(s, e) in c.iter() {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        *c = merged;
    }

    /// End of the contiguous completed prefix starting at `from`.
    fn watermark(&self, from: u64) -> u64 {
        let c = self.completed.lock().unwrap();
        match c.first() {
            Some(&(s, e)) if s <= from => e,
            _ => from,
        }
    }
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

/// A cheap fingerprint of everything that defines the search, so a checkpoint
/// cannot be applied to a different constraint file. FNV-1a over the fields the
/// enumeration depends on - not the name, which a caller may have renamed, and
/// not `answer_key_hex`, which the search never reads.
pub fn fingerprint(p: &Problem, pl: &Plan) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: u8| {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    };
    eat(p.anchor as u8);
    for i in 0..16 {
        match p.diff6[i] {
            Some(d) => {
                eat(1);
                eat(d);
            }
            None => eat(0),
        }
        eat(p.known_low2[i]);
    }
    for d in &p.digits {
        eat(d.byte as u8);
        eat(d.radix as u8);
        eat((d.radix >> 8) as u8);
    }
    for (cb, ks) in &p.oracle {
        for b in cb.iter().chain(ks.iter()) {
            eat(*b);
        }
    }
    for b in pl.n_outer.to_le_bytes() {
        eat(b);
    }
    eat(pl.n_inner as u8);
    eat((pl.n_inner >> 8) as u8);
    h
}

pub struct Checkpoint {
    pub watermark: u64,
    pub candidates: u64,
    pub seconds: f64,
    pub hits: Vec<[u8; 16]>,
}

pub fn read_checkpoint(path: &Path, want_fp: u64) -> Result<Checkpoint, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let mut c = Checkpoint { watermark: 0, candidates: 0, seconds: 0.0, hits: Vec::new() };
    let mut fp: Option<u64> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match k {
            "fingerprint" => fp = u64::from_str_radix(v, 16).ok(),
            "watermark" => c.watermark = v.parse().unwrap_or(0),
            "candidates" => c.candidates = v.parse().unwrap_or(0),
            "elapsed_s" => c.seconds = v.parse().unwrap_or(0.0),
            "hit" => c.hits.push(aes::from_hex16(v)?),
            _ => {}
        }
    }
    match fp {
        Some(f) if f == want_fp => Ok(c),
        Some(f) => Err(format!(
            "{} is a checkpoint for a different problem (fingerprint {:016x}, this one is {:016x}) \
             - refusing to resume from it",
            path.display(),
            f,
            want_fp
        )),
        None => Err(format!("{} has no fingerprint line", path.display())),
    }
}

fn write_checkpoint(path: &Path, p: &Problem, pl: &Plan, c: &Checkpoint) {
    let mut s = String::new();
    s.push_str("# fido_search checkpoint - see search.rs. Safe to delete; the run restarts.\n");
    s.push_str(&format!("vector={}\n", p.name));
    s.push_str(&format!("fingerprint={:016x}\n", fingerprint(p, pl)));
    s.push_str(&format!("n_outer={}\n", pl.n_outer));
    s.push_str(&format!("n_inner={}\n", pl.n_inner));
    s.push_str(&format!("watermark={}\n", c.watermark));
    s.push_str(&format!("candidates={}\n", c.candidates));
    s.push_str(&format!("elapsed_s={:.3}\n", c.seconds));
    for h in &c.hits {
        s.push_str(&format!("hit={}\n", aes::hex16(h)));
    }
    // Write-then-rename so a kill during the write cannot leave a half file.
    let tmp = path.with_extension("tmp");
    let ok = std::fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(s.as_bytes()).and_then(|_| f.sync_all()))
        .and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = ok {
        eprintln!("\n  !! cannot write checkpoint {}: {}", path.display(), e);
    }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

pub struct RunCfg<'a> {
    pub threads: usize,
    pub cpus: Vec<usize>,
    pub quiet: bool,
    /// Borrowed, not owned, so one built program and one set of device buffers
    /// serve every vector in a run instead of being rebuilt per vector. One entry
    /// per device: each gets a worker, and they share the one work cursor with the
    /// CPU threads, so devices of different speeds need no rebalancing.
    pub gpu: Vec<&'a mut Gpu>,
    /// candidates the GPU should aim to cover per launch
    pub gpu_batch: u64,
    pub checkpoint: Option<PathBuf>,
    pub resume: bool,
}

impl<'a> RunCfg<'a> {
    pub fn plain(threads: usize, cpus: &[usize], quiet: bool) -> RunCfg<'a> {
        RunCfg {
            threads,
            cpus: cpus.to_vec(),
            quiet,
            gpu: Vec::new(),
            gpu_batch: 1 << 30,
            checkpoint: None,
            resume: false,
        }
    }
}

/// The original signature, kept because the selftests call it dozens of times.
pub fn run(p: &Problem, threads: usize, cpus: &[usize], quiet: bool) -> Outcome {
    run_cfg(p, &mut RunCfg::plain(threads, cpus, quiet))
}

pub fn run_cfg(p: &Problem, cfg: &mut RunCfg<'_>) -> Outcome {
    let pl = plan(p);
    let backend = pick_backend();
    let total: u64 = match u64::try_from(p.space()) {
        Ok(t) => t,
        Err(_) => {
            return Outcome {
                hits: Vec::new(),
                candidates: 0,
                seconds: 0.0,
                cpu_candidates: 0,
                gpu_candidates: 0,
                skipped: 0,
                aborted: Some(format!(
                    "search space 2^{:.0} does not fit in a u64 - this file is not searchable, \
                     it needs more ladder relations",
                    (p.space() as f64).log2()
                )),
                gpu_false_hits: 0,
            };
        }
    };

    if pl.n_inner < 2 || (backend == Backend::Scalar && cfg.gpu.is_empty()) {
        let t0 = Instant::now();
        let hits = search_scalar_all(p);
        let n = hits.len();
        let _ = n;
        return Outcome {
            hits,
            candidates: total,
            seconds: t0.elapsed().as_secs_f64(),
            cpu_candidates: total,
            gpu_candidates: 0,
            skipped: 0,
            aborted: None,
            gpu_false_hits: 0,
        };
    }

    // --- resume ---------------------------------------------------------------
    let fp = fingerprint(p, &pl);
    let mut resume_from = 0u64;
    let mut prior = Checkpoint { watermark: 0, candidates: 0, seconds: 0.0, hits: Vec::new() };
    if cfg.resume {
        if let Some(path) = &cfg.checkpoint {
            if path.exists() {
                match read_checkpoint(path, fp) {
                    Ok(c) => {
                        resume_from = c.watermark.min(pl.n_outer);
                        prior = c;
                        if !cfg.quiet {
                            println!(
                                "  resume  : from outer step {} of {} ({:.3}% already done, {} hit(s) carried over)",
                                resume_from,
                                pl.n_outer,
                                100.0 * resume_from as f64 / pl.n_outer as f64,
                                prior.hits.len()
                            );
                        }
                    }
                    Err(e) => {
                        return Outcome {
                            hits: Vec::new(),
                            candidates: 0,
                            seconds: 0.0,
                            cpu_candidates: 0,
                            gpu_candidates: 0,
                            skipped: 0,
                            aborted: Some(e),
                            gpu_false_hits: 0,
                        }
                    }
                }
            }
        }
    }
    let skipped = resume_from * pl.n_inner as u64;
    let remaining = total - skipped;

    // --- GPU set-up -----------------------------------------------------------
    let inner_log2 = pl.n_inner.trailing_zeros();
    let mut gpu: Vec<&mut Gpu> = std::mem::take(&mut cfg.gpu);
    let mut gpu_chunk = 0u64;
    if !gpu.is_empty() {
        // A padded table makes the OR-mask table depend on the shared line, and the
        // GPU uploads ONE table per problem. Left unguarded it would upload line 0's
        // masks and search a space that does not contain the key -- a silent wrong
        // answer, which is worse than no answer. The CPU path rebuilds per line, and
        // at the sizes a padded problem reaches (2^45 with the k[15] table, ~3 h on
        // ten cores) the GPU is not needed.
        if !p.masks_are_static() {
            eprintln!(
                "  !! pad = {} and the GPU kernel takes a single OR-mask table, which is \
                 only valid for an aligned table; running on the CPU only. (Per-line \
                 re-upload is the change that would lift this.)",
                p.pad
            );
            gpu.clear();
        }
    }
    if !gpu.is_empty() {
        if !pl.n_inner.is_power_of_two() {
            eprintln!(
                "  !! inner block is {} candidates, not a power of two - the GPU kernel needs one; \
                 running on the CPU only",
                pl.n_inner
            );
            gpu.clear();
        } else {
            gpu_chunk = (cfg.gpu_batch / pl.n_inner as u64).max(1);
            gpu_chunk = gpu_chunk.min(pl.n_outer.max(1));
            let tab = gpu::tab_bytes(&pl);
            // A device that cannot be set up sits the vector out rather than
            // taking the others down with it.
            let mut kept: Vec<&mut Gpu> = Vec::new();
            for g in gpu.into_iter() {
                match g.bind_problem(&tab, gpu_chunk as usize) {
                    Ok(()) => kept.push(g),
                    Err(e) => eprintln!("  !! GPU set-up failed ({}); that device sits this one out", e),
                }
            }
            gpu = kept;
        }
    }

    // ~16M candidates per CPU chunk: long enough that the outer setup is noise,
    // short enough that ten threads of unequal speed still finish together.
    let chunk: u64 = ((16_000_000 / pl.n_inner).max(1)) as u64;

    let n_workers = cfg.threads as u64 + gpu.len() as u64;
    if n_workers == 0 {
        // Otherwise the monitor sees no active workers, stops at once, and the
        // caller is handed a clean "0 hits" for a space nothing looked at.
        return Outcome {
            hits: prior.hits,
            candidates: 0,
            seconds: 0.0,
            cpu_candidates: 0,
            gpu_candidates: 0,
            skipped,
            aborted: Some("no workers: 0 CPU threads and no usable GPU".into()),
            gpu_false_hits: 0,
        };
    }
    let sh = Arc::new(Shared {
        next: AtomicU64::new(resume_from),
        done: AtomicU64::new(0),
        cpu_done: AtomicU64::new(0),
        gpu_done: AtomicU64::new(0),
        active: AtomicU64::new(n_workers),
        end_ns: AtomicU64::new(0),
        stop: AtomicBool::new(false),
        gpu_false_hits: AtomicU64::new(0),
        hits: Mutex::new(prior.hits.clone()),
        abort: Mutex::new(None),
        completed: Mutex::new(if resume_from > 0 { vec![(0, resume_from)] } else { Vec::new() }),
    });

    let t0 = Instant::now();
    std::thread::scope(|sc| {
        // --- CPU workers ------------------------------------------------------
        for t in 0..cfg.threads {
            let sh = sh.clone();
            let pl = &pl;
            let cpu = cfg.cpus.get(t).copied();
            sc.spawn(move || {
                if let Some(c) = cpu {
                    set_affinity(c);
                }
                let mut sus: Vec<Suspect> = Vec::new();
                let mut local: Vec<[u8; 16]> = Vec::new();
                loop {
                    if sh.stop.load(Ordering::Acquire) {
                        break;
                    }
                    let start = sh.next.fetch_add(chunk, Ordering::Relaxed);
                    if start >= pl.n_outer {
                        break;
                    }
                    let end = (start + chunk).min(pl.n_outer);
                    for o in start..end {
                        let (line, kb) = kbase_for(p, pl, o);
                        let tab = pl.tab_for(line).as_ptr() as *const u8;
                        sus.clear();
                        unsafe {
                            match backend {
                                Backend::Vaes => kernel::kernel_vaes::<{ kernel::UNROLL }>(
                                    &kb, tab, pl.n_inner, &p.oracle[0].0, &p.oracle[0].1, &mut sus,
                                ),
                                Backend::AesNi => kernel::kernel_aesni(
                                    &kb, tab, pl.n_inner, &p.oracle[0].0, &p.oracle[0].1, &mut sus,
                                ),
                                Backend::Scalar => unreachable!(),
                            }
                        }
                        for s in sus.iter() {
                            rescan(p, pl, line, &kb, *s, &mut local);
                        }
                        // Publish immediately, never at worker exit: a hit has to
                        // be in the shared list BEFORE this chunk is marked done,
                        // or a checkpoint can record a watermark past the hit
                        // without the hit, and the resume will never look there
                        // again. Hits are astronomically rare, so the lock is free.
                        if !local.is_empty() {
                            sh.hits.lock().unwrap().extend(local.drain(..));
                        }
                    }
                    let n = (end - start) * pl.n_inner as u64;
                    sh.done.fetch_add(n, Ordering::Relaxed);
                    sh.cpu_done.fetch_add(n, Ordering::Relaxed);
                    sh.mark_done(start, end);
                }
                if !local.is_empty() {
                    sh.hits.lock().unwrap().extend(local);
                }
                sh.end_ns.fetch_max(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
                sh.active.fetch_sub(1, Ordering::Release);
            });
        }

        // --- GPU workers ------------------------------------------------------
        for g in gpu {
            let sh = sh.clone();
            let pl = &pl;
            sc.spawn(move || {
                let g = g;
                let mut kb_buf: Vec<u8> = Vec::with_capacity(gpu_chunk as usize * 16);
                let mut local: Vec<[u8; 16]> = Vec::new();
                loop {
                    if sh.stop.load(Ordering::Acquire) {
                        break;
                    }
                    let start = sh.next.fetch_add(gpu_chunk, Ordering::Relaxed);
                    if start >= pl.n_outer {
                        break;
                    }
                    let end = (start + gpu_chunk).min(pl.n_outer);
                    gpu::kbase_batch(p, pl, start, end, &mut kb_buf);
                    // Only a chunk that completed cleanly may be marked done: a
                    // chunk marked done can end up inside a checkpoint watermark,
                    // and a resume will never look at it again.
                    let mut chunk_ok = true;
                    match g.search_batch(&kb_buf, inner_log2, &p.oracle[0].0, &p.oracle[0].1) {
                        Ok(hs) => {
                            for (orel, inner) in hs {
                                let o = start + orel as u64;
                                if o >= end || inner as usize >= pl.n_inner {
                                    sh.fail(format!(
                                        "GPU reported a hit outside the batch it was given \
                                         (outer +{} of {}, inner {} of {})",
                                        orel,
                                        end - start,
                                        inner,
                                        pl.n_inner
                                    ));
                                    chunk_ok = false;
                                    break;
                                }
                                let (lnv, kbv) = kbase_for(p, pl, o);
                                let key = key_at_line(pl, lnv, &kbv, inner as usize);
                                if p.oracle.iter().all(|(cb, ks)| &aes::encrypt_block(&key, cb) == ks) {
                                    local.push(key);
                                } else {
                                    // The kernel claims an exact 128-bit match and
                                    // the reference AES says otherwise. That is a
                                    // broken kernel, not a near miss.
                                    sh.gpu_false_hits.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(e) => {
                            // This chunk is NOT marked done, and the run is
                            // aborted, because silently skipping it would turn a
                            // driver error into "no key found".
                            sh.fail(format!("GPU failed on outer [{}, {}): {}", start, end, e));
                            break;
                        }
                    }
                    // Same ordering rule as the CPU worker: hits are shared before
                    // the chunk is marked done.
                    if !local.is_empty() {
                        sh.hits.lock().unwrap().extend(local.drain(..));
                    }
                    if !chunk_ok {
                        break;
                    }
                    let n = (end - start) * pl.n_inner as u64;
                    sh.done.fetch_add(n, Ordering::Relaxed);
                    sh.gpu_done.fetch_add(n, Ordering::Relaxed);
                    sh.mark_done(start, end);
                }
                if !local.is_empty() {
                    sh.hits.lock().unwrap().extend(local);
                }
                sh.end_ns.fetch_max(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
                sh.active.fetch_sub(1, Ordering::Release);
            });
        }

        // --- monitor: progress line and checkpoints ---------------------------
        if !cfg.quiet || cfg.checkpoint.is_some() {
            let mut last = 0u64;
            let mut tlast = Instant::now();
            // None until the first write. The first checkpoint goes out on the
            // first pass rather than at t+60s, so an unwritable path is found in
            // the first second of a forty-hour run instead of an hour into it.
            let mut tckpt: Option<Instant> = None;
            loop {
                std::thread::sleep(Duration::from_millis(100));
                let d = sh.done.load(Ordering::Relaxed);
                let finished = d >= remaining || sh.active.load(Ordering::Acquire) == 0;

                if let Some(path) = &cfg.checkpoint {
                    if finished || tckpt.map_or(true, |t| t.elapsed() >= Duration::from_secs(60)) {
                        tckpt = Some(Instant::now());
                        let c = Checkpoint {
                            watermark: sh.watermark(0),
                            candidates: prior.candidates + d,
                            seconds: prior.seconds + t0.elapsed().as_secs_f64(),
                            hits: sh.hits.lock().unwrap().clone(),
                        };
                        write_checkpoint(path, p, &pl, &c);
                    }
                }
                if finished {
                    break;
                }
                if cfg.quiet {
                    continue;
                }
                let now = Instant::now();
                if now.duration_since(tlast) < Duration::from_secs(2) {
                    continue;
                }
                let rate = (d - last) as f64 / now.duration_since(tlast).as_secs_f64();
                last = d;
                tlast = now;
                if rate > 0.0 {
                    let el = t0.elapsed().as_secs_f64();
                    let split = {
                        let c = sh.cpu_done.load(Ordering::Relaxed) as f64 / el;
                        let gq = sh.gpu_done.load(Ordering::Relaxed) as f64 / el;
                        if gq > 0.0 {
                            format!(" [cpu {:.2} + gpu {:.2}]", c / 1e9, gq / 1e9)
                        } else {
                            String::new()
                        }
                    };
                    eprint!(
                        "\r  {:>6.2}%  {:>7.3} Gcand/s{}   elapsed {}   eta {}      ",
                        100.0 * (skipped + d) as f64 / total as f64,
                        rate / 1e9,
                        split,
                        hms(el),
                        hms((remaining - d.min(remaining)) as f64 / rate)
                    );
                }
            }
        }
    });
    if !cfg.quiet {
        eprint!("\r{:100}\r", "");
    }

    let mut h = std::mem::take(&mut *sh.hits.lock().unwrap());
    h.sort();
    h.dedup();
    let ns = sh.end_ns.load(Ordering::Relaxed);
    let seconds = if ns > 0 { ns as f64 / 1e9 } else { t0.elapsed().as_secs_f64() };
    let aborted = sh.abort.lock().unwrap().clone();
    Outcome {
        hits: h,
        candidates: sh.done.load(Ordering::Relaxed),
        seconds,
        cpu_candidates: sh.cpu_done.load(Ordering::Relaxed),
        gpu_candidates: sh.gpu_done.load(Ordering::Relaxed),
        skipped,
        aborted,
        gpu_false_hits: sh.gpu_false_hits.load(Ordering::Relaxed),
    }
}

pub fn hms(s: f64) -> String {
    if !s.is_finite() || s < 0.0 {
        return "-".into();
    }
    let t = s as u64;
    format!("{:02}:{:02}:{:02}", t / 3600, (t / 60) % 60, t % 60)
}

// ---------------------------------------------------------------------------
// CPU selection. On a hybrid part the P-cores come first (higher
// EfficiencyClass), and only one logical CPU per physical core is used so the
// chosen cores are really distinct.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod win {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetLogicalProcessorInformationEx(rel: u32, buf: *mut u8, len: *mut u32) -> i32;
        pub fn SetThreadAffinityMask(h: isize, mask: usize) -> usize;
        pub fn GetCurrentThread() -> isize;
    }
    pub const RELATION_PROCESSOR_CORE: u32 = 0;
}

pub fn pick_cpus(n: usize) -> Vec<usize> {
    #[cfg(windows)]
    {
        if let Some(v) = cores_windows() {
            let mut v = v;
            // Highest EfficiencyClass first (P before E), then by CPU index.
            v.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            return v.into_iter().take(n).map(|(_, c)| c).collect();
        }
    }
    (0..n).collect()
}

#[cfg(windows)]
fn cores_windows() -> Option<Vec<(u8, usize)>> {
    unsafe {
        let mut len: u32 = 0;
        win::GetLogicalProcessorInformationEx(win::RELATION_PROCESSOR_CORE, std::ptr::null_mut(), &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        if win::GetLogicalProcessorInformationEx(win::RELATION_PROCESSOR_CORE, buf.as_mut_ptr(), &mut len) == 0 {
            return None;
        }
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 8 <= len as usize {
            let rel = u32::from_le_bytes(buf[off..off + 4].try_into().ok()?);
            let size = u32::from_le_bytes(buf[off + 4..off + 8].try_into().ok()?) as usize;
            if size == 0 {
                break;
            }
            if rel == win::RELATION_PROCESSOR_CORE && off + 48 <= len as usize {
                // PROCESSOR_RELATIONSHIP: Flags@8, EfficiencyClass@9, GroupCount@30,
                // GroupMask[0] = GROUP_AFFINITY { Mask: usize @32, Group: u16 @40 }
                let eff = buf[off + 9];
                let mask = usize::from_le_bytes(buf[off + 32..off + 40].try_into().ok()?);
                if mask != 0 {
                    out.push((eff, mask.trailing_zeros() as usize));
                }
            }
            off += size;
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

pub fn set_affinity(cpu: usize) {
    #[cfg(windows)]
    unsafe {
        if cpu < usize::BITS as usize {
            win::SetThreadAffinityMask(win::GetCurrentThread(), 1usize << cpu);
        }
    }
    #[cfg(not(windows))]
    {
        let _ = cpu;
    }
}
