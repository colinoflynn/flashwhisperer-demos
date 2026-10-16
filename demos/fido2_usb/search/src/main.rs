// Offline key search for the RIOT FIDO2 timing ladder.
//
// Enumerates the constraint set from req/GPU_SEARCH_REQUIREMENTS.md and returns
// every key that reproduces all oracle pairs under AES-128-ECB.
//
//   fido_search --all                 selftest, then tiny / small / medium, with timing
//   fido_search --vector full-2^44    the real problem
//   fido_search --selftest            FIPS-197 plus randomised kernel cross-checks
//
// Build: see build.ps1 (a bare rustc invocation; no crates).

mod aes;
mod gpu;
mod json;
mod kernel;
mod ocl;
mod problem;
mod search;

use problem::Problem;
use std::path::PathBuf;

/// Vectors at or below this many bits are the ones `--all` runs without being
/// asked. Anything larger is a campaign, not a test, and has to be named.
/// A threshold rather than a list of names: `--all` used to exclude `full-2^44`
/// by name, which silently started running `real-2^50` - a 40-hour job - the day
/// that vector was added to the file.
const AUTO_RUN_MAX_BITS: u32 = 36;

fn usage() -> ! {
    eprintln!(
        "usage: fido_search [options]
  --vectors <path>   constraint file            (default ../search_vectors.json)
                     Constraint files may carry `pad`: the bytes the victim's
                     table sits into its
                     16-byte flash line (0 = aligned, the default and the only
                     case a diff6 XOR difference is exact for). A file with
                     pad != 0 must also carry `inputs`, and runs on the CPU
                     only -- the GPU kernel takes one OR-mask table per problem
                     and a padded one needs a table per line.
                     A file may hold a `vectors` array of test problems, or be a
                     single bare problem - which is what a real, measured
                     constraint file looks like.
  --vector <name>    solve one vector by name, or `all`
  --all              selftest + every vector up to 2^{} (default action)
  --selftest         FIPS-197 C.1 and randomised kernel-vs-reference checks
  --quiet            no progress line

 CPU
  --threads <n>      worker threads             (default 10, or 9 with --gpu)
  --no-affinity      do not pin threads to distinct physical cores
  --cpus <l,i,s,t>   pin to exactly these logical CPUs (overrides the default,
                     which is one logical CPU per physical core, P-cores first)
  --backend <name>   auto (default), vaes, aesni or scalar - forces a kernel so
                     the fallback paths can be exercised on a CPU that has VAES

 GPU (OpenCL, compiled at run time; needs only the driver's ICD loader)
  --gpu              also search on the GPU, alongside the CPU threads
  --gpu-only         search on the GPU alone (--threads 0)
  --no-gpu           do not use the GPU even if one is present (default)
  --gpu-device <l>   which GPU(s): an index, a comma-separated list, or `all`.
                     Each gets a worker and they share one work cursor, so devices
                     of unequal speed need no rebalancing.          (default 0)
  --gpu-wg <n>       work-group size                           (default 256)
  --gpu-grid <n>     work-items per launch          (default 8 groups per CU)
  --gpu-repl-sh <n>  log2 of the T0 replication factor; 5 = 32 KB of local
                     memory and no bank conflicts (default: the largest the
                     device can hold, up to 5)
  --gpu-batch <n>    candidates per launch                     (default 2^30)

 Long runs
  --checkpoint <p>   record progress to <p> about once a minute
  --resume           start from <p>'s watermark instead of the beginning
",
        AUTO_RUN_MAX_BITS
    );
    std::process::exit(2)
}

#[derive(PartialEq, Clone, Copy)]
enum GpuUse {
    Off,
    With,
    Only,
}

struct Args {
    vectors: String,
    vector: Option<String>,
    all: bool,
    selftest: bool,
    threads: Option<usize>,
    affinity: bool,
    quiet: bool,
    cpus: Option<Vec<usize>>,
    gpu: GpuUse,
    /// "all", or a comma-separated list of device indices. A repeated index opens
    /// that device twice, which is how the several-device path gets exercised on a
    /// machine that has only one card.
    gpu_devices: String,
    gpu_opts: gpu::Options,
    checkpoint: Option<PathBuf>,
    resume: bool,
}

impl Args {
    /// CPU worker threads. With the GPU on, one core goes to the thread that
    /// drives it - NVIDIA's clFinish spins - so the default keeps the total at
    /// ten rather than oversubscribing.
    fn cpu_threads(&self) -> usize {
        match (self.threads, self.gpu) {
            (Some(n), _) => n,
            (None, GpuUse::Only) => 0,
            (None, GpuUse::With) => 9,
            (None, GpuUse::Off) => 10,
        }
    }
}

fn parse_args() -> Args {
    let mut a = Args {
        vectors: "../search_vectors.json".into(),
        vector: None,
        all: false,
        selftest: false,
        threads: None,
        affinity: true,
        quiet: false,
        cpus: None,
        gpu: GpuUse::Off,
        gpu_devices: "0".into(),
        gpu_opts: gpu::Options::default(),
        checkpoint: None,
        resume: false,
    };
    let mut it = std::env::args().skip(1);
    let num = |o: Option<String>| -> usize { o.and_then(|x| x.parse().ok()).unwrap_or_else(|| usage()) };
    while let Some(s) = it.next() {
        match s.as_str() {
            "--vectors" => a.vectors = it.next().unwrap_or_else(|| usage()),
            "--vector" => a.vector = Some(it.next().unwrap_or_else(|| usage())),
            "--all" => a.all = true,
            "--selftest" => a.selftest = true,
            "--threads" => a.threads = Some(num(it.next())),
            "--no-affinity" => a.affinity = false,
            "--cpus" => {
                let l = it.next().unwrap_or_else(|| usage());
                a.cpus = Some(l.split(',').filter_map(|x| x.trim().parse().ok()).collect());
            }
            "--quiet" => a.quiet = true,
            "--gpu" => a.gpu = GpuUse::With,
            "--gpu-only" => a.gpu = GpuUse::Only,
            "--no-gpu" => a.gpu = GpuUse::Off,
            "--gpu-device" => a.gpu_devices = it.next().unwrap_or_else(|| usage()),
            "--gpu-wg" => a.gpu_opts.wg = Some(num(it.next())),
            "--gpu-grid" => a.gpu_opts.grid = Some(num(it.next())),
            "--gpu-repl-sh" => a.gpu_opts.repl_sh = Some(num(it.next()) as u32),
            "--gpu-batch" => a.gpu_opts.batch_candidates = num(it.next()) as u64,
            "--checkpoint" => a.checkpoint = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--resume" => a.resume = true,
            "--backend" => {
                let n = it.next().unwrap_or_else(|| usage());
                if let Err(e) = search::force_backend(&n) {
                    eprintln!("{}", e);
                    std::process::exit(2);
                }
            }
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    if a.vector.is_none() && !a.selftest {
        a.all = true;
    }
    if a.resume && a.checkpoint.is_none() {
        eprintln!("--resume needs --checkpoint <path> to resume from");
        std::process::exit(2);
    }
    a
}

fn main() {
    let args = parse_args();

    println!("RIOT FIDO2 credential-key search");
    println!("  backend : {}", search::backend_name(search::pick_backend()));
    let cpus = cpu_list(&args);
    println!(
        "  threads : {} {}",
        args.cpu_threads(),
        if cpus.is_empty() { "unpinned".into() } else { format!("pinned to logical CPUs {:?}", cpus) }
    );

    // The GPU is opened once and reused for every vector: building the kernel
    // costs a few hundred milliseconds, which would otherwise be charged to the
    // first vector's rate.
    let mut devices: Vec<gpu::Gpu> = Vec::new();
    if args.gpu != GpuUse::Off {
        let wanted: Vec<usize> = if args.gpu_devices == "all" {
            match gpu::device_count() {
                Ok(n) => (0..n).collect(),
                Err(e) => {
                    eprintln!("  gpu     : unavailable - {}", e);
                    Vec::new()
                }
            }
        } else {
            args.gpu_devices.split(',').filter_map(|x| x.trim().parse().ok()).collect()
        };
        for idx in wanted {
            let o = gpu::Options { device: idx, ..args.gpu_opts };
            match gpu::Gpu::new(&o) {
                Ok(g) => {
                    println!("  gpu {}   : {}", devices.len(), g.describe());
                    devices.push(g);
                }
                Err(e) => eprintln!("  gpu {}   : unavailable - {}", idx, e),
            }
        }
        if devices.is_empty() {
            if args.gpu == GpuUse::Only {
                eprintln!("--gpu-only was asked for and no GPU could be opened; refusing to fall back to the CPU silently");
                std::process::exit(1);
            }
            eprintln!("            continuing on the CPU alone");
        }
    }
    if args.cpu_threads() == 0 && devices.is_empty() {
        eprintln!("nothing to search with: 0 CPU threads and no GPU");
        std::process::exit(2);
    }
    println!();

    if !fips197() {
        eprintln!("FIPS-197 C.1 FAILED - refusing to search with a broken AES core");
        std::process::exit(1);
    }
    println!("[ok] FIPS-197 C.1 AES-128 known-answer test");

    if args.selftest || args.all {
        let mut ok = !selftest() | !sweep_positions();
        // One device is enough to test the kernel; the rest run the same code.
        if let Some(g) = devices.first_mut() {
            ok |= !gpu_selftest(g);
        }
        if ok {
            eprintln!("selftest FAILED");
            std::process::exit(1);
        }
    }
    if args.selftest && !args.all && args.vector.is_none() {
        return;
    }

    let text = match std::fs::read_to_string(&args.vectors) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {}", args.vectors, e);
            std::process::exit(1);
        }
    };
    let doc = json::parse(&text).unwrap_or_else(|e| {
        eprintln!("{}: {}", args.vectors, e);
        std::process::exit(1)
    });

    // The format vector is the hardware ground truth for the oracle; check it if
    // it is sitting next to the constraint file.
    let fvpath = std::path::Path::new(&args.vectors).with_file_name("format_vector.json");
    if let Ok(t) = std::fs::read_to_string(&fvpath) {
        if let Ok(fv) = json::parse(&t) {
            check_format_vector(&fv);
        }
    }

    if let Some(core) = doc.get("aes_core_check") {
        let k = aes::from_hex16(core.get("key_hex").and_then(|x| x.str()).unwrap_or("")).unwrap();
        let p = aes::from_hex16(core.get("plaintext_hex").and_then(|x| x.str()).unwrap_or("")).unwrap();
        let c = aes::from_hex16(core.get("ciphertext_hex").and_then(|x| x.str()).unwrap_or("")).unwrap();
        let got = aes::encrypt_block(&k, &p);
        println!(
            "[{}] aes_core_check from the constraint file",
            if got == c { "ok" } else { "FAIL" }
        );
        if got != c {
            std::process::exit(1);
        }
    }

    // A file is either a bundle of test vectors or a single bare problem. A real
    // constraint file, produced from measured ladder relations, is the second
    // kind - it has no `vectors` array and no `answer_key_hex` - so refusing to
    // read one was refusing requirement 6 of the brief.
    let bare: Vec<&json::J>;
    let vectors: &[json::J];
    let is_bundle = doc.get("vectors").and_then(|x| x.arr()).is_some();
    if is_bundle {
        vectors = doc.get("vectors").and_then(|x| x.arr()).unwrap();
        bare = Vec::new();
    } else if doc.get("anchor_byte").is_some() {
        vectors = &[];
        bare = vec![&doc];
    } else {
        eprintln!(
            "{} is neither a `vectors` bundle nor a single problem (no `anchor_byte`)",
            args.vectors
        );
        std::process::exit(1);
    }

    let file_stem = std::path::Path::new(&args.vectors)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "constraints".into());

    let wanted: Vec<&json::J> = if !bare.is_empty() {
        bare
    } else {
        match &args.vector {
            Some(n) if n != "all" => {
                let v: Vec<_> = vectors
                    .iter()
                    .filter(|v| v.get("name").and_then(|x| x.str()) == Some(n.as_str()))
                    .collect();
                if v.is_empty() {
                    eprintln!("no vector named {:?}; available: {:?}", n, names(vectors));
                    std::process::exit(1);
                }
                v
            }
            Some(_) => vectors.iter().collect(),
            None => {
                // Size, not name: see AUTO_RUN_MAX_BITS.
                let (small, big): (Vec<_>, Vec<_>) = vectors.iter().partition(|v| {
                    v.get("search_space_bits").and_then(|x| x.usize()).unwrap_or(0) as u32
                        <= AUTO_RUN_MAX_BITS
                });
                if !big.is_empty() {
                    println!(
                        "Not running without being asked, because each is hours or more: {}",
                        big.iter()
                            .map(|v| format!(
                                "{} (2^{})",
                                v.get("name").and_then(|x| x.str()).unwrap_or("?"),
                                v.get("search_space_bits").and_then(|x| x.usize()).unwrap_or(0)
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!("Name one with --vector to run it.");
                }
                small
            }
        }
    };

    let mut best_rate = 0.0f64;
    let mut failures = 0usize;
    for v in wanted {
        let mut p = match problem::load(v) {
            Ok(p) => p,
            Err(e) => {
                println!("\n=== {} ===", v.get("name").and_then(|x| x.str()).unwrap_or("?"));
                println!("  SKIPPED: {}", e);
                failures += 1;
                continue;
            }
        };
        if p.name == "unnamed" {
            p.name = file_stem.clone();
        }
        let (rate, ok) = solve(&p, &args, &mut devices);
        best_rate = rate.max(best_rate);
        if !ok {
            failures += 1;
        }
    }

    if best_rate > 0.0 {
        println!();
        println!("Extrapolation at the measured rate:");
        println!(
            "  {:.3} Gcandidate/s on {} CPU thread(s){}",
            best_rate / 1e9,
            args.cpu_threads(),
            if devices.is_empty() { "" } else { " + the GPU" }
        );
        // Every vector the file declares, so the table does not go stale when a
        // larger one is added.
        let mut sizes: Vec<(String, u32)> = vectors
            .iter()
            .filter_map(|v| {
                Some((
                    v.get("name").and_then(|x| x.str())?.to_string(),
                    v.get("search_space_bits").and_then(|x| x.usize())? as u32,
                ))
            })
            .collect();
        sizes.sort_by_key(|(_, b)| *b);
        for (name, bits) in sizes {
            if bits <= AUTO_RUN_MAX_BITS {
                continue;
            }
            let n = 2f64.powi(bits as i32);
            println!("  {:<12} 2^{:<3} = {:.3e}  ->  {}", name, bits, n, search::hms(n / best_rate));
        }
    }
    if failures > 0 {
        std::process::exit(1);
    }
}

/// Logical CPUs to pin to: the explicit list, the auto-picked one, or none.
fn cpu_list(a: &Args) -> Vec<usize> {
    if !a.affinity {
        return Vec::new();
    }
    match &a.cpus {
        Some(v) => v.clone(),
        None => search::pick_cpus(a.cpu_threads()),
    }
}

fn names(vs: &[json::J]) -> Vec<&str> {
    vs.iter().filter_map(|v| v.get("name").and_then(|x| x.str())).collect()
}

fn solve(p: &Problem, args: &Args, devices: &mut [gpu::Gpu]) -> (f64, bool) {
    println!("\n=== {} ===", p.name);
    let pl = search::plan(p);
    let space = p.space();
    let bits = (space as f64).log2();
    println!("  space   : 2^{:.0}  = {} candidates", bits, space);
    println!("  anchor  : byte {}", p.anchor);
    // Name the fields for what they are in THIS file: an aligned table enumerates the
    // anchor's top six bits and a low-two pair per byte, a padded one enumerates a
    // shared line and a window position per byte -- and a padded one with explicit
    // per-byte lines enumerates no line at all. Printing "anchor_top6 (64)" for all
    // three, which this line used to do, misdescribes two of them.
    let (outer, field) = if p.pad == 0 {
        ("anchor_top6".to_string(), "low-2 pairs")
    } else if p.lines.is_some() {
        ("per-byte lines, none enumerated".to_string(), "window positions")
    } else {
        ("shared line".to_string(), "window positions")
    };
    println!(
        "  fields  : {} ({}) + {} {} + {} full bytes{}",
        outer,
        p.n_lines(),
        p.digits.iter().filter(|d| d.radix == 4).count(),
        field,
        p.digits.iter().filter(|d| d.radix == 256).count(),
        if p.pad != 0 { format!(", pad {}", p.pad) } else { String::new() }
    );
    // A file with too few relations is hopeless, and the brief asks that this be
    // obvious in a second rather than in a week. Say so and stop BEFORE printing a
    // layout whose outer-step count has already saturated its own counter.
    if u64::try_from(space).is_err() {
        let unreached: Vec<usize> = (0..16).filter(|&i| p.diff6[i].is_none()).collect();
        println!(
            "  VERDICT : not searchable. {} byte(s) unreached ({:?}), each costing 2^6, so the \
             space is 2^{:.0}.",
            unreached.len(),
            unreached,
            bits
        );
        // No wall time here on purpose: any figure would be a rate quoted from some
        // other run. The ratio to the largest size the search is designed for is
        // the honest statement and it does not go stale.
        println!(
            "            That is 2^{:.0} times `real-2^50`, the largest size this search is \
             built for.",
            bits - 50.0
        );
        println!("            This file needs more ladder relations, not more compute.");
        return (0.0, true); // a correct verdict, not a failure
    }

    println!(
        "  layout  : inner block {} candidates ({} innermost fields), {} outer steps",
        pl.n_inner, pl.n_inner_digits, pl.n_outer
    );

    // Sanity: the stated answer must lie inside the space we are about to search.
    // This used to read the field values straight out of the answer -- the anchor's
    // top six bits and each byte's low two -- which silently assumed the aligned
    // model. On a padded table the outer field is a LINE and a digit is a window
    // POSITION, so it cried wolf on a file that was right, which is worse than
    // useless: a warning that fires on correct input trains you to ignore it.
    //
    // Reachability does not depend on the encoding. Ask the question directly: is
    // there any assignment of the enumerated fields that rebuilds the answer?
    if let Some(ans) = p.answer {
        let mut reachable = false;
        for a in 0..p.n_lines() as u8 {
            let mut vals = Vec::with_capacity(p.digits.len());
            let mut ok = true;
            for d in &p.digits {
                if d.radix == 256 {
                    vals.push(ans[d.byte] as u32);
                } else {
                    match (0..d.radix as u8).find(|&t| p.cand(d.byte, a, t) == ans[d.byte]) {
                        Some(t) => vals.push(t as u32),
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
            }
            if ok && p.rebuild(a, &vals) == ans {
                reachable = true;
                break;
            }
        }
        if !reachable {
            println!("  !! answer_key_hex is NOT reachable from these constraints - file is wrong");
        }
    }

    let mut cfg = search::RunCfg {
        threads: args.cpu_threads(),
        cpus: cpu_list(args),
        quiet: args.quiet,
        gpu: devices.iter_mut().collect(),
        gpu_batch: args.gpu_opts.batch_candidates,
        checkpoint: args.checkpoint.clone(),
        resume: args.resume,
    };
    let out = search::run_cfg(p, &mut cfg);
    // A run that refused to start has no rate; printing NaN invites someone to
    // paste it into a table.
    let rate = if out.seconds > 0.0 { out.candidates as f64 / out.seconds } else { 0.0 };
    if rate > 0.0 {
        println!(
            "  result  : {} hit(s) in {:.3} s  =  {:.3} Gcandidate/s",
            out.hits.len(),
            out.seconds,
            rate / 1e9
        );
    } else {
        println!("  result  : {} hit(s), nothing searched", out.hits.len());
    }
    if out.gpu_candidates > 0 {
        println!(
            "  devices : cpu {:.3} G/s over {:.1}% of the space, gpu {:.3} G/s over {:.1}%",
            out.cpu_candidates as f64 / out.seconds / 1e9,
            100.0 * out.cpu_candidates as f64 / out.candidates.max(1) as f64,
            out.gpu_candidates as f64 / out.seconds / 1e9,
            100.0 * out.gpu_candidates as f64 / out.candidates.max(1) as f64
        );
    }
    if out.skipped > 0 {
        println!(
            "  resumed : {} candidates ({:.2}%) came from the checkpoint, not this run",
            out.skipped,
            100.0 * out.skipped as f64 / space as f64
        );
    }
    for h in &out.hits {
        println!("  KEY     : {}", aes::hex16(h));
    }

    // A wrong hit from the GPU means the kernel is broken. Never quiet about it,
    // and never let the run be read as a clean sweep.
    if out.gpu_false_hits > 0 {
        println!(
            "  [FAIL] the GPU reported {} exact 128-bit match(es) that the reference AES rejects \
             - the kernel is wrong, do not trust this result",
            out.gpu_false_hits
        );
        return (rate, false);
    }
    // An aborted run did not cover the space, so "0 hits" means nothing.
    if let Some(why) = &out.aborted {
        println!("  [FAIL] the search did not cover the whole space: {}", why);
        println!("         0 hits here does NOT mean no key exists.");
        return (rate, false);
    }

    let ok = match (p.answer, out.hits.len()) {
        (Some(a), 1) if out.hits[0] == a => {
            println!("  [ok] exactly one hit, equal to answer_key_hex");
            true
        }
        (Some(_), n) => {
            println!("  [FAIL] expected exactly one hit equal to answer_key_hex, got {}", n);
            false
        }
        (None, 0) => {
            println!("  [FAIL] no key satisfies the oracle - check the constraint file");
            false
        }
        (None, _) => {
            println!("  [ok] search complete");
            true
        }
    };
    (rate, ok)
}

fn fips197() -> bool {
    let k = aes::from_hex16("000102030405060708090a0b0c0d0e0f").unwrap();
    let p = aes::from_hex16("00112233445566778899aabbccddeeff").unwrap();
    let c = aes::from_hex16("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
    aes::encrypt_block(&k, &p) == c
}

fn check_format_vector(fv: &json::J) {
    let g = |k: &str| fv.get(k).and_then(|x| x.str()).map(|s| s.to_string());
    if let (Some(key), Some(cb), Some(ks)) =
        (g("cred_key_hex"), g("counter_block_A1_hex"), g("keystream_block_1_hex"))
    {
        let (k, cb, ks) = (
            aes::from_hex16(&key).unwrap(),
            aes::from_hex16(&cb).unwrap(),
            aes::from_hex16(&ks).unwrap(),
        );
        let ok_direct = aes::encrypt_block(&k, &cb) == ks;
        // credential_id[0:16] XOR plaintext[0:16] must be that same keystream.
        let mut ok_xor = None;
        if let (Some(cid), Some(pt)) = (g("credential_id_165_hex"), g("plaintext_136_hex")) {
            let (cid, pt) = (aes::from_hex(&cid).unwrap(), aes::from_hex(&pt).unwrap());
            if cid.len() >= 16 && pt.len() >= 16 {
                let mut x = [0u8; 16];
                for i in 0..16 {
                    x[i] = cid[i] ^ pt[i];
                }
                ok_xor = Some(x == ks);
            }
        }
        println!(
            "[{}] format_vector: AES128_ECB(cred_key, A1) == keystream block 1{}",
            if ok_direct { "ok" } else { "FAIL" },
            match ok_xor {
                Some(true) => " == credId[0:16] ^ plaintext[0:16]",
                Some(false) => "  (but credId^plaintext DISAGREES)",
                None => "",
            }
        );
    }
}

// ---------------------------------------------------------------------------
// Randomised cross-check: build a problem around a known key with a random
// shape, then make the real search find it. Exercises key reconstruction, the
// inner table, the odometer and the SIMD kernel together.
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Plant the answer at chosen positions inside the inner block and make the
/// search find each one. The kernel processes candidates UNROLL at a time in
/// groups of GRP vectors, two candidates to a register, so the interesting
/// positions are the group and lane boundaries - that is where an off-by-one in
/// the suspect range or the lane test would hide, and a hit that landed there
/// would otherwise be lost silently.
fn sweep_positions() -> bool {
    // Shape: byte 0 unreached, bytes 1..3 low-2 free => a 16384-candidate inner
    // block, times 64 anchor values = 2^20, searched in milliseconds.
    let base = aes::from_hex16("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let anchor = 5usize;
    let n_inner = 256 * 4 * 4 * 4;

    let mut positions: Vec<usize> = Vec::new();
    for e in [0usize, 1, 2, 3, 7, 8, 9, 15, 16, 17] {
        positions.push(e);
        positions.push(n_inner - 1 - e);
    }
    // Group boundaries: GRP vectors = 2*GRP candidates.
    let grp = 2 * kernel::GRP;
    for m in [1usize, 2, 3, 170] {
        for d in [-1i64, 0, 1] {
            let i = (m * grp) as i64 + d;
            if i >= 0 && (i as usize) < n_inner {
                positions.push(i as usize);
            }
        }
    }
    let mut rng = Rng(0x9e3779b97f4a7c15);
    for _ in 0..24 {
        positions.push(rng.below(n_inner as u64) as usize);
    }
    positions.sort();
    positions.dedup();

    let mut ok = true;
    for &pos in &positions {
        // Free bits for this inner index: byte0 = 8 bits, bytes 1..3 = 2 each.
        let mut key = base;
        key[0] = (pos & 0xff) as u8;
        key[1] = (key[1] & !3) | ((pos >> 8) & 3) as u8;
        key[2] = (key[2] & !3) | ((pos >> 10) & 3) as u8;
        key[3] = (key[3] & !3) | ((pos >> 12) & 3) as u8;

        let top6 = key[anchor] >> 2;
        let mut diff6 = [None; 16];
        for i in 1..16 {
            diff6[i] = Some((key[i] >> 2) ^ top6);
        }
        let mut known_low2 = [0u8; 16];
        for i in 0..16 {
            known_low2[i] = key[i] & 3;
        }
        let mut digits = vec![problem::Digit { byte: 0, radix: 256 }];
        for b in 1..4usize {
            digits.push(problem::Digit { byte: b, radix: 4 });
        }
        let oracle = vec![
            ([0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0, 0, 1], [0u8; 16]),
        ];
        let mut p = Problem {
            name: format!("sweep-{}", pos),
            anchor,
            diff6,
            known_low2,
            digits,
            oracle,
            answer: Some(key),
            declared_bits: None,
            pad: 0,
            inputs: [0u8; 16],
            lines: None,
        };
        p.oracle[0].1 = aes::encrypt_block(&key, &p.oracle[0].0);

        let out = search::run(&p, 1, &[], true);
        if !out.hits.contains(&key) || out.hits.len() != 1 {
            println!(
                "[FAIL] position sweep: inner index {} -> {} hit(s), wanted exactly {}",
                pos,
                out.hits.len(),
                aes::hex16(&key)
            );
            ok = false;
        }
    }
    if ok {
        println!(
            "[ok] answer planted at {} inner positions (group/lane boundaries and random), found at every one",
            positions.len()
        );
    }
    ok
}

// ---------------------------------------------------------------------------
// The same two questions asked of the GPU: does its AES agree with the reference
// one, and does the real search find a planted answer wherever it is put?
//
// The device's AES is checked on its own before any searching, because the search
// kernel's compare is exact: if the device's AES were wrong, a correct key would
// simply never match and the run would report a clean zero hits. That is the
// failure this test exists to make loud.
// ---------------------------------------------------------------------------
fn gpu_selftest(g: &mut gpu::Gpu) -> bool {
    let mut ok = true;

    // --- 1. known answers through the device's own AES ----------------------
    let mut keys = vec![
        aes::from_hex16("000102030405060708090a0b0c0d0e0f").unwrap(),
        aes::from_hex16("2b7e151628aed2a6abf7158809cf4f3c").unwrap(),
        [0u8; 16],
        [0xffu8; 16],
    ];
    let mut pts = vec![
        aes::from_hex16("00112233445566778899aabbccddeeff").unwrap(),
        aes::from_hex16("6bc1bee22e409f96e93d7e117393172a").unwrap(),
        [0u8; 16],
        [0xffu8; 16],
    ];
    let mut rng = Rng(0x2545f4914f6cdd1d);
    for _ in 0..508 {
        let mut k = [0u8; 16];
        let mut p = [0u8; 16];
        for i in 0..16 {
            k[i] = rng.next() as u8;
            p[i] = rng.next() as u8;
        }
        keys.push(k);
        pts.push(p);
    }
    match g.encrypt_blocks(&keys, &pts) {
        Ok(out) => {
            let mut bad = 0;
            for i in 0..keys.len() {
                let want = aes::encrypt_block(&keys[i], &pts[i]);
                if out[i] != want {
                    if bad < 3 {
                        println!(
                            "[FAIL] gpu AES: key {} pt {} -> {} want {}",
                            aes::hex16(&keys[i]),
                            aes::hex16(&pts[i]),
                            aes::hex16(&out[i]),
                            aes::hex16(&want)
                        );
                    }
                    bad += 1;
                }
            }
            if bad == 0 {
                println!(
                    "[ok] gpu AES agrees with the reference on {} blocks (FIPS-197 C.1 first)",
                    keys.len()
                );
            } else {
                println!("[FAIL] gpu AES disagrees on {} of {} blocks", bad, keys.len());
                ok = false;
            }
        }
        Err(e) => {
            println!("[FAIL] gpu AES known-answer test could not run: {}", e);
            return false;
        }
    }

    // --- 2. a planted answer, found on the GPU alone -------------------------
    // The real-2^50 shape: two unreached bytes, so the case the brief calls the
    // expected one is the case that gets tested.
    let base = aes::from_hex16("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let anchor = 5usize;
    let n_inner = 256 * 4 * 4 * 4;
    let mut positions: Vec<usize> = vec![0, 1, 2, n_inner - 2, n_inner - 1, n_inner / 2];
    for _ in 0..6 {
        positions.push(rng.below(n_inner as u64) as usize);
    }
    positions.sort();
    positions.dedup();

    for &pos in &positions {
        let mut key = base;
        key[0] = (pos & 0xff) as u8;
        key[1] = (key[1] & !3) | ((pos >> 8) & 3) as u8;
        key[2] = (key[2] & !3) | ((pos >> 10) & 3) as u8;
        key[3] = (key[3] & !3) | ((pos >> 12) & 3) as u8;

        let top6 = key[anchor] >> 2;
        let mut diff6 = [None; 16];
        for i in 1..15 {
            diff6[i] = Some((key[i] >> 2) ^ top6);
        }
        // bytes 0 and 15 unreached
        let mut known_low2 = [0u8; 16];
        for i in 0..16 {
            known_low2[i] = key[i] & 3;
        }
        let mut digits = vec![problem::Digit { byte: 0, radix: 256 }];
        for b in 1..4usize {
            digits.push(problem::Digit { byte: b, radix: 4 });
        }
        digits.push(problem::Digit { byte: 15, radix: 256 });

        let cb = [0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0, 0, 1];
        let p = Problem {
            name: format!("gpu-sweep-{}", pos),
            anchor,
            diff6,
            known_low2,
            digits,
            oracle: vec![(cb, aes::encrypt_block(&key, &cb))],
            answer: Some(key),
            declared_bits: None,
            pad: 0,
            inputs: [0u8; 16],
            lines: None,
        };

        let mut cfg = search::RunCfg {
            threads: 0,
            cpus: Vec::new(),
            quiet: true,
            gpu: vec![g],
            gpu_batch: 1 << 30,
            checkpoint: None,
            resume: false,
        };
        let out = search::run_cfg(&p, &mut cfg);
        if out.aborted.is_some() || out.gpu_false_hits > 0 {
            println!(
                "[FAIL] gpu planted-hit at inner {}: {:?} ({} false hit(s))",
                pos, out.aborted, out.gpu_false_hits
            );
            ok = false;
        } else if out.hits.len() != 1 || out.hits[0] != key {
            println!(
                "[FAIL] gpu planted-hit at inner {} -> {} hit(s), wanted exactly {}",
                pos,
                out.hits.len(),
                aes::hex16(&key)
            );
            ok = false;
        } else if out.gpu_candidates == 0 {
            println!("[FAIL] gpu planted-hit at inner {} was answered by the CPU, not the GPU", pos);
            ok = false;
        }
    }
    if ok {
        println!(
            "[ok] answer planted at {} inner positions and found by the GPU alone, \
             with byte 0 and byte 15 both unreached",
            positions.len()
        );
    }
    ok
}

fn selftest() -> bool {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x243f6a8885a308d3)
        | 1;
    let mut rng = Rng(seed);
    let mut ok = true;

    for trial in 0..12 {
        let mut key = [0u8; 16];
        for b in key.iter_mut() {
            *b = rng.next() as u8;
        }
        let anchor = rng.below(16) as usize;

        // A random shape of the declared size: one or two unreached bytes and a
        // handful of unknown low-2 pairs, kept small enough to search instantly.
        let n_unreached = 1 + rng.below(2) as usize;
        let mut unreached: Vec<usize> = Vec::new();
        while unreached.len() < n_unreached {
            let b = rng.below(16) as usize;
            if b != anchor && !unreached.contains(&b) {
                unreached.push(b);
            }
        }
        let n_low2 = rng.below(4) as usize; // 0..3 pairs -> at most 2^(6+8*2+6)
        let mut low2: Vec<usize> = Vec::new();
        while low2.len() < n_low2 {
            let b = rng.below(16) as usize;
            if !unreached.contains(&b) && !low2.contains(&b) {
                low2.push(b);
            }
        }
        low2.sort();
        unreached.sort();

        let top6 = key[anchor] >> 2;
        let mut diff6 = [None; 16];
        for i in 0..16 {
            if !unreached.contains(&i) {
                diff6[i] = Some((key[i] >> 2) ^ top6);
            }
        }
        let mut known_low2 = [0u8; 16];
        for i in 0..16 {
            known_low2[i] = key[i] & 3;
        }

        let mut oracle = Vec::new();
        for n in 1..=2u8 {
            let mut cb = [0u8; 16];
            for (i, b) in cb.iter_mut().enumerate() {
                *b = (rng.next() as u8).wrapping_add(i as u8);
            }
            cb[15] = n;
            oracle.push((cb, aes::encrypt_block(&key, &cb)));
        }

        let mut digits = Vec::new();
        for b in 0..16usize {
            if unreached.contains(&b) {
                digits.push(problem::Digit { byte: b, radix: 256 });
            } else if low2.contains(&b) {
                digits.push(problem::Digit { byte: b, radix: 4 });
            }
        }

        let p = Problem {
            name: format!("selftest-{}", trial),
            anchor,
            diff6,
            known_low2,
            digits,
            oracle,
            answer: Some(key),
            declared_bits: None,
            pad: 0,
            inputs: [0u8; 16],
            lines: None,
        };

        let out = search::run(&p, 4, &[], true);
        let found = out.hits.contains(&key);
        if !found || out.hits.len() != 1 {
            println!(
                "[FAIL] selftest trial {}: key {} anchor {} unreached {:?} low2 {:?} -> {} hit(s)",
                trial,
                aes::hex16(&key),
                anchor,
                unreached,
                low2,
                out.hits.len()
            );
            ok = false;
        }
    }
    if ok {
        println!("[ok] 12 randomised kernel-vs-reference searches, one hit each");
    }
    ok
}
