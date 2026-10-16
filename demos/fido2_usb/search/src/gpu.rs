// The GPU backend: build aes_kernel.cl at run time, then turn batches of outer
// indices into hits.
//
// The kernel source is embedded in the binary, so the only external dependency is
// the ICD loader that comes with the GPU driver. There is no toolkit, no cargo and
// no network, same as the CPU path.
//
// Division of labour with the CPU
// ------------------------------
// Both pull chunks of the *outer* index range from one atomic cursor (see
// search.rs), so a fast device simply takes more chunks and the two load-balance
// without a schedule. The GPU takes much larger chunks - enough for roughly a
// quarter second of work - because each launch costs a host round trip.
//
// What the host still does per batch
// ----------------------------------
// It decodes each outer index into a `kbase` and uploads the batch. At the
// measured rate that is ~220k kbase computations per second against ~3.6e9
// candidates, so it is noise; it is not worth moving the odometer onto the device
// and it keeps the GPU reading exactly the bytes the CPU kernel would.

use crate::aes;
use crate::ocl::{self, Handle, Lib, Status};
use crate::problem::Problem;
use crate::search::{kbase_for, Plan};
use std::ffi::c_void;

const KERNEL_SRC: &str = include_str!("aes_kernel.cl");

/// Room for hits in one batch. A batch is ~1e9 candidates and a 128-bit match is
/// exact, so one is the expected count and 256 is a sanity cap, not a budget.
const HITS_CAP: u32 = 256;

/// A 16-byte kernel argument at the alignment OpenCL wants for a `uint4`. The
/// field is read only through a raw pointer handed to clSetKernelArg.
#[repr(align(16))]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct U4([u8; 16]);

#[derive(Clone, Copy)]
pub struct Options {
    /// log2 of the T0 replication factor; None picks the largest the device's
    /// local memory allows, up to 5.
    pub repl_sh: Option<u32>,
    /// work-group size; None picks 256.
    pub wg: Option<usize>,
    /// total work-items per launch; None picks 8 groups per compute unit.
    pub grid: Option<usize>,
    /// candidates per launch to aim for, which sets the batch size.
    pub batch_candidates: u64,
    /// pick this device index among the GPUs found.
    pub device: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            repl_sh: None,
            wg: None,
            grid: None,
            batch_candidates: 1 << 30,
            device: 0,
        }
    }
}

pub struct Gpu {
    lib: Lib,
    ctx: Handle,
    queue: Handle,
    prog: Handle,
    k_search: Handle,
    k_encrypt: Handle,
    b_t0: Handle,
    b_tab: Handle,
    b_kbase: Handle,
    b_hits: Handle,
    b_nhits: Handle,
    /// outer steps the kbase buffer can hold
    pub max_outer: usize,
    pub wg: usize,
    pub grid: usize,
    pub repl_sh: u32,
    pub name: String,
    pub compute_units: u32,
    pub clock_mhz: u32,
    pub local_mem: u64,
}

fn check(lib_err: Status, what: &str) -> Result<(), String> {
    if lib_err == ocl::SUCCESS {
        Ok(())
    } else {
        Err(format!("{}: {}", what, ocl::strerror(lib_err)))
    }
}

unsafe fn dev_str(lib: &Lib, dev: Handle, sel: u32) -> String {
    let mut n: usize = 0;
    (lib.clGetDeviceInfo)(dev, sel, 0, std::ptr::null_mut(), &mut n);
    let mut buf = vec![0u8; n];
    (lib.clGetDeviceInfo)(dev, sel, n, buf.as_mut_ptr() as *mut c_void, std::ptr::null_mut());
    while buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf8_lossy(&buf).to_string()
}

unsafe fn dev_u32(lib: &Lib, dev: Handle, sel: u32) -> u32 {
    let mut v: u32 = 0;
    (lib.clGetDeviceInfo)(dev, sel, 4, &mut v as *mut u32 as *mut c_void, std::ptr::null_mut());
    v
}

unsafe fn dev_u64(lib: &Lib, dev: Handle, sel: u32) -> u64 {
    let mut v: u64 = 0;
    (lib.clGetDeviceInfo)(dev, sel, 8, &mut v as *mut u64 as *mut c_void, std::ptr::null_mut());
    v
}

/// How many GPUs the ICD loader can see, across all platforms, in the order
/// `Gpu::new` indexes them. Used by `--gpu-device all`.
pub fn device_count() -> Result<usize, String> {
    let lib = ocl::load()?;
    unsafe {
        let mut nplat: u32 = 0;
        if (lib.clGetPlatformIDs)(0, std::ptr::null_mut(), &mut nplat) != ocl::SUCCESS || nplat == 0 {
            return Ok(0);
        }
        let mut plats = vec![std::ptr::null_mut(); nplat as usize];
        (lib.clGetPlatformIDs)(nplat, plats.as_mut_ptr(), std::ptr::null_mut());
        let mut n = 0usize;
        for &p in &plats {
            let mut nd: u32 = 0;
            if (lib.clGetDeviceIDs)(p, ocl::DEVICE_TYPE_GPU, 0, std::ptr::null_mut(), &mut nd)
                == ocl::SUCCESS
            {
                n += nd as usize;
            }
        }
        Ok(n)
    }
}

/// The T0 table the kernel indexes: T0[x] = [2S(x), S(x), S(x), 3S(x)] packed
/// little-endian. Built from the same S-box the reference AES uses, so the two
/// cannot drift apart.
fn t0_table() -> Vec<u32> {
    (0..256u32)
        .map(|x| {
            let s = aes::SBOX[x as usize] as u32;
            let s2 = aes::xtime(s as u8) as u32;
            s2 | (s << 8) | (s << 16) | ((s2 ^ s) << 24)
        })
        .collect()
}

impl Gpu {
    pub fn new(opts: &Options) -> Result<Gpu, String> {
        let lib = ocl::load()?;
        unsafe {
            // --- platform and device -------------------------------------------
            let mut nplat: u32 = 0;
            check((lib.clGetPlatformIDs)(0, std::ptr::null_mut(), &mut nplat), "clGetPlatformIDs")?;
            if nplat == 0 {
                return Err("OpenCL loaded but reports no platforms".into());
            }
            let mut plats = vec![std::ptr::null_mut(); nplat as usize];
            check((lib.clGetPlatformIDs)(nplat, plats.as_mut_ptr(), std::ptr::null_mut()), "clGetPlatformIDs")?;

            let mut found: Vec<(Handle, Handle)> = Vec::new();
            for &p in &plats {
                let mut nd: u32 = 0;
                if (lib.clGetDeviceIDs)(p, ocl::DEVICE_TYPE_GPU, 0, std::ptr::null_mut(), &mut nd)
                    != ocl::SUCCESS
                    || nd == 0
                {
                    continue;
                }
                let mut ds = vec![std::ptr::null_mut(); nd as usize];
                (lib.clGetDeviceIDs)(p, ocl::DEVICE_TYPE_GPU, nd, ds.as_mut_ptr(), std::ptr::null_mut());
                for d in ds {
                    found.push((p, d));
                }
            }
            if found.is_empty() {
                return Err("OpenCL found no GPU device".into());
            }
            if opts.device >= found.len() {
                return Err(format!(
                    "--gpu-device {} out of range: {} GPU device(s) found",
                    opts.device,
                    found.len()
                ));
            }
            let (_plat, dev) = found[opts.device];

            let name = dev_str(&lib, dev, ocl::DEVICE_NAME);
            let compute_units = dev_u32(&lib, dev, ocl::DEVICE_MAX_COMPUTE_UNITS);
            let clock_mhz = dev_u32(&lib, dev, ocl::DEVICE_MAX_CLOCK_FREQUENCY);
            let local_mem = dev_u64(&lib, dev, ocl::DEVICE_LOCAL_MEM_SIZE);
            let max_wg = {
                let mut v: usize = 0;
                (lib.clGetDeviceInfo)(
                    dev,
                    ocl::DEVICE_MAX_WORK_GROUP_SIZE,
                    std::mem::size_of::<usize>(),
                    &mut v as *mut usize as *mut c_void,
                    std::ptr::null_mut(),
                );
                v
            };

            // The replicated T0 needs 256 * 2^repl_sh * 4 bytes of local memory.
            // 32 copies (32 KB) is conflict-free and measured fastest; fall back
            // only if the device cannot hold it.
            let repl_sh = match opts.repl_sh {
                Some(s) => {
                    if s > 8 {
                        return Err(format!("--gpu-repl-sh {} must be 0..8", s));
                    }
                    s
                }
                None => {
                    let mut s = 5u32;
                    while s > 0 && (256u64 << s) * 4 > local_mem {
                        s -= 1;
                    }
                    s
                }
            };
            let need = (256u64 << repl_sh) * 4;
            if need > local_mem {
                return Err(format!(
                    "device has {} bytes of local memory, the table needs {}",
                    local_mem, need
                ));
            }

            let wg = opts.wg.unwrap_or(256).min(max_wg.max(1));
            let grid = opts.grid.unwrap_or(compute_units as usize * 8 * wg);
            let grid = (grid / wg).max(1) * wg; // a whole number of work-groups

            // --- context and queue ---------------------------------------------
            let mut err: Status = 0;
            let devs = [dev];
            let ctx = (lib.clCreateContext)(
                std::ptr::null(),
                1,
                devs.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut err,
            );
            check(err, "clCreateContext")?;
            let queue = (lib.clCreateCommandQueue)(ctx, dev, 0, &mut err);
            check(err, "clCreateCommandQueue")?;

            // --- build ----------------------------------------------------------
            let src = KERNEL_SRC.as_bytes();
            let srcs = [src.as_ptr()];
            let lens = [src.len()];
            let prog = (lib.clCreateProgramWithSource)(ctx, 1, srcs.as_ptr(), lens.as_ptr(), &mut err);
            check(err, "clCreateProgramWithSource")?;
            let opt = format!("-cl-std=CL1.2 -DREPL_SH={}\0", repl_sh);
            let rc = (lib.clBuildProgram)(
                prog,
                1,
                devs.as_ptr(),
                opt.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if rc != ocl::SUCCESS {
                let mut n: usize = 0;
                (lib.clGetProgramBuildInfo)(prog, dev, ocl::PROGRAM_BUILD_LOG, 0, std::ptr::null_mut(), &mut n);
                let mut log = vec![0u8; n];
                (lib.clGetProgramBuildInfo)(
                    prog,
                    dev,
                    ocl::PROGRAM_BUILD_LOG,
                    n,
                    log.as_mut_ptr() as *mut c_void,
                    std::ptr::null_mut(),
                );
                return Err(format!(
                    "clBuildProgram: {}\n--- build log ---\n{}",
                    ocl::strerror(rc),
                    String::from_utf8_lossy(&log)
                ));
            }
            let k_search = (lib.clCreateKernel)(prog, b"search\0".as_ptr(), &mut err);
            check(err, "clCreateKernel(search)")?;
            let k_encrypt = (lib.clCreateKernel)(prog, b"encrypt_one\0".as_ptr(), &mut err);
            check(err, "clCreateKernel(encrypt_one)")?;

            // --- buffers ---------------------------------------------------------
            let t0 = t0_table();
            let b_t0 = (lib.clCreateBuffer)(
                ctx,
                ocl::MEM_READ_ONLY | ocl::MEM_COPY_HOST_PTR,
                t0.len() * 4,
                t0.as_ptr() as *mut c_void,
                &mut err,
            );
            check(err, "clCreateBuffer(t0)")?;

            let max_outer = 1usize << 16; // set properly in bind_problem
            let b_kbase = (lib.clCreateBuffer)(
                ctx,
                ocl::MEM_READ_ONLY,
                max_outer * 16,
                std::ptr::null_mut(),
                &mut err,
            );
            check(err, "clCreateBuffer(kbase)")?;
            let b_hits = (lib.clCreateBuffer)(
                ctx,
                ocl::MEM_READ_WRITE,
                HITS_CAP as usize * 8,
                std::ptr::null_mut(),
                &mut err,
            );
            check(err, "clCreateBuffer(hits)")?;
            let b_nhits =
                (lib.clCreateBuffer)(ctx, ocl::MEM_READ_WRITE, 4, std::ptr::null_mut(), &mut err);
            check(err, "clCreateBuffer(nhits)")?;

            Ok(Gpu {
                lib,
                ctx,
                queue,
                prog,
                k_search,
                k_encrypt,
                b_t0,
                b_tab: std::ptr::null_mut(),
                b_kbase,
                b_hits,
                b_nhits,
                max_outer,
                wg,
                grid,
                repl_sh,
                name,
                compute_units,
                clock_mhz,
                local_mem,
            })
        }
    }

    pub fn describe(&self) -> String {
        format!(
            "{} ({} CUs @ {} MHz, {} KB local, T0 x{} = {} KB, {} work-items in groups of {})",
            self.name,
            self.compute_units,
            self.clock_mhz,
            self.local_mem / 1024,
            1u32 << self.repl_sh,
            (256u64 << self.repl_sh) * 4 / 1024,
            self.grid,
            self.wg
        )
    }

    /// Upload the inner-block OR-mask table and size the kbase buffer for the
    /// batch this problem wants. Called once per problem.
    pub fn bind_problem(&mut self, tab16: &[u8], max_outer: usize) -> Result<(), String> {
        unsafe {
            let mut err: Status = 0;
            if !self.b_tab.is_null() {
                (self.lib.clReleaseMemObject)(self.b_tab);
            }
            self.b_tab = (self.lib.clCreateBuffer)(
                self.ctx,
                ocl::MEM_READ_ONLY | ocl::MEM_COPY_HOST_PTR,
                tab16.len(),
                tab16.as_ptr() as *mut c_void,
                &mut err,
            );
            check(err, "clCreateBuffer(tab)")?;

            if max_outer > self.max_outer {
                (self.lib.clReleaseMemObject)(self.b_kbase);
                self.b_kbase = (self.lib.clCreateBuffer)(
                    self.ctx,
                    ocl::MEM_READ_ONLY,
                    max_outer * 16,
                    std::ptr::null_mut(),
                    &mut err,
                );
                check(err, "clCreateBuffer(kbase)")?;
                self.max_outer = max_outer;
            }
            Ok(())
        }
    }

    /// AES-128 on the device, for the known-answer tests. Same macros and same
    /// table as the search kernel, so a bug in either shows up in both.
    pub fn encrypt_blocks(&self, keys: &[[u8; 16]], pts: &[[u8; 16]]) -> Result<Vec<[u8; 16]>, String> {
        assert_eq!(keys.len(), pts.len());
        let n = keys.len();
        if n == 0 {
            return Ok(Vec::new());
        }
        let flat = |v: &[[u8; 16]]| -> Vec<u8> { v.iter().flat_map(|k| k.iter().copied()).collect() };
        let (kf, pf) = (flat(keys), flat(pts));
        unsafe {
            let mut err: Status = 0;
            let bk = (self.lib.clCreateBuffer)(
                self.ctx,
                ocl::MEM_READ_ONLY | ocl::MEM_COPY_HOST_PTR,
                kf.len(),
                kf.as_ptr() as *mut c_void,
                &mut err,
            );
            check(err, "clCreateBuffer(keys)")?;
            let bp = (self.lib.clCreateBuffer)(
                self.ctx,
                ocl::MEM_READ_ONLY | ocl::MEM_COPY_HOST_PTR,
                pf.len(),
                pf.as_ptr() as *mut c_void,
                &mut err,
            );
            check(err, "clCreateBuffer(pts)")?;
            let bo = (self.lib.clCreateBuffer)(
                self.ctx,
                ocl::MEM_WRITE_ONLY,
                n * 16,
                std::ptr::null_mut(),
                &mut err,
            );
            check(err, "clCreateBuffer(out)")?;

            let setb = |i: u32, b: Handle| -> Status {
                (self.lib.clSetKernelArg)(
                    self.k_encrypt,
                    i,
                    std::mem::size_of::<Handle>(),
                    &b as *const Handle as *const c_void,
                )
            };
            check(setb(0, bk), "arg0")?;
            check(setb(1, bp), "arg1")?;
            check(setb(2, self.b_t0), "arg2")?;
            check(setb(3, bo), "arg3")?;
            let nn = n as u32;
            check(
                (self.lib.clSetKernelArg)(self.k_encrypt, 4, 4, &nn as *const u32 as *const c_void),
                "arg4",
            )?;

            let wg = self.wg.min(256);
            let g = ((n + wg - 1) / wg) * wg;
            check(
                (self.lib.clEnqueueNDRangeKernel)(
                    self.queue,
                    self.k_encrypt,
                    1,
                    std::ptr::null(),
                    &g,
                    &wg,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                ),
                "NDRange(encrypt_one)",
            )?;
            let mut out = vec![0u8; n * 16];
            check(
                (self.lib.clEnqueueReadBuffer)(
                    self.queue,
                    bo,
                    1,
                    0,
                    out.len(),
                    out.as_mut_ptr() as *mut c_void,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                ),
                "read(out)",
            )?;
            check((self.lib.clFinish)(self.queue), "clFinish")?;
            (self.lib.clReleaseMemObject)(bk);
            (self.lib.clReleaseMemObject)(bp);
            (self.lib.clReleaseMemObject)(bo);

            Ok(out
                .chunks_exact(16)
                .map(|c| {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(c);
                    a
                })
                .collect())
        }
    }

    /// Search one batch of outer steps. `kbases` is 16 bytes per outer step.
    /// Returns (outer index within the batch, inner index) for every exact match
    /// against the single oracle pair the kernel tests.
    pub fn search_batch(
        &self,
        kbases: &[u8],
        inner_log2: u32,
        pt: &[u8; 16],
        expect: &[u8; 16],
    ) -> Result<Vec<(u32, u32)>, String> {
        let n_outer = kbases.len() / 16;
        assert!(n_outer > 0 && n_outer <= self.max_outer);
        unsafe {
            check(
                (self.lib.clEnqueueWriteBuffer)(
                    self.queue,
                    self.b_kbase,
                    1,
                    0,
                    kbases.len(),
                    kbases.as_ptr() as *const c_void,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                ),
                "write(kbase)",
            )?;
            let zero: u32 = 0;
            check(
                (self.lib.clEnqueueWriteBuffer)(
                    self.queue,
                    self.b_nhits,
                    1,
                    0,
                    4,
                    &zero as *const u32 as *const c_void,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                ),
                "write(nhits)",
            )?;

            let setb = |i: u32, b: Handle| -> Status {
                (self.lib.clSetKernelArg)(
                    self.k_search,
                    i,
                    std::mem::size_of::<Handle>(),
                    &b as *const Handle as *const c_void,
                )
            };
            let setv = |i: u32, p: *const c_void, sz: usize| -> Status {
                (self.lib.clSetKernelArg)(self.k_search, i, sz, p)
            };
            check(setb(0, self.b_kbase), "arg0(kbase)")?;
            check(setb(1, self.b_tab), "arg1(tab)")?;
            check(setb(2, self.b_t0), "arg2(t0)")?;
            let no = n_outer as u32;
            check(setv(3, &no as *const u32 as *const c_void, 4), "arg3(n_outer)")?;
            check(setv(4, &inner_log2 as *const u32 as *const c_void, 4), "arg4(inner_log2)")?;
            let p4 = U4(*pt);
            let e4 = U4(*expect);
            check(setv(5, &p4 as *const U4 as *const c_void, 16), "arg5(pt)")?;
            check(setv(6, &e4 as *const U4 as *const c_void, 16), "arg6(expect)")?;
            check(setb(7, self.b_hits), "arg7(hits)")?;
            check(setb(8, self.b_nhits), "arg8(nhits)")?;
            check(setv(9, &HITS_CAP as *const u32 as *const c_void, 4), "arg9(cap)")?;

            check(
                (self.lib.clEnqueueNDRangeKernel)(
                    self.queue,
                    self.k_search,
                    1,
                    std::ptr::null(),
                    &self.grid,
                    &self.wg,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                ),
                "NDRange(search)",
            )?;

            let mut nh: u32 = 0;
            check(
                (self.lib.clEnqueueReadBuffer)(
                    self.queue,
                    self.b_nhits,
                    1,
                    0,
                    4,
                    &mut nh as *mut u32 as *mut c_void,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                ),
                "read(nhits)",
            )?;
            check((self.lib.clFinish)(self.queue), "clFinish")?;

            if nh == 0 {
                return Ok(Vec::new());
            }
            if nh > HITS_CAP {
                return Err(format!(
                    "the kernel reported {} hits in one batch but the buffer holds {} - \
                     refusing to report a truncated list",
                    nh, HITS_CAP
                ));
            }
            let mut raw = vec![0u8; nh as usize * 8];
            check(
                (self.lib.clEnqueueReadBuffer)(
                    self.queue,
                    self.b_hits,
                    1,
                    0,
                    raw.len(),
                    raw.as_mut_ptr() as *mut c_void,
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                ),
                "read(hits)",
            )?;
            Ok(raw
                .chunks_exact(8)
                .map(|c| {
                    (
                        u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                        u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                    )
                })
                .collect())
        }
    }
}

impl Drop for Gpu {
    fn drop(&mut self) {
        unsafe {
            for b in [self.b_nhits, self.b_hits, self.b_kbase, self.b_tab, self.b_t0] {
                if !b.is_null() {
                    (self.lib.clReleaseMemObject)(b);
                }
            }
            (self.lib.clReleaseKernel)(self.k_encrypt);
            (self.lib.clReleaseKernel)(self.k_search);
            (self.lib.clReleaseProgram)(self.prog);
            (self.lib.clReleaseCommandQueue)(self.queue);
            (self.lib.clReleaseContext)(self.ctx);
        }
    }
}

// The device handles are used only from the thread that owns the Gpu, but the
// search hands one to a worker thread, so it has to cross a thread boundary once.
unsafe impl Send for Gpu {}

/// Flatten the inner table into the bytes the kernel reads.
pub fn tab_bytes(pl: &Plan) -> Vec<u8> {
    let mut v = Vec::with_capacity(pl.n_inner * 16);
    for blk in pl.tab_for(0) {
        v.extend_from_slice(&blk.0[0..16]);
        v.extend_from_slice(&blk.0[16..32]);
    }
    v
}

/// Decode a range of outer indices into the kbase bytes for one batch.
pub fn kbase_batch(p: &Problem, pl: &Plan, start: u64, end: u64, out: &mut Vec<u8>) {
    out.clear();
    for o in start..end {
        let (_a, kb) = kbase_for(p, pl, o);
        out.extend_from_slice(&kb);
    }
}
