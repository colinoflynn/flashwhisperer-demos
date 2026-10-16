// Just enough OpenCL to run one kernel, loaded at run time.
//
// Why dynamic loading rather than `#[link(name = "OpenCL")]`: there is no
// OpenCL.lib on this machine and no toolkit to get one from. `OpenCL.dll` is the
// Khronos ICD loader, which ships with the GPU driver, so `GetProcAddress` is the
// only binding available - and it is the one we want anyway, because a machine
// with no GPU then gives a clean "no OpenCL" instead of a link error at build
// time. `build.ps1` stays a single bare `rustc`.
//
// Nothing here is a general-purpose OpenCL crate. It is exactly the entry points
// gpu.rs uses and no others, with handles as opaque pointers and errors as the
// raw cl_int. Add one to the `entry_points!` list below when gpu.rs needs it.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::ffi::c_void;

pub type Handle = *mut c_void;
pub type Status = i32;

pub const SUCCESS: Status = 0;

// Device types.
pub const DEVICE_TYPE_GPU: u64 = 1 << 2;
pub const DEVICE_TYPE_ALL: u64 = 0xFFFF_FFFF;

// clGetDeviceInfo selectors.
pub const DEVICE_NAME: u32 = 0x102B;
pub const DEVICE_VENDOR: u32 = 0x102C;
pub const DEVICE_MAX_COMPUTE_UNITS: u32 = 0x1002;
pub const DEVICE_MAX_CLOCK_FREQUENCY: u32 = 0x100C;
pub const DEVICE_LOCAL_MEM_SIZE: u32 = 0x1023;
pub const DEVICE_MAX_WORK_GROUP_SIZE: u32 = 0x1004;
pub const DEVICE_GLOBAL_MEM_SIZE: u32 = 0x101F;
pub const PLATFORM_NAME: u32 = 0x0902;
pub const PROGRAM_BUILD_LOG: u32 = 0x1183;

// clCreateBuffer flags.
pub const MEM_READ_WRITE: u64 = 1 << 0;
pub const MEM_WRITE_ONLY: u64 = 1 << 1;
pub const MEM_READ_ONLY: u64 = 1 << 2;
pub const MEM_COPY_HOST_PTR: u64 = 1 << 5;

macro_rules! entry_points {
    ( $( $name:ident : $ty:ty ),* $(,)? ) => {
        pub struct Lib {
            _handle: Handle,
            $( pub $name: $ty, )*
        }
        impl Lib {
            unsafe fn bind(h: Handle) -> Result<Lib, String> {
                $(
                    let $name: $ty = {
                        let p = sym(h, concat!(stringify!($name), "\0").as_bytes());
                        if p.is_null() {
                            return Err(format!("OpenCL is present but has no {}", stringify!($name)));
                        }
                        std::mem::transmute(p)
                    };
                )*
                Ok(Lib { _handle: h, $( $name, )* })
            }
        }
    };
}

entry_points! {
    clGetPlatformIDs: unsafe extern "system" fn(u32, *mut Handle, *mut u32) -> Status,
    clGetPlatformInfo: unsafe extern "system" fn(Handle, u32, usize, *mut c_void, *mut usize) -> Status,
    clGetDeviceIDs: unsafe extern "system" fn(Handle, u64, u32, *mut Handle, *mut u32) -> Status,
    clGetDeviceInfo: unsafe extern "system" fn(Handle, u32, usize, *mut c_void, *mut usize) -> Status,
    clCreateContext: unsafe extern "system" fn(*const isize, u32, *const Handle, *mut c_void, *mut c_void, *mut Status) -> Handle,
    clCreateCommandQueue: unsafe extern "system" fn(Handle, Handle, u64, *mut Status) -> Handle,
    clCreateProgramWithSource: unsafe extern "system" fn(Handle, u32, *const *const u8, *const usize, *mut Status) -> Handle,
    clBuildProgram: unsafe extern "system" fn(Handle, u32, *const Handle, *const u8, *mut c_void, *mut c_void) -> Status,
    clGetProgramBuildInfo: unsafe extern "system" fn(Handle, Handle, u32, usize, *mut c_void, *mut usize) -> Status,
    clCreateKernel: unsafe extern "system" fn(Handle, *const u8, *mut Status) -> Handle,
    clCreateBuffer: unsafe extern "system" fn(Handle, u64, usize, *mut c_void, *mut Status) -> Handle,
    clSetKernelArg: unsafe extern "system" fn(Handle, u32, usize, *const c_void) -> Status,
    clEnqueueWriteBuffer: unsafe extern "system" fn(Handle, Handle, u32, usize, usize, *const c_void, u32, *const Handle, *mut Handle) -> Status,
    clEnqueueReadBuffer: unsafe extern "system" fn(Handle, Handle, u32, usize, usize, *mut c_void, u32, *const Handle, *mut Handle) -> Status,
    clEnqueueNDRangeKernel: unsafe extern "system" fn(Handle, Handle, u32, *const usize, *const usize, *const usize, u32, *const Handle, *mut Handle) -> Status,
    clFinish: unsafe extern "system" fn(Handle) -> Status,
    clReleaseMemObject: unsafe extern "system" fn(Handle) -> Status,
    clReleaseKernel: unsafe extern "system" fn(Handle) -> Status,
    clReleaseProgram: unsafe extern "system" fn(Handle) -> Status,
    clReleaseCommandQueue: unsafe extern "system" fn(Handle) -> Status,
    clReleaseContext: unsafe extern "system" fn(Handle) -> Status,
}

// --------------------------------------------------------------------------
// Platform glue: load the library and look up a symbol.
// --------------------------------------------------------------------------

#[cfg(windows)]
mod sys {
    use super::Handle;
    #[link(name = "kernel32")]
    extern "system" {
        pub fn LoadLibraryA(name: *const u8) -> Handle;
        pub fn GetProcAddress(h: Handle, name: *const u8) -> Handle;
    }
}

#[cfg(windows)]
const CANDIDATES: &[&str] = &["OpenCL.dll\0"];

#[cfg(windows)]
unsafe fn open(name: &str) -> Handle {
    sys::LoadLibraryA(name.as_ptr())
}

#[cfg(windows)]
unsafe fn sym(h: Handle, name: &[u8]) -> Handle {
    sys::GetProcAddress(h, name.as_ptr())
}

#[cfg(unix)]
mod sys {
    use super::Handle;
    #[link(name = "dl")]
    extern "C" {
        pub fn dlopen(name: *const u8, flags: i32) -> Handle;
        pub fn dlsym(h: Handle, name: *const u8) -> Handle;
    }
}

#[cfg(unix)]
const CANDIDATES: &[&str] = &["libOpenCL.so.1\0", "libOpenCL.so\0", "libOpenCL.dylib\0"];

#[cfg(unix)]
unsafe fn open(name: &str) -> Handle {
    sys::dlopen(name.as_ptr(), 2 /* RTLD_NOW */)
}

#[cfg(unix)]
unsafe fn sym(h: Handle, name: &[u8]) -> Handle {
    sys::dlsym(h, name.as_ptr())
}

pub fn load() -> Result<Lib, String> {
    unsafe {
        for name in CANDIDATES {
            let h = open(name);
            if !h.is_null() {
                return Lib::bind(h);
            }
        }
        Err(format!(
            "no OpenCL loader found (tried {})",
            CANDIDATES
                .iter()
                .map(|s| s.trim_end_matches('\0'))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// The handful of OpenCL error codes this program can actually provoke, so a
/// failure names itself instead of printing a bare negative number.
pub fn strerror(e: Status) -> String {
    let s = match e {
        0 => "SUCCESS",
        -1 => "DEVICE_NOT_FOUND",
        -2 => "DEVICE_NOT_AVAILABLE",
        -3 => "COMPILER_NOT_AVAILABLE",
        -4 => "MEM_OBJECT_ALLOCATION_FAILURE",
        -5 => "OUT_OF_RESOURCES",
        -6 => "OUT_OF_HOST_MEMORY",
        -11 => "BUILD_PROGRAM_FAILURE",
        -30 => "INVALID_VALUE",
        -33 => "INVALID_DEVICE",
        -34 => "INVALID_CONTEXT",
        -36 => "INVALID_COMMAND_QUEUE",
        -38 => "INVALID_MEM_OBJECT",
        -45 => "INVALID_PROGRAM_EXECUTABLE",
        -46 => "INVALID_KERNEL_NAME",
        -48 => "INVALID_KERNEL",
        -49 => "INVALID_ARG_INDEX",
        -50 => "INVALID_ARG_VALUE",
        -51 => "INVALID_ARG_SIZE",
        -52 => "INVALID_KERNEL_ARGS",
        -54 => "INVALID_WORK_GROUP_SIZE",
        -55 => "INVALID_WORK_ITEM_SIZE",
        -57 => "INVALID_EVENT_WAIT_LIST",
        -61 => "INVALID_BUFFER_SIZE",
        _ => "",
    };
    if s.is_empty() {
        format!("CL error {}", e)
    } else {
        format!("CL_{} ({})", s, e)
    }
}
