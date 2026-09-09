use crate::windows::wide_path;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

type InvalidParameterHandler =
    Option<unsafe extern "C" fn(*const u16, *const u16, *const u16, u32, usize)>;

extern "C" {
    fn _wopen(path: *const u16, flags: i32, ...) -> i32;
    fn _close(fd: i32) -> i32;
    fn _write(fd: i32, buffer: *const std::ffi::c_void, length: u32) -> i32;
    fn _read(fd: i32, buffer: *mut std::ffi::c_void, length: u32) -> i32;
    fn _isatty(fd: i32) -> i32;
    fn _errno() -> *mut i32;
    fn __doserrno() -> *mut u32;
    fn _set_thread_local_invalid_parameter_handler(
        handler: InvalidParameterHandler,
    ) -> InvalidParameterHandler;
}

unsafe extern "C" fn ignore_invalid_parameter(
    _expression: *const u16,
    _function: *const u16,
    _file: *const u16,
    _line: u32,
    _reserved: usize,
) {
}

// Match CPython's scoped CRT invalid-parameter suppression, including closed fds.
pub(super) struct SuppressInvalidParameters(InvalidParameterHandler);

impl SuppressInvalidParameters {
    pub(super) fn new() -> Self {
        Self(unsafe { _set_thread_local_invalid_parameter_handler(Some(ignore_invalid_parameter)) })
    }
}

impl Drop for SuppressInvalidParameters {
    fn drop(&mut self) {
        unsafe { _set_thread_local_invalid_parameter_handler(self.0) };
    }
}

pub(super) fn errno() -> i32 {
    unsafe { *_errno() }
}

#[napi(object)]
pub struct CrtWriteResult {
    pub errno: i32,
    pub value: i32,
}

pub(super) struct Descriptor(i32);

impl Descriptor {
    pub(super) fn open(path: &[u16], flags: i32, mode: i32) -> Result<Self, i32> {
        let _guard = SuppressInvalidParameters::new();
        loop {
            let descriptor = unsafe { _wopen(path.as_ptr(), flags, mode) };
            if descriptor >= 0 {
                return Ok(Self(descriptor));
            }
            let errno = errno();
            if errno != 4 {
                return Err(errno);
            }
        }
    }

    pub(super) fn raw(&self) -> i32 {
        self.0
    }

    pub(super) fn write(&self, buffer: &[u8]) -> CrtWriteResult {
        let _guard = SuppressInvalidParameters::new();
        // CPython _Py_write bounds a console write, then the signed CRT count.
        let count = if buffer.len() > 32767 && unsafe { _isatty(self.0) } != 0 {
            32767
        } else {
            buffer.len().min(i32::MAX as usize)
        };
        'retry: loop {
            unsafe { *_errno() = 0 };
            let mut length = count as u32;
            loop {
                unsafe { *__doserrno() = 0 };
                let value = unsafe { _write(self.0, buffer.as_ptr().cast(), length) };
                let mut errno = if value < 0 { errno() } else { 0 };
                if errno == 28 && unsafe { *__doserrno() } == 0 {
                    // Full nonblocking pipes may accept a shorter write.
                    errno = 11;
                    unsafe { *_errno() = errno };
                    length /= 2;
                    if length > 0 {
                        continue;
                    }
                }
                if errno == 4 {
                    continue 'retry;
                }
                return CrtWriteResult { errno, value };
            }
        }
    }

    pub(super) fn close(&mut self) -> i32 {
        let descriptor = std::mem::replace(&mut self.0, -1);
        if descriptor < 0 {
            return 0;
        }
        let _guard = SuppressInvalidParameters::new();
        if unsafe { _close(descriptor) } < 0 {
            errno()
        } else {
            0
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        self.close();
    }
}

#[napi(object)]
pub struct CrtReadCount {
    pub errno: i32,
    pub value: i32,
}

#[napi]
pub struct WindowsReadFile {
    descriptor: Descriptor,
}

#[napi(object, object_from_js = false, use_nullable = true)]
pub struct ReadFileOpenResult {
    pub errno: i32,
    pub file: Option<WindowsReadFile>,
}

#[napi]
pub fn open_windows_read_file(path: Buffer) -> napi::Result<ReadFileOpenResult> {
    let path = wide_path(path)?;
    const O_BINARY: i32 = 0x8000;
    const O_NOINHERIT: i32 = 0x0080;
    Ok(match Descriptor::open(&path, O_BINARY | O_NOINHERIT, 0) {
        Ok(descriptor) => ReadFileOpenResult {
            errno: 0,
            file: Some(WindowsReadFile { descriptor }),
        },
        Err(errno) => ReadFileOpenResult { errno, file: None },
    })
}

#[napi]
impl WindowsReadFile {
    #[napi]
    pub fn read(&self, mut buffer: Buffer) -> CrtReadCount {
        let _guard = SuppressInvalidParameters::new();
        let count = buffer.len().min(i32::MAX as usize) as u32;
        loop {
            unsafe {
                *_errno() = 0;
                *__doserrno() = 0;
            }
            let value = unsafe { _read(self.descriptor.raw(), buffer.as_mut_ptr().cast(), count) };
            let mut errno = if value < 0 { errno() } else { 0 };
            // _Py_read reports a nonblocking empty pipe as EAGAIN.
            if errno == 22 && unsafe { *__doserrno() } == 232 {
                errno = 11;
            }
            if errno != 4 {
                return CrtReadCount { errno, value };
            }
        }
    }

    #[napi]
    pub fn close(&mut self) -> i32 {
        self.descriptor.close()
    }
}
