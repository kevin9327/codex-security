use crate::windows::wide_path;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use windows_sys::Win32::{Foundation::GetLastError, Storage::FileSystem::CreateSymbolicLinkW};

#[napi]
pub fn create_windows_symlink(
    target: Buffer,
    destination: Buffer,
    flags: u32,
) -> napi::Result<u32> {
    let target = wide_path(target)?;
    let destination = wide_path(destination)?;
    Ok(unsafe {
        if !CreateSymbolicLinkW(destination.as_ptr(), target.as_ptr(), flags) {
            GetLastError()
        } else {
            0
        }
    })
}

extern "C" {
    fn _wopen(path: *const u16, flags: i32, ...) -> i32;
    fn _read(fd: i32, buffer: *mut std::ffi::c_void, length: u32) -> i32;
    fn _write(fd: i32, buffer: *const std::ffi::c_void, length: u32) -> i32;
    fn _close(fd: i32) -> i32;
    fn _errno() -> *mut i32;
}

#[napi(object, use_nullable = true)]
pub struct CrtCopyResult {
    pub errno: i32,
    pub path: Option<Buffer>,
}

struct Descriptor(i32);

impl Descriptor {
    fn open(path: &[u16], flags: i32) -> Result<Self, i32> {
        loop {
            let fd = unsafe { _wopen(path.as_ptr(), flags, 0o666) };
            if fd >= 0 {
                return Ok(Self(fd));
            }
            let errno = unsafe { *_errno() };
            if errno != 4 {
                return Err(errno);
            }
        }
    }

    fn close(&mut self) -> i32 {
        let fd = std::mem::replace(&mut self.0, -1);
        if fd >= 0 && unsafe { _close(fd) } < 0 {
            unsafe { *_errno() }
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

fn copy_bytes(source: i32, destination: i32) -> i32 {
    // Match shutil's Windows copy buffer without retaining the whole file.
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = unsafe { _read(source, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if count < 0 {
            let errno = unsafe { *_errno() };
            if errno == 4 {
                continue;
            }
            return errno;
        }
        if count == 0 {
            return 0;
        }
        let mut offset = 0;
        while offset < count as usize {
            let written = unsafe {
                _write(
                    destination,
                    buffer[offset..].as_ptr().cast(),
                    count as u32 - offset as u32,
                )
            };
            if written < 0 {
                let errno = unsafe { *_errno() };
                if errno == 4 {
                    continue;
                }
                return errno;
            }
            offset += written as usize;
        }
    }
}

#[napi]
pub fn copy_file_crt(source: Buffer, destination: Buffer) -> napi::Result<CrtCopyResult> {
    let source_path = wide_path(source.to_vec().into())?;
    let destination_path = wide_path(destination.to_vec().into())?;
    const O_BINARY: i32 = 0x8000;
    const O_NOINHERIT: i32 = 0x0080;
    const O_WRONLY: i32 = 0x0001;
    const O_CREAT: i32 = 0x0100;
    const O_TRUNC: i32 = 0x0200;
    let mut source_fd = match Descriptor::open(&source_path, O_BINARY | O_NOINHERIT) {
        Ok(fd) => fd,
        Err(errno) => {
            return Ok(CrtCopyResult {
                errno,
                path: Some(source),
            });
        }
    };
    let mut result = match Descriptor::open(
        &destination_path,
        O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | O_NOINHERIT,
    ) {
        Ok(mut destination_fd) => {
            let errno = copy_bytes(source_fd.0, destination_fd.0);
            let close_errno = destination_fd.close();
            CrtCopyResult {
                errno: if close_errno != 0 { close_errno } else { errno },
                path: None,
            }
        }
        Err(errno) => CrtCopyResult {
            errno,
            path: Some(destination),
        },
    };
    // Nested FileIO context managers close the destination, then the source.
    // A close failure replaces the pending copy/open error without a filename.
    let close_errno = source_fd.close();
    if close_errno != 0 {
        result = CrtCopyResult {
            errno: close_errno,
            path: None,
        };
    }
    Ok(result)
}
