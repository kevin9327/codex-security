use napi::bindgen_prelude::{BigInt, Buffer};
use napi_derive::napi;

#[napi(object)]
pub struct CopyStatMetadata {
    pub mode: u32,
    pub atime_ns: BigInt,
    pub mtime_ns: BigInt,
    pub flags: u32,
}

fn nanoseconds(value: BigInt) -> napi::Result<i128> {
    let (value, lossless) = value.get_i128();
    if !lossless {
        return Err(napi::Error::from_reason(
            "Timestamp does not fit in 128 bits",
        ));
    }
    Ok(value)
}

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::unix::path;
    use std::{ffi::CStr, fs, io, os::unix::ffi::OsStrExt, os::unix::fs::MetadataExt};

    // Darwin's symlink metadata functions are absent from libc's declarations.
    #[cfg(target_os = "macos")]
    extern "C" {
        fn lchmod(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int;
        fn lchflags(path: *const libc::c_char, flags: libc::c_uint) -> libc::c_int;
    }

    #[napi(object, use_nullable = true)]
    pub struct CopyStatReadResult {
        pub errno: i32,
        pub metadata: Option<CopyStatMetadata>,
    }

    #[napi(object, use_nullable = true)]
    pub struct CopyStatResult {
        pub errno: i32,
        pub path: Option<Buffer>,
    }

    fn last_errno() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap()
    }

    fn failure(errno: i32, path: &CStr) -> CopyStatResult {
        CopyStatResult {
            errno,
            path: Some(path.to_bytes().to_vec().into()),
        }
    }

    #[napi]
    pub fn read_copy_stat(
        source: Buffer,
        follow_symlinks: bool,
    ) -> napi::Result<CopyStatReadResult> {
        let source = path(source)?;
        let source = std::ffi::OsStr::from_bytes(source.to_bytes());
        let stat = if follow_symlinks {
            fs::metadata(source)
        } else {
            fs::symlink_metadata(source)
        };
        Ok(match stat {
            Err(error) => CopyStatReadResult {
                errno: error.raw_os_error().unwrap(),
                metadata: None,
            },
            Ok(stat) => {
                #[cfg(target_os = "macos")]
                let flags = std::os::macos::fs::MetadataExt::st_flags(&stat);
                #[cfg(not(target_os = "macos"))]
                let flags = 0;
                CopyStatReadResult {
                    errno: 0,
                    metadata: Some(CopyStatMetadata {
                        mode: stat.mode() & 0o7777,
                        atime_ns: (i128::from(stat.atime()) * 1_000_000_000
                            + i128::from(stat.atime_nsec()))
                        .into(),
                        mtime_ns: (i128::from(stat.mtime()) * 1_000_000_000
                            + i128::from(stat.mtime_nsec()))
                        .into(),
                        flags,
                    }),
                }
            }
        })
    }

    fn timespec(value: BigInt) -> napi::Result<libc::timespec> {
        let value = nanoseconds(value)?;
        Ok(libc::timespec {
            tv_sec: value
                .div_euclid(1_000_000_000)
                .try_into()
                .map_err(|_| napi::Error::from_reason("Timestamp does not fit in time_t"))?,
            tv_nsec: value.rem_euclid(1_000_000_000) as _,
        })
    }

    #[cfg(target_os = "linux")]
    fn xattr_buffer(
        initial: usize,
        maximum: usize,
        mut operation: impl FnMut(&mut [u8]) -> isize,
    ) -> Result<Vec<u8>, i32> {
        // CPython retries ERANGE once with Linux's maximum attribute size.
        for size in [initial, maximum] {
            let mut buffer = vec![0; size];
            let length = operation(&mut buffer);
            if length >= 0 {
                buffer.truncate(length as usize);
                return Ok(buffer);
            }
            let errno = last_errno();
            if errno != libc::ERANGE {
                return Err(errno);
            }
        }
        Err(libc::ERANGE)
    }

    #[cfg(target_os = "linux")]
    fn copy_xattrs(source: &CStr, destination: &CStr, follow: bool) -> Option<CopyStatResult> {
        // Linux UAPI XATTR_LIST_MAX and XATTR_SIZE_MAX are both 64 KiB.
        const XATTR_MAX: usize = 65_536;
        let names = xattr_buffer(256, XATTR_MAX, |buffer| unsafe {
            if follow {
                libc::listxattr(source.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len())
            } else {
                libc::llistxattr(source.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len())
            }
        });
        let names = match names {
            Ok(names) => names,
            Err(libc::ENOTSUP | libc::ENODATA | libc::EINVAL) => return None,
            Err(errno) => return Some(failure(errno, source)),
        };
        for name in names.split_inclusive(|byte| *byte == 0) {
            let name = CStr::from_bytes_with_nul(name).expect("listxattr returns terminated names");
            let value = xattr_buffer(128, XATTR_MAX, |buffer| unsafe {
                if follow {
                    libc::getxattr(
                        source.as_ptr(),
                        name.as_ptr(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                } else {
                    libc::lgetxattr(
                        source.as_ptr(),
                        name.as_ptr(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                    )
                }
            });
            let result = value.map_err(|errno| (errno, source)).and_then(|value| {
                let result = unsafe {
                    if follow {
                        libc::setxattr(
                            destination.as_ptr(),
                            name.as_ptr(),
                            value.as_ptr().cast(),
                            value.len(),
                            0,
                        )
                    } else {
                        libc::lsetxattr(
                            destination.as_ptr(),
                            name.as_ptr(),
                            value.as_ptr().cast(),
                            value.len(),
                            0,
                        )
                    }
                };
                if result < 0 {
                    Err((last_errno(), destination))
                } else {
                    Ok(())
                }
            });
            match result {
                Ok(())
                | Err((
                    libc::EPERM | libc::ENOTSUP | libc::ENODATA | libc::EINVAL | libc::EACCES,
                    _,
                )) => {}
                Err((errno, path)) => return Some(failure(errno, path)),
            }
        }
        None
    }

    #[napi]
    pub fn copy_stat(
        source: Buffer,
        destination: Buffer,
        follow_symlinks: bool,
        metadata: CopyStatMetadata,
    ) -> napi::Result<CopyStatResult> {
        let source = path(source)?;
        let destination = path(destination)?;
        let times = [timespec(metadata.atime_ns)?, timespec(metadata.mtime_ns)?];
        let flags = if follow_symlinks {
            0
        } else {
            libc::AT_SYMLINK_NOFOLLOW
        };
        if unsafe { libc::utimensat(libc::AT_FDCWD, destination.as_ptr(), times.as_ptr(), flags) }
            < 0
        {
            // Python's utime omits the filename on a syscall failure.
            return Ok(CopyStatResult {
                errno: last_errno(),
                path: None,
            });
        }
        #[cfg(target_os = "linux")]
        if let Some(error) = copy_xattrs(&source, &destination, follow_symlinks) {
            return Ok(error);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = source;
        let mode = metadata.mode as libc::mode_t;
        let mut chmod_result = 0;
        if follow_symlinks {
            chmod_result = unsafe { libc::chmod(destination.as_ptr(), mode) };
        }
        #[cfg(target_os = "macos")]
        if !follow_symlinks {
            chmod_result = unsafe { lchmod(destination.as_ptr(), mode) };
        }
        if chmod_result < 0 {
            return Ok(failure(last_errno(), &destination));
        }
        #[cfg(target_os = "macos")]
        {
            let result = unsafe {
                if follow_symlinks {
                    libc::chflags(destination.as_ptr(), metadata.flags as _)
                } else {
                    lchflags(destination.as_ptr(), metadata.flags as _)
                }
            };
            if result < 0 {
                let errno = last_errno();
                if errno != libc::EOPNOTSUPP && errno != libc::ENOTSUP {
                    return Ok(failure(errno, &destination));
                }
            }
        }
        Ok(CopyStatResult {
            errno: 0,
            path: None,
        })
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::windows::wide_path;
    use std::{
        ffi::OsString,
        fs,
        mem::size_of,
        os::windows::{
            ffi::OsStringExt,
            fs::MetadataExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        ptr::{null, null_mut},
    };
    use windows_sys::Win32::{
        Foundation::{GetLastError, FILETIME, INVALID_HANDLE_VALUE},
        Storage::FileSystem::*,
    };

    const UNIX_EPOCH_TICKS: i128 = 116_444_736_000_000_000;

    #[napi(object, use_nullable = true)]
    pub struct CopyStatReadResult {
        pub error: u32,
        pub metadata: Option<CopyStatMetadata>,
    }

    #[napi(object, use_nullable = true)]
    pub struct CopyStatResult {
        pub error: u32,
        pub path: Option<Buffer>,
    }

    #[napi]
    pub fn read_copy_stat(
        source: Buffer,
        follow_symlinks: bool,
    ) -> napi::Result<CopyStatReadResult> {
        let wide = wide_path(source)?;
        let source = OsString::from_wide(&wide[..wide.len() - 1]);
        let stat = if follow_symlinks {
            fs::metadata(&source)
        } else {
            fs::symlink_metadata(&source)
        };
        Ok(match stat {
            Err(error) => CopyStatReadResult {
                error: error.raw_os_error().unwrap() as u32,
                metadata: None,
            },
            Ok(stat) => {
                let directory = stat.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0;
                let executable = wide[..wide.len() - 1]
                    .iter()
                    .rposition(|unit| *unit == u16::from(b'.'))
                    .map(|index| &wide[index + 1..wide.len() - 1])
                    .is_some_and(|extension| {
                        [b"exe", b"bat", b"cmd", b"com"].iter().any(|suffix| {
                            extension.len() == suffix.len()
                                && extension.iter().zip(suffix.iter()).all(|(unit, byte)| {
                                    *unit == u16::from(*byte)
                                        || *unit == u16::from(byte.to_ascii_uppercase())
                                })
                        })
                    });
                CopyStatReadResult {
                    error: 0,
                    metadata: Some(CopyStatMetadata {
                        mode: 0o444
                            | if stat.permissions().readonly() {
                                0
                            } else {
                                0o222
                            }
                            | if directory || executable { 0o111 } else { 0 },
                        atime_ns: ((i128::from(stat.last_access_time()) - UNIX_EPOCH_TICKS) * 100)
                            .into(),
                        mtime_ns: ((i128::from(stat.last_write_time()) - UNIX_EPOCH_TICKS) * 100)
                            .into(),
                        flags: 0,
                    }),
                }
            }
        })
    }

    fn filetime(value: BigInt) -> napi::Result<FILETIME> {
        let ticks: u64 = (nanoseconds(value)?.div_euclid(100) + UNIX_EPOCH_TICKS)
            .try_into()
            .map_err(|_| napi::Error::from_reason("Timestamp does not fit in FILETIME"))?;
        Ok(FILETIME {
            dwLowDateTime: ticks as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        })
    }

    #[napi]
    pub fn set_windows_times(
        destination: Buffer,
        atime_ns: BigInt,
        mtime_ns: BigInt,
    ) -> napi::Result<CopyStatResult> {
        let wide = wide_path(destination.to_vec().into())?;
        let atime = filetime(atime_ns)?;
        let mtime = filetime(mtime_ns)?;
        // Python 3.12 utime follows links, requests write-attributes access,
        // and does not share the handle. copystat skips utime for link metadata.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_WRITE_ATTRIBUTES,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Ok(CopyStatResult {
                error: unsafe { GetLastError() },
                path: Some(destination),
            });
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let error = if unsafe { SetFileTime(handle.as_raw_handle(), null(), &atime, &mtime) } == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        // Python deliberately omits the filename on a SetFileTime failure.
        Ok(CopyStatResult { error, path: None })
    }

    #[napi]
    pub fn copy_file2(source: Buffer, destination: Buffer, flags: u32) -> napi::Result<i32> {
        let source = wide_path(source)?;
        let destination = wide_path(destination)?;
        let parameters = COPYFILE2_EXTENDED_PARAMETERS {
            dwSize: size_of::<COPYFILE2_EXTENDED_PARAMETERS>() as u32,
            dwCopyFlags: flags,
            ..Default::default()
        };
        let result = unsafe { CopyFile2(source.as_ptr(), destination.as_ptr(), &parameters) };
        Ok(if result >= 0 {
            0
        } else if result as u32 & 0xffff0000 == 0x80070000 {
            result & 0xffff
        } else {
            result
        })
    }
}
