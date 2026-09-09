use crate::windows::{wide_path, PositionResult};
use crate::windows_crt::{errno, CrtWriteResult, Descriptor, SuppressInvalidParameters};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::mem::{size_of, MaybeUninit};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError, ERROR_INVALID_HANDLE, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::*,
};

extern "C" {
    fn _lseeki64(fd: i32, offset: i64, origin: i32) -> i64;
    fn _locking(fd: i32, mode: i32, bytes: i32) -> i32;
    fn _get_osfhandle(fd: i32) -> isize;
}

#[napi]
pub struct WindowsCompletionFile {
    descriptor: Descriptor,
}

#[napi(object, object_from_js = false, use_nullable = true)]
pub struct CompletionFileOpenResult {
    pub errno: i32,
    pub file: Option<WindowsCompletionFile>,
}

#[napi]
pub fn open_windows_completion_file(path: Buffer) -> napi::Result<CompletionFileOpenResult> {
    let path = wide_path(path)?;
    const O_RDWR: i32 = 0x0002;
    const O_CREAT: i32 = 0x0100;
    const O_BINARY: i32 = 0x8000;
    const O_NOINHERIT: i32 = 0x0080;
    Ok(
        match Descriptor::open(&path, O_RDWR | O_CREAT | O_BINARY | O_NOINHERIT, 0o600) {
            Ok(descriptor) => CompletionFileOpenResult {
                errno: 0,
                file: Some(WindowsCompletionFile { descriptor }),
            },
            Err(errno) => CompletionFileOpenResult { errno, file: None },
        },
    )
}

#[napi]
impl WindowsCompletionFile {
    #[napi]
    pub fn size(&self) -> PositionResult {
        let handle = {
            let _guard = SuppressInvalidParameters::new();
            unsafe { _get_osfhandle(self.descriptor.raw()) as HANDLE }
        };
        let failure = |error| PositionResult {
            error,
            value: "0".into(),
        };
        if handle == INVALID_HANDLE_VALUE {
            unsafe { SetLastError(ERROR_INVALID_HANDLE) };
            return failure(ERROR_INVALID_HANDLE);
        }
        let kind = unsafe { GetFileType(handle) };
        if kind == FILE_TYPE_UNKNOWN {
            let error = unsafe { GetLastError() };
            if error != 0 {
                return failure(error);
            }
        }
        if kind != FILE_TYPE_DISK {
            return failure(0);
        }
        // Python fstat requires both queries even when only st_size is requested.
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        let mut basic = FILE_BASIC_INFO::default();
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0
            || unsafe {
                GetFileInformationByHandleEx(
                    handle,
                    FileBasicInfo,
                    (&mut basic as *mut FILE_BASIC_INFO).cast(),
                    size_of::<FILE_BASIC_INFO>() as u32,
                )
            } == 0
        {
            return failure(unsafe { GetLastError() });
        }
        let mut id = MaybeUninit::<FILE_ID_INFO>::uninit();
        // A filesystem without FileIdInfo still yields a successful fstat.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                id.as_mut_ptr().cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        PositionResult {
            error: 0,
            value: (((u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow)) as i64)
                .to_string(),
        }
    }

    #[napi]
    pub fn seek_start(&self) -> i32 {
        let _guard = SuppressInvalidParameters::new();
        if unsafe { _lseeki64(self.descriptor.raw(), 0, 0) } < 0 {
            errno()
        } else {
            0
        }
    }

    #[napi]
    pub fn write_zero(&self) -> CrtWriteResult {
        self.descriptor.write(&[0_u8])
    }

    #[napi]
    pub fn locking(&self, unlock: bool) -> i32 {
        let _guard = SuppressInvalidParameters::new();
        const LK_UNLCK: i32 = 0;
        const LK_NBLCK: i32 = 2;
        if unsafe {
            _locking(
                self.descriptor.raw(),
                if unlock { LK_UNLCK } else { LK_NBLCK },
                1,
            )
        } != 0
        {
            errno()
        } else {
            0
        }
    }

    #[napi]
    pub fn close(&mut self) -> i32 {
        self.descriptor.close()
    }
}
