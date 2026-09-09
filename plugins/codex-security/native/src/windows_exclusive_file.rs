use crate::{
    windows::wide_path,
    windows_crt::{CrtWriteResult, Descriptor},
};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub struct WindowsExclusiveFile {
    descriptor: Descriptor,
}

#[napi(object, object_from_js = false, use_nullable = true)]
pub struct ExclusiveFileOpenResult {
    pub errno: i32,
    pub file: Option<WindowsExclusiveFile>,
}

#[napi]
pub fn open_windows_exclusive_file(
    path: Buffer,
    mode: u32,
    read_write: Option<bool>,
) -> napi::Result<ExclusiveFileOpenResult> {
    let path = wide_path(path)?;
    const O_WRONLY: i32 = 0x0001;
    const O_RDWR: i32 = 0x0002;
    const O_CREAT: i32 = 0x0100;
    const O_EXCL: i32 = 0x0400;
    const O_BINARY: i32 = 0x8000;
    const O_NOINHERIT: i32 = 0x0080;
    Ok(
        match Descriptor::open(
            &path,
            (if read_write.unwrap_or(false) {
                O_RDWR
            } else {
                O_WRONLY
            }) | O_CREAT
                | O_EXCL
                | O_BINARY
                | O_NOINHERIT,
            mode as i32,
        ) {
            Ok(descriptor) => ExclusiveFileOpenResult {
                errno: 0,
                file: Some(WindowsExclusiveFile { descriptor }),
            },
            Err(errno) => ExclusiveFileOpenResult { errno, file: None },
        },
    )
}

#[napi]
impl WindowsExclusiveFile {
    #[napi]
    pub fn write(&self, buffer: Buffer) -> CrtWriteResult {
        self.descriptor.write(&buffer)
    }

    #[napi]
    pub fn close(&mut self) -> i32 {
        self.descriptor.close()
    }
}
