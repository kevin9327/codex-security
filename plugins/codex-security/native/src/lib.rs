mod copy_metadata;
mod errors;
mod process;
mod regex;
mod sqlite;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_completion_file;
#[cfg(windows)]
mod windows_copy;
#[cfg(windows)]
mod windows_crt;
#[cfg(windows)]
mod windows_exclusive_file;

#[napi_derive::napi]
pub fn wall_clock_microseconds() -> napi::bindgen_prelude::BigInt {
    use std::time::{SystemTime, UNIX_EPOCH};
    let micros = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_micros() as i128,
        Err(error) => -(error.duration().as_nanos().div_ceil(1000) as i128),
    };
    micros.into()
}
