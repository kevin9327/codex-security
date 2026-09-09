use napi::bindgen_prelude::{Uint16Array, Uint32Array};
use napi_derive::napi;
use rustpython_sre_engine::{Request, State};
use rustpython_wtf8::Wtf8Buf;

/// Instructions come from the internal typed compiler, never from scan artifacts.
#[napi]
pub fn regex_full_match(instructions: Uint32Array, units: Uint16Array) -> bool {
    let instructions = instructions.to_vec();
    let value = Wtf8Buf::from_wide(&units);
    let request = Request::new(value.as_slice(), 0, usize::MAX, &instructions, true);
    State::default().py_match(&request)
}
