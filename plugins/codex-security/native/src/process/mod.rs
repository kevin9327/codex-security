use napi::bindgen_prelude::{Buffer, Either, Null};
use napi_derive::napi;
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read, Write},
    thread,
};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

#[napi(object)]
pub struct EnvironmentEdit {
    pub name: Buffer,
    pub value: Either<Buffer, Null>,
}

#[napi(object)]
pub struct ProcessRequest {
    pub program: Buffer,
    pub args: Vec<Buffer>,
    pub cwd: Option<Either<Buffer, Null>>,
    pub input: Option<Either<Buffer, Null>>,
    pub stdout_path: Option<Either<Buffer, Null>>,
    pub environment: Option<Vec<EnvironmentEdit>>,
}

#[napi(object, use_nullable = true)]
pub struct ProcessResult {
    pub error: u32,
    pub return_code: Option<i64>,
    pub stdout: Buffer,
    pub stderr: Buffer,
}

struct Request {
    program: OsString,
    args: Vec<OsString>,
    cwd: Option<OsString>,
    input: Option<Vec<u8>>,
    environment: Vec<(OsString, Option<OsString>)>,
}

fn nullable(value: Either<Buffer, Null>) -> Option<Buffer> {
    match value {
        Either::A(value) => Some(value),
        Either::B(_) => None,
    }
}

fn invalid(message: &str) -> napi::Error {
    napi::Error::new(napi::Status::InvalidArg, message)
}

trait Child {
    fn wait(&mut self) -> io::Result<i64>;
    fn kill(&mut self);
}

struct Spawned {
    child: Box<dyn Child>,
    input: Option<File>,
    output: File,
    error: File,
}

struct Guard(Box<dyn Child>, bool);
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.1 {
            self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn read(mut pipe: File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join<T>(thread: thread::ScopedJoinHandle<'_, io::Result<T>>) -> io::Result<T> {
    thread
        .join()
        .map_err(|_| io::Error::other("Process pipe worker panicked"))?
}

fn communicate(
    spawned: Spawned,
    input: Option<Vec<u8>>,
    stdout_file: Option<File>,
) -> io::Result<(i64, Vec<u8>, Vec<u8>)> {
    thread::scope(|scope| {
        // Drop this guard before scope joins if a worker cannot be started.
        let mut child = Guard(spawned.child, false);
        let output = thread::Builder::new().spawn_scoped(scope, move || {
            let mut pipe = spawned.output;
            if let Some(mut file) = stdout_file {
                io::copy(&mut pipe, &mut file)?;
                Ok(Vec::new())
            } else {
                read(pipe)
            }
        })?;
        let error = thread::Builder::new().spawn_scoped(scope, move || read(spawned.error))?;
        let writer = match (spawned.input, input) {
            (Some(mut pipe), Some(bytes)) => {
                Some(thread::Builder::new().spawn_scoped(scope, move || {
                    match pipe.write_all(&bytes) {
                        // Python communicate ignores a child closing its input early.
                        Err(e)
                            if e.kind() == io::ErrorKind::BrokenPipe
                                || e.kind() == io::ErrorKind::InvalidInput =>
                        {
                            Ok(())
                        }
                        result => result,
                    }
                })?)
            }
            _ => None,
        };
        let code = child.0.wait()?;
        child.1 = true;
        if let Some(writer) = writer {
            join(writer)?;
        }
        Ok((code, join(output)?, join(error)?))
    })
}

/// OS strings are raw POSIX bytes or UTF-16LE code units. No shell is requested.
#[napi]
pub fn raw_process(request: ProcessRequest) -> napi::Result<ProcessResult> {
    let stdout_file = request
        .stdout_path
        .and_then(nullable)
        .as_deref()
        .map(platform::decode)
        .transpose()?
        .map(|path| File::options().write(true).truncate(true).open(path))
        .transpose()
        .map_err(|error| napi::Error::from_reason(error.to_string()))?;
    let request = Request {
        program: platform::decode(&request.program)?,
        args: request
            .args
            .iter()
            .map(|value| platform::decode(value))
            .collect::<napi::Result<_>>()?,
        cwd: request
            .cwd
            .and_then(nullable)
            .as_deref()
            .map(platform::decode)
            .transpose()?,
        input: request.input.and_then(nullable).map(|bytes| bytes.to_vec()),
        environment: request
            .environment
            .unwrap_or_default()
            .into_iter()
            .map(|edit| {
                let name = platform::decode(&edit.name)?;
                platform::validate_name(&name)?;
                Ok((
                    name,
                    nullable(edit.value)
                        .as_deref()
                        .map(platform::decode)
                        .transpose()?,
                ))
            })
            .collect::<napi::Result<_>>()?,
    };
    let spawned = match platform::spawn(&request) {
        Ok(child) => child,
        Err(error) => {
            return match error.raw_os_error() {
                Some(error) => Ok(ProcessResult {
                    error: error as u32,
                    return_code: None,
                    stdout: Vec::new().into(),
                    stderr: Vec::new().into(),
                }),
                None => Err(napi::Error::from_reason(error.to_string())),
            }
        }
    };
    let (code, stdout, stderr) = communicate(spawned, request.input, stdout_file)
        .map_err(|error| napi::Error::from_reason(error.to_string()))?;
    Ok(ProcessResult {
        error: 0,
        return_code: Some(code),
        stdout: stdout.into(),
        stderr: stderr.into(),
    })
}
