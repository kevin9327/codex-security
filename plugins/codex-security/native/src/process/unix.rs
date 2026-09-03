use super::{invalid, Child, Request, Spawned};
use std::{
    collections::BTreeMap,
    ffi::{CString, OsStr, OsString},
    fs::File,
    io,
    os::unix::ffi::{OsStrExt, OsStringExt},
    ptr,
};

pub(super) fn decode(bytes: &[u8]) -> napi::Result<OsString> {
    if bytes.contains(&0) {
        return Err(invalid("Process string contains a NUL byte"));
    }
    Ok(OsString::from_vec(bytes.to_vec()))
}

pub(super) fn validate_name(name: &OsStr) -> napi::Result<()> {
    if name.is_empty() || name.as_bytes().contains(&b'=') {
        return Err(invalid("Invalid environment name"));
    }
    Ok(())
}

struct Strings {
    _strings: Vec<CString>,
    pointers: Vec<*const libc::c_char>,
}
impl Strings {
    fn as_ptr(&self) -> *const *const libc::c_char {
        self.pointers.as_ptr()
    }

    fn new(values: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let strings: Vec<_> = values
            .into_iter()
            .map(|value| CString::new(value).unwrap())
            .collect();
        let mut pointers: Vec<_> = strings.iter().map(|value| value.as_ptr()).collect();
        pointers.push(ptr::null());
        Self {
            _strings: strings,
            pointers,
        }
    }
}
// The pointers refer to immutable CString allocations owned by this same value.
unsafe impl Send for Strings {}
unsafe impl Sync for Strings {}

pub(super) fn spawn(request: &Request) -> io::Result<Spawned> {
    let mut env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    for (key, value) in &request.environment {
        if let Some(value) = value {
            env.insert(key.clone(), value.clone());
        } else {
            env.remove(key);
        }
    }
    let program = request.program.as_bytes();
    let paths: Vec<_> = if program.contains(&b'/') {
        vec![CString::new(program).unwrap()]
    } else {
        env.get(OsStr::new("PATH"))
            .map_or(b"/bin:/usr/bin".as_slice(), |path| path.as_bytes())
            .split(|byte| *byte == b':')
            .map(|directory| {
                let mut path = directory.to_vec();
                if !path.is_empty() {
                    path.push(b'/');
                }
                path.extend_from_slice(program);
                CString::new(path).unwrap()
            })
            .collect()
    };
    let args = Strings::new(
        std::iter::once(&request.program)
            .chain(&request.args)
            .map(|arg| arg.as_bytes().to_vec()),
    );
    let env = Strings::new(env.into_iter().map(|(key, value)| {
        let mut entry = key.into_vec();
        entry.push(b'=');
        entry.extend(value.into_vec());
        entry
    }));
    spawn_platform(request, paths, args, env)
}

#[cfg(target_os = "linux")]
fn spawn_platform(
    request: &Request,
    paths: Vec<CString>,
    args: Strings,
    env: Strings,
) -> io::Result<Spawned> {
    use std::os::{
        fd::{FromRawFd, OwnedFd},
        unix::process::{CommandExt, ExitStatusExt},
    };
    use std::process::{Command, Stdio};
    struct Process(std::process::Child);
    impl Child for Process {
        fn wait(&mut self) -> io::Result<i64> {
            let status = self.0.wait()?;
            Ok(status
                .code()
                .map(i64::from)
                .unwrap_or_else(|| -i64::from(status.signal().unwrap())))
        }
        fn kill(&mut self) {
            let _ = self.0.kill();
        }
    }
    let mut command = Command::new(&request.program);
    let stdin = if request.input.is_some() {
        Stdio::piped()
    } else {
        // Node marks its stdio close-on-exec; duplicate the explicitly inherited input.
        let fd = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
        if fd >= 0 {
            Stdio::from(unsafe { File::from_raw_fd(fd) })
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
            Stdio::inherit()
        }
    };
    command
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &request.cwd {
        command.current_dir(cwd);
    }
    let maximum_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    unsafe {
        command.pre_exec(move || {
            // Keep Rust's exec-error pipe open on failure, but close every inherited fd at exec.
            close_on_exec(maximum_fd)?;
            for signal in [libc::SIGPIPE, libc::SIGXFSZ] {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(signal, &action, ptr::null_mut()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut saved = None;
            for path in &paths {
                // execvp would silently invoke a shell for ENOEXEC; Python tries execve only.
                libc::execve(path.as_ptr(), args.as_ptr(), env.as_ptr());
                let error = io::Error::last_os_error();
                if saved.is_none()
                    && !matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
                {
                    saved = Some(error);
                }
            }
            Err(saved.unwrap_or_else(io::Error::last_os_error))
        });
    }
    let mut child = command.spawn()?;
    let input = child
        .stdin
        .take()
        .map(|pipe| File::from(OwnedFd::from(pipe)));
    let output = File::from(OwnedFd::from(child.stdout.take().unwrap()));
    let error = File::from(OwnedFd::from(child.stderr.take().unwrap()));
    Ok(Spawned {
        child: Box::new(Process(child)),
        input,
        output,
        error,
    })
}

#[cfg(target_os = "linux")]
unsafe fn close_on_exec(maximum_fd: libc::c_long) -> io::Result<()> {
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) } == 0 {
        return Ok(());
    }
    // Older kernels: enumerate after fork, without allocating or using readdir's locks.
    let directory = unsafe {
        libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if directory >= 0 {
        let mut buffer = [0u8; 4096];
        loop {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    directory,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if count == 0 {
                unsafe {
                    libc::close(directory);
                }
                return Ok(());
            }
            if count < 0 {
                unsafe {
                    libc::close(directory);
                }
                break;
            }
            let mut offset = 0;
            while offset < count as usize {
                let length =
                    u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
                let mut fd = 0i32;
                for byte in &buffer[offset + 19..offset + length] {
                    if !byte.is_ascii_digit() {
                        break;
                    }
                    fd = fd * 10 + i32::from(*byte - b'0');
                }
                if fd >= 3 {
                    unsafe {
                        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                    }
                }
                offset += length;
            }
        }
    }
    // This is also Python's fallback when a descriptor directory is unavailable.
    for fd in 3..maximum_fd {
        unsafe {
            libc::fcntl(fd as i32, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn spawn_platform(
    request: &Request,
    paths: Vec<CString>,
    args: Strings,
    env: Strings,
) -> io::Result<Spawned> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // Public libSystem APIs available before the package's macOS 11 minimum.
    unsafe extern "C" {
        fn posix_spawn_file_actions_addchdir_np(
            actions: *mut libc::posix_spawn_file_actions_t,
            path: *const libc::c_char,
        ) -> libc::c_int;
        fn posix_spawn_file_actions_addinherit_np(
            actions: *mut libc::posix_spawn_file_actions_t,
            fd: libc::c_int,
        ) -> libc::c_int;
    }
    fn check(error: i32) -> io::Result<()> {
        if error == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(error))
        }
    }
    fn pipe() -> io::Result<(File, File)> {
        let mut descriptors = [0; 2];
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut files = Vec::new();
        for fd in descriptors {
            files.push(unsafe { File::from_raw_fd(fd) });
        }
        for file in &mut files {
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            *file = unsafe { File::from_raw_fd(fd) };
        }
        Ok((files.remove(0), files.remove(0)))
    }
    struct Actions(libc::posix_spawn_file_actions_t);
    impl Drop for Actions {
        fn drop(&mut self) {
            unsafe {
                libc::posix_spawn_file_actions_destroy(&mut self.0);
            }
        }
    }
    struct Attributes(libc::posix_spawnattr_t);
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe {
                libc::posix_spawnattr_destroy(&mut self.0);
            }
        }
    }
    struct Process(libc::pid_t);
    impl Child for Process {
        fn wait(&mut self) -> io::Result<i64> {
            let mut status = 0;
            loop {
                if unsafe { libc::waitpid(self.0, &mut status, 0) } >= 0 {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            Ok(if libc::WIFEXITED(status) {
                i64::from(libc::WEXITSTATUS(status))
            } else {
                -i64::from(libc::WTERMSIG(status))
            })
        }
        fn kill(&mut self) {
            unsafe {
                libc::kill(self.0, libc::SIGKILL);
            }
        }
    }
    let (output, child_output) = pipe()?;
    let (error, child_error) = pipe()?;
    let input = request.input.as_ref().map(|_| pipe()).transpose()?;
    let mut actions = std::mem::MaybeUninit::uninit();
    check(unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) })?;
    let mut actions = Actions(unsafe { actions.assume_init() });
    let mut attr = std::mem::MaybeUninit::uninit();
    check(unsafe { libc::posix_spawnattr_init(attr.as_mut_ptr()) })?;
    let mut attr = Attributes(unsafe { attr.assume_init() });
    for (file, destination) in [(&child_output, 1), (&child_error, 2)] {
        check(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut actions.0, file.as_raw_fd(), destination)
        })?;
    }
    if let Some((child_input, _)) = &input {
        check(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut actions.0, child_input.as_raw_fd(), 0)
        })?;
    } else {
        let flags = unsafe { libc::fcntl(0, libc::F_GETFD) };
        if flags >= 0 {
            check(unsafe { posix_spawn_file_actions_addinherit_np(&mut actions.0, 0) })?;
        }
    }
    let cwd = request
        .cwd
        .as_ref()
        .map(|cwd| CString::new(cwd.as_bytes()).unwrap());
    if let Some(cwd) = &cwd {
        check(unsafe { posix_spawn_file_actions_addchdir_np(&mut actions.0, cwd.as_ptr()) })?;
    }
    let mut signals = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut signals);
        libc::sigaddset(&mut signals, libc::SIGPIPE);
        libc::sigaddset(&mut signals, libc::SIGXFSZ);
    }
    check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attr.0, &signals) })?;
    check(unsafe {
        libc::posix_spawnattr_setflags(
            &mut attr.0,
            (libc::POSIX_SPAWN_CLOEXEC_DEFAULT | libc::POSIX_SPAWN_SETSIGDEF) as libc::c_short,
        )
    })?;
    let mut saved = None;
    let mut last = libc::ENOENT;
    for path in paths {
        let mut pid = 0;
        let status = unsafe {
            libc::posix_spawn(
                &mut pid,
                path.as_ptr(),
                &actions.0,
                &attr.0,
                args.as_ptr().cast_mut().cast(),
                env.as_ptr().cast_mut().cast(),
            )
        };
        if status == 0 {
            return Ok(Spawned {
                child: Box::new(Process(pid)),
                input: input.map(|(_, parent)| parent),
                output,
                error,
            });
        }
        if saved.is_none() && !matches!(status, libc::ENOENT | libc::ENOTDIR) {
            saved = Some(status);
        }
        last = status;
    }
    Err(io::Error::from_raw_os_error(saved.unwrap_or(last)))
}
