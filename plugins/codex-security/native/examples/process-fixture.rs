use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

#[cfg(unix)]
fn bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}
#[cfg(windows)]
fn bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().flat_map(u16::to_le_bytes).collect()
}
#[cfg(unix)]
fn raw(prefix: &str) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    let mut value = prefix.as_bytes().to_vec();
    value.extend(if cfg!(target_os = "macos") {
        "é".as_bytes()
    } else {
        &[0xff]
    });
    OsString::from_vec(value)
}
#[cfg(windows)]
fn raw(prefix: &str) -> OsString {
    use std::os::windows::ffi::OsStringExt;
    OsString::from_wide(&prefix.encode_utf16().chain([0xd800]).collect::<Vec<_>>())
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(unix)]
static SIGNALS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
extern "C" fn before_runtime() {
    let defaults = [libc::SIGPIPE, libc::SIGXFSZ]
        .into_iter()
        .all(|signal| unsafe {
            let mut action = std::mem::zeroed::<libc::sigaction>();
            libc::sigaction(signal, std::ptr::null(), &mut action) == 0
                && action.sa_sigaction == libc::SIG_DFL
        });
    SIGNALS.store(defaults, std::sync::atomic::Ordering::Relaxed);
}
#[cfg(unix)]
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INITIALIZER: extern "C" fn() = before_runtime;

#[cfg(target_os = "linux")]
unsafe fn disable_close_range() -> std::io::Result<()> {
    // Exercise the older-kernel path without changing the production binding.
    let mut filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_close_range as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn launch(args: &[OsString]) {
    let root = Path::new(&args[4]);
    let directory = root.join(raw("process-cwd-"));
    fs::create_dir(&directory).unwrap();
    let name = {
        let mut name = raw("process-exe-");
        if cfg!(windows) {
            name.push(".exe");
        }
        name
    };
    fs::copy(env::current_exe().unwrap(), directory.join(name)).unwrap();
    let sentinel = fs::File::create(root.join("inherited-descriptor")).unwrap();
    let mut node = Command::new(&args[2]);
    node.arg(&args[3])
        .arg("process-worker")
        .arg(root)
        .current_dir(&directory)
        .env(raw("PROCESS_RAW_"), raw("inherited-"))
        .env(raw("PROCESS_REMOVE_RAW_"), "present")
        .env("PROCESS_REMOVE", "present")
        .env("PROCESS_SET", "old")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        assert_eq!(unsafe { libc::dup2(sentinel.as_raw_fd(), 200) }, 200);
        assert_eq!(unsafe { libc::fcntl(200, libc::F_SETFD, 0) }, 0);
        node.arg("200");
        #[cfg(target_os = "linux")]
        let fallback = args.get(5).is_some_and(|arg| arg == "fallback");
        unsafe {
            node.pre_exec(move || {
                for signal in [libc::SIGPIPE, libc::SIGXFSZ] {
                    libc::signal(signal, libc::SIG_IGN);
                }
                #[cfg(target_os = "linux")]
                if fallback {
                    disable_close_range()?;
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        let handle = sentinel.as_raw_handle();
        assert_ne!(
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
        node.arg((handle as usize).to_string());
    }
    let status = node.status().unwrap();
    #[cfg(unix)]
    unsafe {
        libc::close(200);
    }
    drop(sentinel);
    fs::remove_dir_all(directory).unwrap();
    assert!(status.success(), "Node process proof failed: {status}");
}

fn main() {
    let args: Vec<_> = env::args_os().collect();
    match args.get(1).and_then(|arg| arg.to_str()) {
        Some("launch") => launch(&args),
        Some("check-inherited") => {
            #[cfg(windows)]
            unsafe {
                use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
                use windows_sys::Win32::{
                    Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS},
                    System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE},
                };
                let parent = OpenProcess(
                    PROCESS_DUP_HANDLE,
                    0,
                    args[2].to_str().unwrap().parse().unwrap(),
                );
                assert!(!parent.is_null());
                let parent = OwnedHandle::from_raw_handle(parent);
                let handle = args[3].to_str().unwrap().parse::<usize>().unwrap();
                let mut duplicate = std::ptr::null_mut();
                assert_ne!(
                    DuplicateHandle(
                        parent.as_raw_handle(),
                        handle as _,
                        GetCurrentProcess(),
                        &mut duplicate,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS
                    ),
                    0
                );
                drop(OwnedHandle::from_raw_handle(duplicate));
            }
            #[cfg(not(windows))]
            panic!("Windows-only fixture mode");
        }
        Some("inspect") => {
            println!(
                "cwd={}",
                hex(&bytes(env::current_dir().unwrap().as_os_str()))
            );
            for (index, value) in args.iter().skip(2).enumerate() {
                println!("arg{index}={}", hex(&bytes(value)));
            }
            for (label, name) in [
                ("inherited", raw("PROCESS_RAW_")),
                ("set", OsString::from("PROCESS_SET")),
                ("edited", raw("PROCESS_EDIT_")),
            ] {
                println!(
                    "{label}={}",
                    env::var_os(name)
                        .map(|value| hex(&bytes(&value)))
                        .unwrap_or_default()
                );
            }
            println!("removed={}", env::var_os("PROCESS_REMOVE").is_none());
            println!(
                "removedRaw={}",
                env::var_os(raw("PROCESS_REMOVE_RAW_")).is_none()
            );
            let descriptor = args[2].to_str().unwrap().parse::<usize>().unwrap();
            #[cfg(unix)]
            {
                println!(
                    "closed={}",
                    unsafe { libc::fcntl(descriptor as i32, libc::F_GETFD) } == -1
                );
                println!(
                    "signals={}",
                    SIGNALS.load(std::sync::atomic::Ordering::Relaxed)
                );
            }
            #[cfg(windows)]
            {
                use windows_sys::Win32::Foundation::GetHandleInformation;
                let mut flags = 0;
                println!(
                    "closed={}",
                    unsafe { GetHandleInformation(descriptor as _, &mut flags) } == 0
                );
            }
        }
        Some("flood") => {
            std::io::stderr().write_all(&vec![b'B'; 262_144]).unwrap();
            std::io::stdout().write_all(&vec![b'A'; 262_144]).unwrap();
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            std::io::stdout().write_all(&input).unwrap();
        }
        Some("input") => {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            std::io::stdout().write_all(&input).unwrap();
        }
        Some("exit") => std::process::exit(7),
        Some("signal") => {
            #[cfg(unix)]
            unsafe {
                libc::raise(libc::SIGTERM);
            }
            #[cfg(windows)]
            unsafe {
                windows_sys::Win32::System::Threading::ExitProcess(u32::MAX);
            }
        }
        _ => panic!("Unknown fixture mode"),
    }
}
