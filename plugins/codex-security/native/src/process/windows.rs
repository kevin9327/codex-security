use super::{invalid, Child, Request, Spawned};
use std::{
    cmp::Ordering,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Globalization::{CompareStringOrdinal, CSTR_EQUAL, CSTR_LESS_THAN},
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{GetFileType, FILE_TYPE_CHAR},
    System::{
        Console::{GetStdHandle, STD_INPUT_HANDLE},
        Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW},
        Pipes::CreatePipe,
        Threading::*,
    },
};

pub(super) fn decode(bytes: &[u8]) -> napi::Result<OsString> {
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid(
            "Process string must contain whole UTF-16LE code units",
        ));
    }
    let value: Vec<_> = bytes
        .chunks_exact(2)
        .map(|part| u16::from_le_bytes([part[0], part[1]]))
        .collect();
    if value.contains(&0) {
        return Err(invalid("Process string contains a NUL code unit"));
    }
    Ok(OsString::from_wide(&value))
}

pub(super) fn validate_name(name: &OsStr) -> napi::Result<()> {
    if name.is_empty() || name.encode_wide().skip(1).any(|unit| unit == 61) {
        return Err(invalid("Invalid environment name"));
    }
    Ok(())
}

fn check(success: i32) -> io::Result<()> {
    if success == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().collect()
}

fn compare(left: &[u16], right: &[u16]) -> Ordering {
    match unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        )
    } {
        CSTR_EQUAL => Ordering::Equal,
        CSTR_LESS_THAN => Ordering::Less,
        _ => Ordering::Greater,
    }
}

fn environment(edits: &[(OsString, Option<OsString>)]) -> io::Result<Vec<u16>> {
    struct Block(*mut u16);
    impl Drop for Block {
        fn drop(&mut self) {
            unsafe {
                FreeEnvironmentStringsW(self.0);
            }
        }
    }
    let pointer = unsafe { GetEnvironmentStringsW() };
    if pointer.is_null() {
        return Err(io::Error::last_os_error());
    }
    let block = Block(pointer);
    let mut entries = Vec::new();
    let mut cursor = block.0;
    unsafe {
        while *cursor != 0 {
            let start = cursor;
            while *cursor != 0 {
                cursor = cursor.add(1);
            }
            let entry = std::slice::from_raw_parts(start, cursor.offset_from(start) as usize);
            if let Some(split) = entry
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, unit)| **unit == 61)
                .map(|(index, _)| index)
            {
                entries.push((entry[..split].to_vec(), entry[split + 1..].to_vec()));
            }
            cursor = cursor.add(1);
        }
    }
    for (key, value) in edits {
        let key = wide(key);
        entries.retain(|(name, _)| compare(name, &key) != Ordering::Equal);
        if let Some(value) = value {
            entries.push((key, wide(value)));
        }
    }
    entries.sort_by(|(a, _), (b, _)| compare(a, b));
    let mut result = Vec::new();
    for (key, value) in entries {
        result.extend(key);
        result.push(61);
        result.extend(value);
        result.push(0);
    }
    if result.is_empty() {
        result.push(0);
    }
    result.push(0);
    Ok(result)
}

// Python's list2cmdline quoting, including empty arguments and trailing backslashes.
fn command_line(request: &Request) -> Vec<u16> {
    let mut line = Vec::new();
    for (index, argument) in std::iter::once(&request.program)
        .chain(&request.args)
        .enumerate()
    {
        if index != 0 {
            line.push(32);
        }
        let value = wide(argument);
        let quoted = value.is_empty() || value.iter().any(|unit| matches!(unit, 9 | 32));
        if quoted {
            line.push(34);
        }
        let mut slashes = 0;
        for unit in value {
            if unit == 92 {
                slashes += 1;
                continue;
            }
            let count = if unit == 34 { slashes * 2 + 1 } else { slashes };
            line.extend(std::iter::repeat_n(92, count));
            line.push(unit);
            slashes = 0;
        }
        line.extend(std::iter::repeat_n(
            92,
            if quoted { slashes * 2 } else { slashes },
        ));
        if quoted {
            line.push(34);
        }
    }
    line.push(0);
    line
}

fn pipe(parent_reads: bool) -> io::Result<(File, File)> {
    let mut read = null_mut();
    let mut write = null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    check(unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) })?;
    let read = unsafe { File::from_raw_handle(read) };
    let write = unsafe { File::from_raw_handle(write) };
    let (parent, child) = if parent_reads {
        (read, write)
    } else {
        (write, read)
    };
    check(unsafe { SetHandleInformation(parent.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) })?;
    Ok((parent, child))
}

fn inherited_input() -> io::Result<File> {
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if input.is_null() {
        return pipe(false).map(|(_, child)| child);
    }
    let mut duplicate = null_mut();
    let process = unsafe { GetCurrentProcess() };
    check(unsafe {
        DuplicateHandle(
            process,
            input,
            process,
            &mut duplicate,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    })?;
    Ok(unsafe { File::from_raw_handle(duplicate) })
}

pub(super) fn spawn(request: &Request) -> io::Result<Spawned> {
    let (output, child_output) = pipe(true)?;
    let (error, child_error) = pipe(true)?;
    let (input, child_input) = if request.input.is_some() {
        let (parent, child) = pipe(false)?;
        (Some(parent), child)
    } else {
        (None, inherited_input()?)
    };
    let mut handles = [
        child_input.as_raw_handle(),
        child_output.as_raw_handle(),
        child_error.as_raw_handle(),
    ]
    .into_iter()
    .filter(|handle| {
        // Console pseudo-handles cannot appear in PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
        !(*handle as usize & 3 == 3 && unsafe { GetFileType(*handle) } == FILE_TYPE_CHAR)
    })
    .collect::<Vec<_>>();
    let mut bytes = 0;
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes);
    }
    let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let list = storage.as_mut_ptr().cast();
    check(unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) })?;
    struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for Attributes {
        fn drop(&mut self) {
            unsafe {
                DeleteProcThreadAttributeList(self.0);
            }
        }
    }
    let attributes = Attributes(list);
    check(unsafe {
        UpdateProcThreadAttribute(
            attributes.0,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_mut_ptr().cast(),
            handles.len() * size_of::<HANDLE>(),
            null_mut(),
            null(),
        )
    })?;
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_input.as_raw_handle();
    startup.StartupInfo.hStdOutput = child_output.as_raw_handle();
    startup.StartupInfo.hStdError = child_error.as_raw_handle();
    startup.lpAttributeList = attributes.0;
    let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
    let mut command = command_line(request);
    let env = environment(&request.environment)?;
    let cwd = request.cwd.as_ref().map(|cwd| {
        let mut value = wide(cwd);
        value.push(0);
        value
    });
    // A null application name preserves CreateProcess search and batch semantics.
    check(unsafe {
        CreateProcessW(
            null(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            env.as_ptr().cast(),
            cwd.as_ref().map_or(null(), |cwd| cwd.as_ptr()),
            &startup.StartupInfo,
            &mut process,
        )
    })?;
    let process_handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    drop(unsafe { OwnedHandle::from_raw_handle(process.hThread) });
    struct Process(OwnedHandle);
    impl Child for Process {
        fn wait(&mut self) -> io::Result<i64> {
            if unsafe { WaitForSingleObject(self.0.as_raw_handle(), INFINITE) } == WAIT_FAILED {
                return Err(io::Error::last_os_error());
            }
            let mut code = 0;
            check(unsafe { GetExitCodeProcess(self.0.as_raw_handle(), &mut code) })?;
            Ok(i64::from(code))
        }
        fn kill(&mut self) {
            unsafe {
                TerminateProcess(self.0.as_raw_handle(), 1);
            }
        }
    }
    Ok(Spawned {
        child: Box::new(Process(process_handle)),
        input,
        output,
        error,
    })
}
