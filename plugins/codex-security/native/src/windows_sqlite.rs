use libsqlite3_sys as sql;
use std::{
    ffi::{c_char, c_int, CStr},
    ptr,
    sync::OnceLock,
};

const NAME: &CStr = c"codex-windows";

pub fn vfs_name() -> Result<*const c_char, c_int> {
    static REGISTERED: OnceLock<c_int> = OnceLock::new();
    let status = *REGISTERED.get_or_init(|| unsafe {
        let original = sql::sqlite3_vfs_find(c"win32".as_ptr());
        if original.is_null() {
            return sql::SQLITE_CANTOPEN;
        }
        let mut vfs = Box::new(*original);
        vfs.zName = NAME.as_ptr();
        vfs.pNext = ptr::null_mut();
        // Reserve the largest namespace prefix without reducing SQLite's path budget.
        vfs.mxPathname += 6;
        vfs.xFullPathname = Some(full_pathname);
        let vfs = Box::into_raw(vfs);
        let status = sql::sqlite3_vfs_register(vfs, 0);
        if status != sql::SQLITE_OK {
            drop(Box::from_raw(vfs));
        }
        status
    });
    if status == sql::SQLITE_OK {
        Ok(NAME.as_ptr())
    } else {
        Err(status)
    }
}

unsafe extern "C" fn full_pathname(
    _vfs: *mut sql::sqlite3_vfs,
    name: *const c_char,
    capacity: c_int,
    output: *mut c_char,
) -> c_int {
    let original = sql::sqlite3_vfs_find(c"win32".as_ptr());
    if original.is_null() || capacity <= 6 {
        return sql::SQLITE_CANTOPEN;
    }
    let Some(resolve) = (*original).xFullPathname else {
        return sql::SQLITE_CANTOPEN;
    };
    let status = resolve(original, name, capacity - 6, output);
    if status != sql::SQLITE_OK {
        return status;
    }
    let path = CStr::from_ptr(output).to_bytes();
    // Node's executable has no longPathAware manifest. SQLite's Win32 VFS
    // needs a namespace prefix once the database or its journal reaches MAX_PATH.
    if String::from_utf8_lossy(path).encode_utf16().count() + 8 < 260
        || path.starts_with(b"\\\\?\\")
        || path.starts_with(b"\\\\.\\")
    {
        return sql::SQLITE_OK;
    }
    let (prefix, skip): (&[u8], usize) = if path.starts_with(b"\\\\") {
        (b"\\\\?\\UNC\\", 2)
    } else {
        (b"\\\\?\\", 0)
    };
    let length = path.len();
    ptr::copy(
        output.add(skip),
        output.add(prefix.len()),
        length - skip + 1,
    );
    ptr::copy_nonoverlapping(prefix.as_ptr().cast(), output, prefix.len());
    sql::SQLITE_OK
}
