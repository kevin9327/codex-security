use libsqlite3_sys as sql;
use napi::{bindgen_prelude::*, Env, Error, Result, Status};
use napi_derive::napi;
use std::{
    cell::Cell,
    ffi::{c_void, CStr, CString},
    ptr,
    rc::Rc,
};

type Value = Either5<Null, BigInt, f64, String, Buffer>;
extern "C" {
    fn sqlite3_close_v2(database: *mut sql::sqlite3) -> i32;
}
fn input_error(message: impl Into<String>) -> Error {
    Error::new(Status::InvalidArg, message.into())
}
fn cstring(value: &[u8]) -> Result<CString> {
    CString::new(value).map_err(|_| input_error("embedded NUL"))
}
fn failure<T>(env: &Env, db: *mut sql::sqlite3, code: i32) -> Result<T> {
    let message = unsafe {
        CStr::from_ptr(if db.is_null() {
            sql::sqlite3_errstr(code)
        } else {
            sql::sqlite3_errmsg(db)
        })
    }
    .to_string_lossy()
    .into_owned();
    let mut error = env.create_error(Error::new(Status::GenericFailure, message))?;
    error.set_named_property("sqliteErrorCode", code & 255)?;
    error.set_named_property("sqliteExtendedCode", code)?;
    Err(Error::from(error.into_unknown(env)?))
}
fn check(env: &Env, db: *mut sql::sqlite3, code: i32) -> Result<()> {
    if code == sql::SQLITE_OK {
        Ok(())
    } else {
        failure(env, db, code)
    }
}
struct Database {
    raw: Cell<*mut sql::sqlite3>,
    active: Cell<u32>,
}
struct ActiveCall<'a>(&'a Cell<u32>);
impl<'a> ActiveCall<'a> {
    fn enter(value: &'a Cell<u32>) -> Self {
        value.set(value.get() + 1);
        Self(value)
    }
}
impl Drop for ActiveCall<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}
struct ActiveStatement<'a>(&'a Cell<bool>);
impl Drop for ActiveStatement<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}
impl Database {
    fn get(&self) -> Result<*mut sql::sqlite3> {
        let raw = self.raw.get();
        if raw.is_null() {
            Err(input_error("connection is closed"))
        } else {
            Ok(raw)
        }
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let raw = self.raw.replace(ptr::null_mut());
        if !raw.is_null() {
            unsafe {
                sqlite3_close_v2(raw);
            }
        }
    }
}
#[napi]
pub struct SqliteConnection {
    inner: Rc<Database>,
}
#[napi]
impl SqliteConnection {
    #[napi(constructor)]
    pub fn new(env: Env, filename: Buffer, read_only: bool, uri: bool) -> Result<Self> {
        let name = cstring(&filename)?;
        let mut raw = ptr::null_mut();
        let flags = if read_only {
            sql::SQLITE_OPEN_READONLY
        } else {
            sql::SQLITE_OPEN_READWRITE | sql::SQLITE_OPEN_CREATE
        } | sql::SQLITE_OPEN_FULLMUTEX
            | if uri { sql::SQLITE_OPEN_URI } else { 0 };
        #[cfg(windows)]
        let vfs = match crate::windows_sqlite::vfs_name() {
            Ok(name) => name,
            Err(code) => return failure(&env, ptr::null_mut(), code),
        };
        #[cfg(not(windows))]
        let vfs = ptr::null();
        let code = unsafe { sql::sqlite3_open_v2(name.as_ptr(), &mut raw, flags, vfs) };
        if code != sql::SQLITE_OK {
            let error = failure(&env, raw, code);
            if !raw.is_null() {
                unsafe {
                    sqlite3_close_v2(raw);
                }
            }
            return error;
        }
        unsafe {
            sql::sqlite3_extended_result_codes(raw, 1);
        }
        Ok(Self {
            inner: Rc::new(Database {
                raw: Cell::new(raw),
                active: Cell::new(0),
            }),
        })
    }
    #[napi]
    pub fn close(&self, env: Env) -> Result<()> {
        if self.inner.active.get() != 0 {
            return Err(input_error("connection has an active call"));
        }
        let raw = self.inner.raw.get();
        if raw.is_null() {
            return Ok(());
        }
        check(&env, raw, unsafe { sqlite3_close_v2(raw) })?;
        self.inner.raw.set(ptr::null_mut());
        Ok(())
    }
    #[napi(getter)]
    pub fn in_transaction(&self) -> Result<bool> {
        Ok(unsafe { sql::sqlite3_get_autocommit(self.inner.get()?) == 0 })
    }
    #[napi]
    pub fn limit(&self, category: i32, value: i32) -> Result<i32> {
        Ok(unsafe { sql::sqlite3_limit(self.inner.get()?, category, value) })
    }
    #[napi(getter)]
    pub fn changes(&self) -> Result<BigInt> {
        Ok(BigInt::from(unsafe {
            sql::sqlite3_changes64(self.inner.get()?)
        }))
    }
    #[napi(getter)]
    pub fn last_insert_rowid(&self) -> Result<BigInt> {
        Ok(BigInt::from(unsafe {
            sql::sqlite3_last_insert_rowid(self.inner.get()?)
        }))
    }
    #[napi]
    pub fn busy_timeout(&self, env: Env, milliseconds: i32) -> Result<()> {
        let raw = self.inner.get()?;
        check(&env, raw, unsafe {
            sql::sqlite3_busy_timeout(raw, milliseconds)
        })
    }
    #[napi]
    pub fn exec(&self, env: Env, source: String) -> Result<()> {
        let raw = self.inner.get()?;
        let source = cstring(source.as_bytes())?;
        let _active = ActiveCall::enter(&self.inner.active);
        check(&env, raw, unsafe {
            sql::sqlite3_exec(raw, source.as_ptr(), None, ptr::null_mut(), ptr::null_mut())
        })
    }
    #[napi]
    pub fn prepare(&self, env: Env, source: String) -> Result<SqliteStatement> {
        let raw = self.inner.get()?;
        let source = cstring(source.as_bytes())?;
        let _active = ActiveCall::enter(&self.inner.active);
        let mut statement = ptr::null_mut();
        let mut tail = ptr::null();
        check(&env, raw, unsafe {
            sql::sqlite3_prepare_v2(raw, source.as_ptr(), -1, &mut statement, &mut tail)
        })?;
        let result = SqliteStatement {
            raw: Cell::new(statement),
            closed: Cell::new(false),
            active: Cell::new(false),
            owner: self.inner.clone(),
        };
        while unsafe { *tail } != 0 {
            let mut next = ptr::null_mut();
            let mut rest = ptr::null();
            let code = unsafe { sql::sqlite3_prepare_v2(raw, tail, -1, &mut next, &mut rest) };
            if code != sql::SQLITE_OK {
                return failure(&env, raw, code);
            }
            if !next.is_null() {
                unsafe {
                    sql::sqlite3_finalize(next);
                }
                result.finalize_statement(env)?;
                return Err(input_error("execute accepts one SQL statement"));
            }
            tail = rest;
        }
        Ok(result)
    }
    #[napi]
    pub fn backup(&self, env: Env, destination: &SqliteConnection) -> Result<SqliteBackup> {
        let source = self.inner.get()?;
        let target = destination.inner.get()?;
        let raw =
            unsafe { sql::sqlite3_backup_init(target, c"main".as_ptr(), source, c"main".as_ptr()) };
        if raw.is_null() {
            return failure(&env, target, unsafe {
                sql::sqlite3_extended_errcode(target)
            });
        }
        Ok(SqliteBackup {
            raw: Cell::new(raw),
            source: self.inner.clone(),
            destination: destination.inner.clone(),
        })
    }
    #[napi]
    pub fn function(
        &self,
        env: Env,
        name: String,
        arguments: i32,
        deterministic: bool,
        callback: FunctionRef<Vec<Value>, Value>,
    ) -> Result<()> {
        let raw = self.inner.get()?;
        let name = cstring(name.as_bytes())?;
        let function = Box::new(UserFunction { env, callback });
        let flags = sql::SQLITE_UTF8
            | if deterministic {
                sql::SQLITE_DETERMINISTIC
            } else {
                0
            };
        check(&env, raw, unsafe {
            sql::sqlite3_create_function_v2(
                raw,
                name.as_ptr(),
                arguments,
                flags,
                Box::into_raw(function).cast(),
                Some(call_function),
                None,
                None,
                Some(drop_function),
            )
        })
    }
}
#[napi]
pub struct SqliteStatement {
    raw: Cell<*mut sql::sqlite3_stmt>,
    closed: Cell<bool>,
    active: Cell<bool>,
    owner: Rc<Database>,
}
impl SqliteStatement {
    fn get(&self) -> Result<*mut sql::sqlite3_stmt> {
        self.owner.get()?;
        if self.active.get() {
            return Err(input_error("recursive use of statement"));
        }
        if self.closed.get() {
            Err(input_error("statement is finalized"))
        } else {
            Ok(self.raw.get())
        }
    }
}
impl Drop for SqliteStatement {
    fn drop(&mut self) {
        let raw = self.raw.replace(ptr::null_mut());
        if !raw.is_null() {
            unsafe {
                sql::sqlite3_finalize(raw);
            }
        }
    }
}
#[napi]
impl SqliteStatement {
    #[napi(getter)]
    pub fn columns(&self) -> Result<Vec<String>> {
        let raw = self.get()?;
        if raw.is_null() {
            return Ok(vec![]);
        }
        (0..unsafe { sql::sqlite3_column_count(raw) })
            .map(|i| {
                Ok(unsafe { CStr::from_ptr(sql::sqlite3_column_name(raw, i)) }
                    .to_string_lossy()
                    .into_owned())
            })
            .collect()
    }
    #[napi(getter)]
    pub fn parameter_names(&self) -> Result<Vec<Either<String, Null>>> {
        let raw = self.get()?;
        if raw.is_null() {
            return Ok(vec![]);
        }
        Ok((1..=unsafe { sql::sqlite3_bind_parameter_count(raw) })
            .map(|i| {
                let name = unsafe { sql::sqlite3_bind_parameter_name(raw, i) };
                if name.is_null() {
                    Either::B(Null)
                } else {
                    Either::A(
                        unsafe { CStr::from_ptr(name) }
                            .to_string_lossy()
                            .into_owned(),
                    )
                }
            })
            .collect())
    }
    #[napi]
    pub fn bind(&self, env: Env, values: Vec<Value>) -> Result<()> {
        let raw = self.get()?;
        let count = if raw.is_null() {
            0
        } else {
            unsafe { sql::sqlite3_bind_parameter_count(raw) }
        };
        if values.len() != count as usize {
            return Err(input_error(format!(
                "expected {count} parameters, received {}",
                values.len()
            )));
        }
        if raw.is_null() {
            return Ok(());
        }
        unsafe {
            sql::sqlite3_reset(raw);
        }
        check(&env, self.owner.get()?, unsafe {
            sql::sqlite3_clear_bindings(raw)
        })?;
        for (index, value) in values.into_iter().enumerate() {
            let index = (index + 1) as i32;
            let code = unsafe {
                match value {
                    Either5::A(_) => sql::sqlite3_bind_null(raw, index),
                    Either5::B(value) => {
                        let (value, lossless) = value.get_i64();
                        if !lossless {
                            return Err(input_error("integer outside signed 64-bit range"));
                        }
                        sql::sqlite3_bind_int64(raw, index, value)
                    }
                    Either5::C(value) => sql::sqlite3_bind_double(raw, index, value),
                    Either5::D(value) => sql::sqlite3_bind_text64(
                        raw,
                        index,
                        value.as_ptr().cast(),
                        value.len() as u64,
                        sql::SQLITE_TRANSIENT(),
                        sql::SQLITE_UTF8 as u8,
                    ),
                    Either5::E(value) => {
                        if value.is_empty() {
                            sql::sqlite3_bind_zeroblob64(raw, index, 0)
                        } else {
                            sql::sqlite3_bind_blob64(
                                raw,
                                index,
                                value.as_ptr().cast(),
                                value.len() as u64,
                                sql::SQLITE_TRANSIENT(),
                            )
                        }
                    }
                }
            };
            check(&env, self.owner.get()?, code)?;
        }
        Ok(())
    }
    #[napi]
    pub fn step(&self, env: Env) -> Result<Either<Vec<Value>, Null>> {
        let raw = self.get()?;
        if raw.is_null() {
            return Ok(Either::B(Null));
        }
        self.active.set(true);
        let _statement_active = ActiveStatement(&self.active);
        let _connection_active = ActiveCall::enter(&self.owner.active);
        let code = unsafe { sql::sqlite3_step(raw) };
        if code == sql::SQLITE_DONE {
            return Ok(Either::B(Null));
        }
        if code != sql::SQLITE_ROW {
            return failure(&env, self.owner.get()?, code);
        }
        let mut row = vec![];
        for index in 0..unsafe { sql::sqlite3_column_count(raw) } {
            let value = unsafe {
                match sql::sqlite3_column_type(raw, index) {
                    sql::SQLITE_NULL => Either5::A(Null),
                    sql::SQLITE_INTEGER => {
                        Either5::B(BigInt::from(sql::sqlite3_column_int64(raw, index)))
                    }
                    sql::SQLITE_FLOAT => Either5::C(sql::sqlite3_column_double(raw, index)),
                    sql::SQLITE_TEXT => {
                        let bytes = sql::sqlite3_column_text(raw, index);
                        let size = sql::sqlite3_column_bytes(raw, index) as usize;
                        let bytes = if size == 0 {
                            &[]
                        } else {
                            std::slice::from_raw_parts(bytes, size)
                        };
                        Either5::D(
                            std::str::from_utf8(bytes)
                                .map_err(|_| input_error("SQLite TEXT is not UTF-8"))?
                                .to_owned(),
                        )
                    }
                    _ => {
                        let bytes = sql::sqlite3_column_blob(raw, index).cast::<u8>();
                        let size = sql::sqlite3_column_bytes(raw, index) as usize;
                        Either5::E(
                            if size == 0 {
                                vec![]
                            } else {
                                std::slice::from_raw_parts(bytes, size).to_vec()
                            }
                            .into(),
                        )
                    }
                }
            };
            row.push(value);
        }
        Ok(Either::A(row))
    }
    #[napi(js_name = "finalize")]
    pub fn finalize_statement(&self, env: Env) -> Result<()> {
        if self.active.get() {
            return Err(input_error("recursive use of statement"));
        }
        self.closed.set(true);
        let raw = self.raw.replace(ptr::null_mut());
        if raw.is_null() {
            return Ok(());
        }
        check(&env, self.owner.raw.get(), unsafe {
            sql::sqlite3_finalize(raw)
        })
    }
}
#[napi(object)]
pub struct BackupStep {
    pub status: i32,
    pub remaining: i32,
    pub page_count: i32,
}
#[napi]
pub struct SqliteBackup {
    raw: Cell<*mut sql::sqlite3_backup>,
    source: Rc<Database>,
    destination: Rc<Database>,
}
impl Drop for SqliteBackup {
    fn drop(&mut self) {
        let raw = self.raw.replace(ptr::null_mut());
        if !raw.is_null() {
            unsafe {
                sql::sqlite3_backup_finish(raw);
            }
        }
    }
}
#[napi]
impl SqliteBackup {
    #[napi]
    pub fn step(&self, env: Env, pages: i32) -> Result<BackupStep> {
        self.source.get()?;
        let target = self.destination.get()?;
        let raw = self.raw.get();
        if raw.is_null() {
            return Err(input_error("backup is finished"));
        }
        let status = unsafe { sql::sqlite3_backup_step(raw, pages) };
        if ![
            sql::SQLITE_OK,
            sql::SQLITE_DONE,
            sql::SQLITE_BUSY,
            sql::SQLITE_LOCKED,
        ]
        .contains(&status)
        {
            return failure(&env, target, status);
        }
        Ok(BackupStep {
            status,
            remaining: unsafe { sql::sqlite3_backup_remaining(raw) },
            page_count: unsafe { sql::sqlite3_backup_pagecount(raw) },
        })
    }
    #[napi]
    pub fn finish(&self, env: Env) -> Result<()> {
        let raw = self.raw.replace(ptr::null_mut());
        if raw.is_null() {
            return Ok(());
        }
        check(&env, self.destination.raw.get(), unsafe {
            sql::sqlite3_backup_finish(raw)
        })
    }
}
struct UserFunction {
    env: Env,
    callback: FunctionRef<Vec<Value>, Value>,
}
unsafe extern "C" fn drop_function(data: *mut c_void) {
    drop(Box::from_raw(data.cast::<UserFunction>()));
}
unsafe extern "C" fn call_function(
    context: *mut sql::sqlite3_context,
    argc: i32,
    argv: *mut *mut sql::sqlite3_value,
) {
    let function = &*sql::sqlite3_user_data(context).cast::<UserFunction>();
    let mut arguments = vec![];
    for value in if argc == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(argv, argc as usize)
    } {
        arguments.push(match sql::sqlite3_value_type(*value) {
            sql::SQLITE_NULL => Either5::A(Null),
            sql::SQLITE_INTEGER => Either5::B(BigInt::from(sql::sqlite3_value_int64(*value))),
            sql::SQLITE_FLOAT => Either5::C(sql::sqlite3_value_double(*value)),
            sql::SQLITE_TEXT => {
                let size = sql::sqlite3_value_bytes(*value) as usize;
                let bytes = if size == 0 {
                    &[]
                } else {
                    std::slice::from_raw_parts(sql::sqlite3_value_text(*value), size)
                };
                match std::str::from_utf8(bytes) {
                    Ok(value) => Either5::D(value.to_owned()),
                    Err(_) => {
                        sql::sqlite3_result_error(
                            context,
                            c"SQLite TEXT is not UTF-8".as_ptr(),
                            -1,
                        );
                        return;
                    }
                }
            }
            _ => {
                let size = sql::sqlite3_value_bytes(*value) as usize;
                Either5::E(
                    if size == 0 {
                        vec![]
                    } else {
                        std::slice::from_raw_parts(
                            sql::sqlite3_value_blob(*value).cast::<u8>(),
                            size,
                        )
                        .to_vec()
                    }
                    .into(),
                )
            }
        });
    }
    match function
        .callback
        .borrow_back(&function.env)
        .and_then(|callback| callback.call(arguments))
    {
        Ok(value) => match value {
            Either5::A(_) => sql::sqlite3_result_null(context),
            Either5::B(value) => {
                let (value, lossless) = value.get_i64();
                if lossless {
                    sql::sqlite3_result_int64(context, value);
                } else {
                    sql::sqlite3_result_error(
                        context,
                        c"integer outside signed 64-bit range".as_ptr(),
                        -1,
                    );
                }
            }
            Either5::C(value) => sql::sqlite3_result_double(context, value),
            Either5::D(value) => sql::sqlite3_result_text64(
                context,
                value.as_ptr().cast(),
                value.len() as u64,
                sql::SQLITE_TRANSIENT(),
                sql::SQLITE_UTF8 as u8,
            ),
            Either5::E(value) => {
                if value.is_empty() {
                    sql::sqlite3_result_zeroblob64(context, 0);
                } else {
                    sql::sqlite3_result_blob64(
                        context,
                        value.as_ptr().cast(),
                        value.len() as u64,
                        sql::SQLITE_TRANSIENT(),
                    )
                }
            }
        },
        Err(_) => {
            let mut thrown = ptr::null_mut();
            napi::sys::napi_get_and_clear_last_exception(function.env.raw(), &mut thrown);
            sql::sqlite3_result_error(
                context,
                c"user-defined function raised exception".as_ptr(),
                -1,
            );
        }
    }
}
#[napi]
pub fn complete_statement(source: String) -> Result<bool> {
    let source = cstring(source.as_bytes())?;
    Ok(unsafe { sql::sqlite3_complete(source.as_ptr()) != 0 })
}
#[napi]
pub fn sqlite_version() -> String {
    unsafe { CStr::from_ptr(sql::sqlite3_libversion()) }
        .to_string_lossy()
        .into_owned()
}
