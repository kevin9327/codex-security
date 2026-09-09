# Native OS primitives

These bindings supply OS operations that Node does not expose. The `resolve-security-md` helper uses native account lookup on Unix and native path, file, and directory operations on Windows.

`wallClockMicroseconds`, typed in `process-binding.mts`, reads the OS wall clock as signed Unix microseconds. TypeScript formats persistence timestamps with Python's UTC spelling, retaining six fractional digits and omitting a zero fraction.

`errnoMessage` copies the C runtime's error text. `windowsErrorMessage` returns Win32 error text as UTF-16LE. Preflight config reads use `windowsReadFileCrt`, which owns a non-inheritable CRT descriptor and returns binary bytes or the CRT errno, preserving the existing file-read diagnostics without translating Win32 error codes.

The Node-API 8 functions are typed in `binding.mts`. Paths remain byte buffers. `statAt` never follows the final symlink; device and inode numbers are decimal strings so JavaScript does not round them. `openAt` and `duplicate` create descriptors with close-on-exec set. Node owns subsequent reads, writes, `fstat`, `fsync`, and close calls. `userHome` looks up raw username bytes through the operating system and returns raw home-directory bytes or a missing result, without Git. `environment` reads a named environment value as raw bytes, returning null when unset and an empty buffer for an empty value.

`directoryEntries` returns raw names in filesystem order. With `withTypes: true`, it uses cached directory and symlink types where available and returns any individual type-query errno beside that entry. Symlinks are not followed. With `withTypes: false`, it never queries entry metadata; the unused type flags are false and entry errnos are zero. A directory-open or iteration failure returns its errno and an empty array. Rust closes the directory on success or failure.

`readCopyStat` captures permission bits, bigint access/modification nanoseconds, and macOS file flags. The caller can retain that snapshot across a file read, matching cached `DirEntry.stat()` metadata. Unix `copyStat` applies the snapshot in timestamp, Linux extended-attribute, permission, and file-flag order, with [Python 3.12's supported operations and ignored errors](https://github.com/python/cpython/blob/v3.12.10/Lib/shutil.py). Its follow choice is already resolved by the caller; failures return the native errno and raw source or destination path, or null for filename-less timestamp errors.

Windows `setWindowsTimes` supplies the missing exact timestamp write and preserves Python's handle sharing and filename-less `SetFileTime` errors. The typed caller retains the existing wide `realpath` and `chmod` operations, including skipping timestamp changes when copying link metadata. `copyFile2` passes explicit flags to Win32 and returns the error decoded from its HRESULT, matching [Python 3.12's native copy operation](https://github.com/python/cpython/blob/v3.12.10/Modules/_winapi.c). The caller owns fallback decisions. These primitives do not perform recursive copies or select targets.

`openAt` and `fileLock` retry EINTR, matching the current Python helpers. Other descriptor operations return their native errno. Directory enumeration uses the Rust standard library's OS behavior. `readDescriptor` retries one interrupted Node read without losing earlier chunks. Blocking locks must run outside the main JavaScript event loop; a process that holds a lock releases it on close or exit. A Python signal handler can raise during a blocked call, so later routing must preserve cancellation through the worker lifecycle.

Install the pinned Rust toolchain and the existing TypeScript dependencies, then run from the repository root:

```sh
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
pnpm --dir sdk/typescript run build:ci
node plugins/codex-security/native/generate-unicode.mjs
node plugins/codex-security/native/build.mjs
node plugins/codex-security/native/proof.mjs
cargo +1.97.1 fmt --check --manifest-path plugins/codex-security/native/Cargo.toml
cargo +1.97.1 clippy --locked --manifest-path plugins/codex-security/native/Cargo.toml -- -D warnings
```

The proof runs without Python. It checks directory replacement, byte paths, unreadable-file metadata, long raw symlinks, descriptor duplication, Node descriptor I/O, account lookup, directory names and types, names-only enumeration, nonsearchable directories, contention, unlock, and process-death release. Linux exercises undecodable filename bytes; macOS uses valid UTF-8 filenames required by APFS. CI invokes it with an empty `PATH`. During migration, the same protocol can compare the existing Python lock helper:

```sh
node plugins/codex-security/native/proof.mjs python3 plugins/codex-security/scripts
```

Build outputs stay under ignored `target` and `dist` directories. Linux output directories include the C runtime: `linux-x64-gnu`, `linux-arm64-gnu`, `linux-x64-musl`, and `linux-arm64-musl`. The dependency-free `platform.mts` helper distinguishes glibc from musl using the Node diagnostic report header, without a subprocess. macOS and Windows retain their platform and architecture directories. Source, Cargo registry, and compiler paths are remapped before compilation; actual payload bytes are checked for private paths. Before an artifact is uploaded, run:

```sh
node plugins/codex-security/native/check.mjs
```

GNU Linux artifacts must import no glibc version newer than 2.28. Musl artifacts must be ELF images for the current architecture, depend on that architecture's musl library, and have no version requirements from glibc. GCC's own `GLIBC_2.0` compatibility exports are attributed to `libgcc_s.so.1`, not the C library. Musl has no glibc-style symbol version floor, so its runtime compatibility also requires the load proofs below. macOS artifacts must declare a deployment target of 11.0 or earlier. A build from a newer GNU Linux workstation can pass the behavioral proof and still fail this distribution check.

The `native-unix` workflow builds Linux artifacts in digest-pinned manylinux 2.28 images. It mounts the pinned Rust toolchain and fetched Cargo registry and Git caches, builds offline, and blocks Python commands during compilation. macOS builds set `MACOSX_DEPLOYMENT_TARGET=11.0`. CI verifies separate x64 and arm64 artifacts on both platforms using Node 20.0.0 and 22.13.0.

The `native-musl` workflow uses native x64 and arm64 Ubuntu workers with digest-pinned Rust 1.97.1 Alpine compiler images. Musl builds disable static CRT linkage so Node can load the shared library. After the ELF and private-path checks, each unchanged artifact runs the full proof in pinned Node 20.0.0 Alpine 3.17 and Node 22.13.0 Alpine 3.21 images, with musl 1.2.3 and 1.2.5 respectively. Compilation uses the locked registry and Git caches offline; runtime containers mount only the source and artifact read-only. Python is absent, and proof processes receive an empty `PATH`.

Windows uses `windows-binding.mts` and the same Rust crate. `WindowsHandle` owns a non-inheritable handle through Rust's `File`; explicit `close()` and garbage collection release it. Handles never cross into Node's CRT descriptor table. Paths and returned names are UTF-16LE buffers without a NUL terminator, preserving lone surrogates. Volume identities and file positions are decimal strings; file IDs retain all 128 bits in a buffer.

The binding exposes synchronous file and directory creation, attributes and reparse tags, identity and final/opened names, read/write/seek/size/EOF/flush, exact-handle rename and deletion, and exclusive whole-file locking. Rust's `File` supplies ordinary I/O, cursor-preserving truncation, `sync_all` for flush, and locks. Calls return numeric Windows errors, including 6 for closed handles and 33 for nonblocking lock contention. Buffer ranges, path encoding, and 64-bit seek arguments are checked before use. Overlapped handles are unsupported because pending operations could retain native buffers beyond the call. Path authorization, ancestor traversal, and reparse-point policy remain the caller's responsibility.

`windowsInvariantLowercase` uses `LCMapStringEx` with the invariant locale and filesystem lowercase mapping, matching Python's `ntpath.normcase`. The typed scan-local file backend uses it when comparing verified handle paths. That backend retains ancestor handles without delete sharing and renames or deletes the opened leaf handle; its Python callers remain until finalization migrates.

Five additional operations preserve Windows strings at the Node boundary. `windowsArguments` returns the complete OS argument vector, including the executable and Node options, using Rust's CRT-compatible parser. `windowsEnvironment` reads one wide environment name and distinguishes an absent value (`null`) from an empty buffer. `windowsAbsolutePath` resolves against the native current directory and drive directories without requiring the destination to exist. `windowsDirectoryEntries` uses `std::fs::read_dir` and cached `DirEntry::file_type()` values without opening each child; names remain UTF-16LE, and construction or iteration failures return their numeric Windows error and an empty array. Directory symlinks and junctions have both directory and symbolic-link flags. The typed adapter exposes this enumerator through `entriesWithTypes`, which `resolve-security-md --list` uses on Windows. `windowsReadLink` returns a UTF-16LE link target or its numeric Windows error; candidate normalization uses it to resolve missing paths without losing raw filenames. Assessment validation, deep-review worklists, and rank shard/pool helpers share these typed wide-path operations.

`windows-files.mts` leaves ordinary absolute-path resolution and canonicalization to `GetFullPathNameW` and `GetFinalPathNameByHandleW`, trimming trailing separators below the root. Its small verbatim-path normalizer preserves drive and UNC share roots when resolving dot segments, including literal trailing dots and spaces. Non-strict `realpath` can retain unresolved components; callers must check containment independently. It also supports missing output paths. `stat(path, false)` retains exact symbolic-link and reparse-point metadata so callers can reject junction traversal independently of the enumerator's link label. The SDK's public runtime floor remains Node 22.13.0. Node 20.0.0 is an additional native-foundation compatibility proof; it does not change the SDK engine requirement.

`createWindowsSymlink` passes raw UTF-16LE target and destination paths and caller-supplied flags to `CreateSymbolicLinkW`, returning its numeric Windows error. The caller owns directory-target inference and retry decisions. `copyFileCrt` copies binary bytes through `_wopen`, `_read`, and `_write` with a 1 MiB buffer and non-inheritable descriptors. It opens the source before truncating the destination, closes destination then source, and returns CRT `errno`. Open errors include the failing path; read, write, and close errors return a null path. A close error replaces an earlier error, matching nested FileIO context managers. Same-file checks, metadata, and `CopyFile2` fallback decisions remain with the typed copy owner.

`openWindowsCompletionFile` opens a UTF-16LE path through `_wopen` with read/write, create, binary, and non-inheritable flags and mode `0600`, returning CRT `errno`. The owned `WindowsCompletionFile` exposes only `size`, `seekStart`, `writeZero`, one-byte `locking`, and idempotent `close`. Size follows Python's Windows fstat queries and Windows errors, including size zero for non-disk handles; other operations report CRT errors. Locking uses the current offset with `LK_NBLCK` or `LK_UNLCK`. Scoped thread-local invalid-parameter suppression lets closed operations report errors without terminating the process. Explicit close and garbage collection release the descriptor. The caller owns seeding, seek order, contention handling, retries, and callback cleanup.

Build on Windows after compiling the TypeScript tools, then run:

```sh
node plugins/codex-security/native/build.mjs
node plugins/codex-security/native/check.mjs
node --expose-gc plugins/codex-security/native/proof-windows.mjs
```

The `native-windows` workflow builds x64 and arm64 with MSVC and a static CRT. It checks PE architecture and private paths, then runs the same artifact on Node 22.13.0 and 20.0.0 with an empty `PATH`. The proof covers handle lifetime and garbage collection, ancestor replacement, junctions, exact-handle operations, raw UTF-16 and long paths, numeric errors, and whole-file locking and release. Blocking locks run in child processes. A separate Node 22 invocation uses the runner's Python to compare both directions of contention, unlock, close, and process-death release against the existing `msvcrt` byte-zero lock. Python is only an optional migration oracle:

```sh
node --expose-gc plugins/codex-security/native/proof-windows.mjs python plugins/codex-security/scripts
```

The build also compiles the test-only `windows-wide-launcher` Rust example. It starts a Node proof child with lone surrogates in arguments, environment values, and its working directory. That child checks complete directory iteration, distinct surrogate and replacement-character files, canonical paths, bounded reads, output truncation, and recursive long paths through the typed adapter. A Rust file guard with sharing disabled remains open while the child enumerates its name; an explicit data read fails with a sharing violation. Attribute-only access is not blocked by Windows file sharing. Root-normalization tables run on the same matrix. Scope binding also reads raw requested-scope and contract paths, preserves ordered JSON and unrelated hash fields, truncates both outputs, and leaves documents unchanged when validation fails. The launcher cleans up the wide fixtures and is never included in the uploaded or bundled native payloads.

`process-binding.mts` exposes synchronous `rawProcess` for raw POSIX bytes or Windows UTF-16LE executable, arguments, cwd, and inherited environment edits. It captures unlimited byte stdout/stderr concurrently with byte stdin; absent input inherits stdin and an empty buffer sends EOF. Spawn failures return native error numbers; successful calls return Python-compatible exit or signal codes. Unix restores SIGPIPE/SIGXFSZ and closes inherited descriptors at exec. Windows restricts handle inheritance and preserves CreateProcess executable lookup. It does not request a shell. This internal primitive is not routed into product commands yet.

The test-only `process-fixture` example and portable process proof cover raw arguments, cwd and environment, descriptor inheritance, signal defaults, large simultaneous pipe traffic, early input closure, executable search, and exit/error codes. The existing Linux, macOS, and Windows workflows execute it on Node 20/22; the fixture executable is excluded from uploaded and bundled payloads.

## Package inputs

The `native-artifacts` workflow calls all three platform workflows and combines their eight verified payloads into `native-universal-<commit>`. PR validation jobs share one artifact assembled by `node-ci`; release and standalone validation runs assemble their own. The standalone MCP builder and npm package include the same complete `mcp/native` tree; neither compiles nor downloads code at runtime.

The GNU x64 job also runs `notices.mjs` against the locked Cargo metadata. It collects crate licenses and the pinned Rust standard-library notices for both package surfaces. The NAPI crates omit license files from their registry archives, so `licenses/napi.txt` preserves their [pinned upstream license](https://github.com/napi-rs/napi-rs/blob/956e4525fea6a676ea3680b711382f167b899af9/LICENSE). Review that override when upgrading those dependencies.

Before local plugin builds, tests, or Docker builds, select a successful run for the checkout's native sources. You can run `native-artifacts` manually on a pushed branch. Use the artifact name shown by that run; pull-request artifacts use the tested merge commit. From the repository root:

```sh
gh run download <run-id> --name native-universal-<commit> --dir plugins/codex-security/native/prebuilt
```

The ignored `prebuilt` directory must contain all eight platform directories and the shared notices. Refresh it after changing the native source or build toolchain. Missing payloads fail the build, including on hosts that only load one of them. Installed-package checks load the matching artifact with an empty `PATH`.

## SQLite foundation

`sqlite.mts` accepts the native binding and provides unused internal connection, statement, row, transaction, scalar-function, and online-backup primitives. SQLite INTEGER values remain bigint and REAL values remain number, including integral REAL values; callers choose any domain conversion explicitly. Transactions require synchronous callbacks. Queries, migrations, and command routing remain in TypeScript when they are migrated.

The addon bundles `libsqlite3-sys` 0.38.2 and SQLite 3.53.2 using the locked C compiler dependencies. Native builds need a C compiler but no Python, node-gyp, bindgen, or system SQLite. `.cargo/config.toml` fixes SQLite URI parsing to opt-in, matching Python's `uri=False`. The existing eight-artifact distribution and notices include the engine.

`proof-sqlite.mts` runs on Node 20/22 with an empty PATH and covers typed values, transactions, statement/callback lifetime, foreign keys, busy contention, and live WAL online backups that replace destinations and preserve rowids. Windows CI temporarily prepares synthetic filename expectations using Python 3.12.10, then both Node proofs consume only that data. Replace this migration-only preparation with reviewed recorded expectations after actual Windows parity is established; final Python retirement must remove the preparation and its setup step.

## Regex foundation

`regex-binding.mts` exposes one internal `regexFullMatch(Uint32Array, Uint16Array): boolean` operation. The caller supplies trusted bytecode from the typed Python-pattern compiler. The addon owns a copy of the instructions and converts UTF-16 units to WTF-8 before executing a full match. Astral characters and lone surrogates survive the boundary. Pattern parsing, error diagnostics, and Python 3.12 anchor semantics belong to the typed compiler; no product command uses this primitive yet.

Cargo pins the existing [RustPython SRE engine and WTF-8 crate](https://github.com/RustPython/RustPython/tree/287dcd91e9c64e302c9a6cd02f3f88f49ecf558b/crates) to that revision. A scoped Cargo override supplies only the engine's five Unicode lookup functions through `unicode15`. `generate-unicode.mts` rebuilds its ignored Rust tables from the existing `@unicode/unicode-15.0.0` 2.0.2 dependency before Cargo compilation. It uses Letter, Number, Decimal_Number, White_Space, simple lowercase, and simple uppercase plus the first unconditional full-uppercase code point, matching SRE's uppercase operation. The facade adds Python's four U+001C–U+001F whitespace characters. Engine code is fetched unchanged; ICU and Unicode 17 data are not linked.

Run `node plugins/codex-security/native/proof-regex.mjs` after building. All eight native CI targets run the recorded full-match cases on Node 20/22 without Python. The cases cover capture backtracking, conditionals, lookbehind, atomic and possessive repeats, large repeat counts, Unicode 15 classification and casing, and raw UTF-16. Native notices include both Git dependencies' licenses and the generated Unicode data notices.
