//! The SFTP subsystem, served over a session channel via `russh-sftp`
//! (ADR 0016).
//!
//! By default the full filesystem is served as the launching OS user (OpenSSH
//! parity). When a `--sftp-root` is configured, every client path is mapped
//! into that root and path escapes (`..` and symlink traversal) are rejected.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use russh::Channel;
use russh::server::Msg;
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};

/// How many directory entries to return per `readdir` call.
const READDIR_BATCH: usize = 100;

/// Spawn the SFTP server over a session channel.
pub(crate) fn spawn(channel: Channel<Msg>, root: Option<PathBuf>) {
    let handler = SftpSession::new(root);
    tokio::spawn(async move {
        russh_sftp::server::run(channel.into_stream(), handler).await;
    });
}

/// An open handle: either a file or a directory listing in progress.
enum HandleEntry {
    File(std::fs::File),
    Dir { entries: Vec<File>, offset: usize },
}

/// Per-connection SFTP state.
struct SftpSession {
    /// The jail root, if any. When `Some`, the client sees it as `/`.
    root: Option<PathBuf>,
    /// Open handles keyed by the string we hand the client.
    handles: HashMap<String, HandleEntry>,
    /// Monotonic handle id source.
    next_handle: u64,
}

impl SftpSession {
    fn new(root: Option<PathBuf>) -> Self {
        // Canonicalize the root up front so symlink checks are stable.
        let root = root.map(|r| r.canonicalize().unwrap_or(r));
        Self {
            root,
            handles: HashMap::new(),
            next_handle: 0,
        }
    }

    fn alloc_handle(&mut self, entry: HandleEntry) -> String {
        let id = self.next_handle;
        self.next_handle += 1;
        let key = format!("h{id}");
        self.handles.insert(key.clone(), entry);
        key
    }

    /// Map a client path to a real filesystem path, enforcing the jail.
    fn resolve(&self, client_path: &str) -> Result<PathBuf, StatusCode> {
        match &self.root {
            None => Ok(PathBuf::from(client_path)),
            Some(root) => {
                let rel = client_path.trim_start_matches('/');
                let joined = root.join(rel);
                let normalized = normalize_lexical(&joined);
                if !normalized.starts_with(root) {
                    return Err(StatusCode::PermissionDenied);
                }
                // For existing paths, canonicalize to defeat symlink escapes.
                if let Ok(canon) = normalized.canonicalize() {
                    if !canon.starts_with(root) {
                        return Err(StatusCode::PermissionDenied);
                    }
                    return Ok(canon);
                }
                Ok(normalized)
            }
        }
    }

    /// Present a real path back to the client (jail-relative when jailed).
    fn to_client_path(&self, real: &Path) -> String {
        match &self.root {
            None => real.to_string_lossy().into_owned(),
            Some(root) => {
                let shown = real.strip_prefix(root).unwrap_or(real);
                let mut s = String::from("/");
                s.push_str(&shown.to_string_lossy());
                // Collapse "/." → "/".
                if s == "/." {
                    s = "/".into();
                }
                s
            }
        }
    }
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

/// Resolve `.`/`..` components without touching the filesystem.
fn normalize_lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn io_to_status(e: &std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = if path.is_empty() {
            ".".to_string()
        } else {
            path
        };
        let real = self.resolve(&path)?;
        let canonical = real.canonicalize().unwrap_or(real);
        let shown = self.to_client_path(&canonical);
        Ok(Name {
            id,
            files: vec![File::dummy(shown)],
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = self.resolve(&filename)?;
        let mut opts: std::fs::OpenOptions = pflags.into();
        if pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::APPEND) {
            // Create-on-write leniency: some clients open for write without the
            // CREATE flag and expect the file to be created (real OpenSSH
            // uploads send CREATE, so this only helps the lenient case).
            opts.create(true);
        } else {
            // Read-only opens: ensure read access even if no flag was set.
            opts.read(true);
        }
        let file = opts.open(&path).map_err(|e| io_to_status(&e))?;
        Ok(Handle {
            id,
            handle: self.alloc_handle(HandleEntry::File(file)),
        })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let Some(HandleEntry::File(file)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| io_to_status(&e))?;
        let mut buf = vec![0u8; len as usize];
        let n = file.read(&mut buf).map_err(|e| io_to_status(&e))?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let Some(HandleEntry::File(file)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| io_to_status(&e))?;
        file.write_all(&data).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(ok_status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let real = self.resolve(&path)?;
        let mut entries = Vec::new();
        for dirent in std::fs::read_dir(&real).map_err(|e| io_to_status(&e))? {
            let dirent = dirent.map_err(|e| io_to_status(&e))?;
            let name = dirent.file_name().to_string_lossy().into_owned();
            let attrs = match dirent.metadata() {
                Ok(meta) => (&meta).into(),
                Err(_) => FileAttributes::default(),
            };
            entries.push(File::new(name, attrs));
        }
        Ok(Handle {
            id,
            handle: self.alloc_handle(HandleEntry::Dir { entries, offset: 0 }),
        })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(HandleEntry::Dir { entries, offset }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        if *offset >= entries.len() {
            return Err(StatusCode::Eof);
        }
        let end = (*offset + READDIR_BATCH).min(entries.len());
        let batch = entries[*offset..end].to_vec();
        *offset = end;
        Ok(Name { id, files: batch })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let real = self.resolve(&path)?;
        let meta = std::fs::metadata(&real).map_err(|e| io_to_status(&e))?;
        Ok(Attrs {
            id,
            attrs: (&meta).into(),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let real = self.resolve(&path)?;
        let meta = std::fs::symlink_metadata(&real).map_err(|e| io_to_status(&e))?;
        Ok(Attrs {
            id,
            attrs: (&meta).into(),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let Some(HandleEntry::File(file)) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let meta = file.metadata().map_err(|e| io_to_status(&e))?;
        Ok(Attrs {
            id,
            attrs: (&meta).into(),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let real = self.resolve(&path)?;
        apply_setstat(&real, &attrs);
        Ok(ok_status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        if let Some(HandleEntry::File(file)) = self.handles.get(&handle)
            && let Some(size) = attrs.size
        {
            let _ = file.set_len(size);
        }
        Ok(ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let real = self.resolve(&path)?;
        std::fs::create_dir(&real).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        let real = self.resolve(&path)?;
        std::fs::remove_dir(&real).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let real = self.resolve(&filename)?;
        std::fs::remove_file(&real).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let old = self.resolve(&oldpath)?;
        let new = self.resolve(&newpath)?;
        std::fs::rename(&old, &new).map_err(|e| io_to_status(&e))?;
        Ok(ok_status(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let real = self.resolve(&path)?;
        let target = std::fs::read_link(&real).map_err(|e| io_to_status(&e))?;
        Ok(Name {
            id,
            files: vec![File::dummy(self.to_client_path(&target))],
        })
    }
}

/// Apply a subset of `setstat` attributes best-effort (permissions, size).
fn apply_setstat(path: &Path, attrs: &FileAttributes) {
    if let Some(size) = attrs.size
        && let Ok(file) = std::fs::OpenOptions::new().write(true).open(path)
    {
        let _ = file.set_len(size);
    }
    #[cfg(unix)]
    if let Some(mode) = attrs.permissions {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
    }
}
