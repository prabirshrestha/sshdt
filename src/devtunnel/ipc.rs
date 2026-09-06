use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(super) const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub(super) struct Endpoint {
    pub port: u16,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Request {
    pub version: u32,
    pub token: String,
    pub remote_port: u16,
    pub local_port: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Response {
    pub version: u32,
    pub error: Option<String>,
}

pub(super) fn directory() -> Result<PathBuf> {
    let root = super::logs::state_dir();
    fs::create_dir_all(&root)?;
    secure(&root)?;
    let path = root.join("brokers");
    fs::create_dir_all(&path)?;
    secure(&path)?;
    Ok(path)
}

pub(super) fn secure(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() || metadata.is_dir(),
        "broker path must be a regular file or directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() || metadata.is_dir(),
            "invalid broker path type"
        );
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "broker path has a different owner"
        );
        file.set_permissions(fs::Permissions::from_mode(if metadata.is_dir() {
            0o700
        } else {
            0o600
        }))?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "broker path must not be a reparse point"
        );
        windows_security::secure(path)?;
    }
    Ok(())
}

pub(super) fn read_endpoint(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "broker metadata must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0,
            "broker metadata is not private to this user"
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "broker metadata must not be a reparse point"
        );
    }
    ensure!(metadata.len() <= 4096, "broker metadata too large");
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "broker metadata too large");
    Ok(bytes)
}

pub(super) async fn send<T: Serialize>(stream: &mut TcpStream, message: &T) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    ensure!(bytes.len() <= 4096, "broker message too large");
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

pub(super) async fn receive<T: for<'a> Deserialize<'a>>(stream: &mut TcpStream) -> Result<T> {
    let length = stream.read_u32().await? as usize;
    ensure!(length <= 4096, "broker message too large");
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).context("invalid broker message")
}

#[cfg(windows)]
mod windows_security {
    use super::*;
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SE_FILE_OBJECT, SetNamedSecurityInfoW,
            },
            DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
            PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    pub(super) fn secure(path: &Path) -> Result<()> {
        unsafe {
            let mut token = ptr::null_mut();
            ensure!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0,
                "cannot read user token"
            );
            let mut length = 0;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut length);
            let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            );
            CloseHandle(token);
            ensure!(ok != 0, "cannot read user identity");
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            let mut sid = ptr::null_mut();
            ensure!(
                ConvertSidToStringSidW(user.User.Sid, &mut sid) != 0,
                "cannot format user identity"
            );
            let mut n = 0;
            while *sid.add(n) != 0 {
                n += 1;
            }
            let sid_text = String::from_utf16_lossy(std::slice::from_raw_parts(sid, n));
            LocalFree(sid.cast());
            let descriptor: Vec<u16> = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid_text})\0")
                .encode_utf16()
                .collect();
            let mut security = ptr::null_mut();
            ensure!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    descriptor.as_ptr(),
                    1,
                    &mut security,
                    ptr::null_mut()
                ) != 0,
                "cannot create broker security"
            );
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl = ptr::null_mut();
            let ok = GetSecurityDescriptorDacl(security, &mut present, &mut dacl, &mut defaulted);
            if ok == 0 {
                LocalFree(security);
                anyhow::bail!("cannot read broker security");
            }
            let mut name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let result = SetNamedSecurityInfoW(
                name.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            );
            LocalFree(security);
            ensure!(result == 0, "cannot restrict broker path access ({result})");
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn endpoint_reads_reject_links_public_files_and_oversized_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("endpoint");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_endpoint(&path).is_err());
        secure(&path).unwrap();
        assert_eq!(read_endpoint(&path).unwrap(), b"{}");
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_endpoint(&link).is_err());
        assert!(secure(&link).is_err());
        fs::write(&path, vec![0; 4097]).unwrap();
        assert!(read_endpoint(&path).is_err());
        assert!(read_endpoint(directory.path()).is_err());
    }
}
