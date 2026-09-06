use anyhow::{Context, Result};
use fs4::FileExt;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Arc,
};

pub fn state_dir() -> PathBuf {
    std::env::var_os("SSHDT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".sshdt")
        })
}

#[derive(Clone)]
pub struct Log {
    prefix: Arc<str>,
}

impl Log {
    pub fn new(role: &str) -> Result<Self> {
        let prefix = match role {
            "host" => "devtunnel",
            "client" => "devtunnel-client",
            _ => anyhow::bail!("unknown tunnel log role"),
        };
        fs::create_dir_all(state_dir().join("logs"))?;
        Ok(Self {
            prefix: prefix.into(),
        })
    }

    pub fn write(&self, command: &str, stream: &str, text: &str) {
        if let Err(error) = self.append(command, stream, text) {
            tracing::warn!(%error, "cannot write Dev Tunnel log");
        }
    }

    fn append(&self, command: &str, stream: &str, text: &str) -> Result<()> {
        let dir = state_dir().join("logs");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join(format!("{}.lock", self.prefix)))?;
        FileExt::lock(&lock)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let date = date(now / 86400);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(format!("{}.{date}.log", self.prefix)))?;
        writeln!(
            file,
            "{now} [{}] [{}] {}",
            sanitize(command),
            sanitize(stream),
            sanitize(text)
        )?;
        let mut files: Vec<_> = fs::read_dir(&dir)?
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(&format!("{}.", self.prefix)) && name.ends_with(".log")
            })
            .map(|entry| entry.path())
            .collect();
        files.sort();
        let excess = files.len().saturating_sub(7);
        for path in files.into_iter().take(excess) {
            fs::remove_file(path).context("prune tunnel log")?;
        }
        FileExt::unlock(&lock)?;
        Ok(())
    }
}

pub fn sanitize(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if [
        "token",
        "authorization",
        "password",
        "secret",
        "credential",
        "eyj",
    ]
    .iter()
    .any(|key| lower.contains(key))
    {
        return "[credential-bearing output omitted]".into();
    }
    text.split_whitespace()
        .map(|word| {
            if word.contains("://") {
                "[URL omitted]".to_string()
            } else {
                word.chars()
                    .filter(|c| !c.is_control())
                    .take(2048)
                    .collect()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(8192)
        .collect()
}

fn date(days: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp((days * 86400) as i64)
        .expect("current timestamp fits calendar")
        .date()
        .to_string()
}

pub fn show(role: &str, follow: bool) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let prefix = match role {
        "host" => "devtunnel",
        "client" => "devtunnel-client",
        _ => anyhow::bail!("unknown tunnel log role"),
    };
    let dir = state_dir().join("logs");
    let mut current = PathBuf::new();
    let mut offset = 0;
    loop {
        let mut files = match fs::read_dir(&dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|path| {
                    path.file_name().is_some_and(|name| {
                        let name = name.to_string_lossy();
                        name.starts_with(&format!("{prefix}.")) && name.ends_with(".log")
                    })
                })
                .collect::<Vec<_>>(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        files.sort();
        if let Some(path) = files.last() {
            if *path != current {
                current = path.clone();
                offset = 0;
            }
            let mut file = fs::File::open(&current)?;
            if file.metadata()?.len() < offset {
                offset = 0;
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            offset += data.len() as u64;
            std::io::stdout().write_all(&data)?;
            std::io::stdout().flush()?;
        } else if !follow {
            println!("No Dev Tunnel {role} logs found.");
        }
        if !follow {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dates_and_secrets() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(
            sanitize("Authorization: Bearer abc"),
            "[credential-bearing output omitted]"
        );
        assert_eq!(
            sanitize("visit https://a.example/?key=private"),
            "visit [URL omitted]"
        );
        assert_eq!(sanitize("Hosting port: 2222"), "Hosting port: 2222");
    }
}
