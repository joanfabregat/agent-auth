use crate::AppResult;
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub fn private_dir(path: &Path) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err("runtime and session directories must be owned, mode-0700 directories".into());
    }
    // Credentials and callback-control secrets must stay on a memory filesystem.
    if rustix::fs::statfs(path)?.f_type as u64 != 0x0102_1994 {
        return Err("runtime and session directories must be on tmpfs".into());
    }
    Ok(())
}

pub fn read_secret(path: &Path) -> AppResult<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > 64 * 1024
    {
        return Err("secret input must be an owned, mode-0600 regular file under 64 KiB".into());
    }
    private_dir(path.parent().ok_or("secret path has no parent")?)?;
    Ok(fs::read_to_string(path)?)
}

pub fn write_new(path: &Path, value: &[u8]) -> AppResult<()> {
    private_dir(path.parent().ok_or("secret path has no parent")?)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(value)?;
    file.sync_all()?;
    Ok(())
}

pub fn replace_secret(path: &Path, value: &[u8]) -> AppResult<()> {
    if !path.exists() {
        return write_new(path, value);
    }
    read_secret(path)?;
    let temporary = path.with_file_name(format!(
        ".replacement-{}",
        oauth2::CsrfToken::new_random().secret()
    ));
    let result = (|| {
        write_new(&temporary, value)?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_symlinks_loose_permissions_and_overwrites() {
        let dir = ["/dev/shm", "/tmp"]
            .into_iter()
            .find_map(|path| {
                tempfile::tempdir_in(path).ok().filter(|dir| {
                    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).is_ok()
                        && private_dir(dir.path()).is_ok()
                })
            })
            .expect("test requires writable tmpfs");
        let secret = dir.path().join("secret");
        write_new(&secret, b"fixture").unwrap();
        assert_eq!(read_secret(&secret).unwrap(), "fixture");
        assert!(write_new(&secret, b"replacement").is_err());
        replace_secret(&secret, b"rotated-fixture").unwrap();
        assert_eq!(read_secret(&secret).unwrap(), "rotated-fixture");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(read_secret(&link).is_err());
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secret(&secret).is_err());
    }
}
