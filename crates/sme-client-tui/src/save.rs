//! "Save as" for decrypted images.
//!
//! The user-chosen path is the only allowed exit for image plaintext (plan.md §11).
//! The app data directory and the system temporary directory are rejected so the
//! application never leaves its own copy behind (I4/I11 canary locations).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum SaveError {
    Empty,
    NoFileName,
    MissingParent(PathBuf),
    Forbidden(PathBuf),
    AlreadyExists(PathBuf),
    Io(std::io::Error),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "path is empty"),
            Self::NoFileName => write!(f, "path has no file name"),
            Self::MissingParent(path) => write!(f, "directory does not exist: {}", path.display()),
            Self::Forbidden(path) => write!(
                f,
                "refusing to write inside the app data directory or the system temp directory: {}",
                path.display()
            ),
            Self::AlreadyExists(path) => write!(
                f,
                "file already exists (choose another name): {}",
                path.display()
            ),
            Self::Io(error) => write!(f, "write failed: {error}"),
        }
    }
}

impl std::error::Error for SaveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SaveError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Write decrypted image bytes to a user-chosen path.
///
/// `app_dir` is the directory holding the keystore; both it and [`std::env::temp_dir`]
/// are forbidden locations. Existing files are never overwritten: the user must pick
/// a new name, which also keeps the previous file from being clobbered by a typo.
pub fn save_image(input: &str, bytes: &[u8], app_dir: &Path) -> Result<PathBuf, SaveError> {
    save_image_with_roots(input, bytes, &[app_dir.to_path_buf(), std::env::temp_dir()])
}

fn save_image_with_roots(
    input: &str,
    bytes: &[u8],
    forbidden_roots: &[PathBuf],
) -> Result<PathBuf, SaveError> {
    let target = absolute_target(input)?;
    let parent = target.parent().ok_or(SaveError::NoFileName)?;
    let file_name = target.file_name().ok_or(SaveError::NoFileName)?;

    if !parent.is_dir() {
        return Err(SaveError::MissingParent(parent.to_path_buf()));
    }

    // Resolve `..` and symlinks once, then compare against both the lexical and the
    // canonical form of each root. The app directory may not exist before first login.
    let canonical_parent = std::fs::canonicalize(parent)?;
    let canonical_target = canonical_parent.join(file_name);
    for root in forbidden_roots {
        for form in comparison_forms(root) {
            if canonical_parent.starts_with(&form) {
                return Err(SaveError::Forbidden(canonical_target));
            }
        }
    }

    if canonical_target.exists() {
        return Err(SaveError::AlreadyExists(canonical_target));
    }

    write_new_file(&canonical_target, bytes)?;
    Ok(canonical_target)
}

fn absolute_target(input: &str) -> Result<PathBuf, SaveError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(SaveError::Empty);
    }

    let path = PathBuf::from(input);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn comparison_forms(path: &Path) -> Vec<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(current) => current.join(path),
            Err(_) => path.to_path_buf(),
        }
    };

    let mut forms = vec![absolute.clone()];
    if let Ok(canonical) = std::fs::canonicalize(&absolute)
        && canonical != absolute
    {
        forms.push(canonical);
    }
    forms
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), SaveError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Decrypted image plaintext: keep it readable only by the owner.
        options.mode(0o600);
    }

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(SaveError::AlreadyExists(path.to_path_buf()));
        }
        Err(error) => return Err(SaveError::Io(error)),
    };

    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(SaveError::Io(error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

    fn scratch_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sme-save-{}-{}-{name}",
            std::process::id(),
            NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        path
    }

    #[test]
    fn writes_exactly_the_decrypted_bytes() {
        let scratch = scratch_dir("write");
        let target = scratch.join("photo.jpg");
        let bytes = b"\xFF\xD8\xFF\xE0 decrypted image canary";

        let saved = save_image_with_roots(target.to_str().unwrap(), bytes, &[]).expect("save");

        assert_eq!(saved, target);
        assert_eq!(std::fs::read(&saved).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&saved).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn rejects_the_app_data_directory() {
        let scratch = scratch_dir("app-dir");
        let app_dir = scratch.join("app");
        std::fs::create_dir_all(&app_dir).unwrap();
        let target = app_dir.join("photo.jpg");

        let error = save_image_with_roots(target.to_str().unwrap(), b"x", &[app_dir])
            .expect_err("app dir must be rejected");

        assert!(matches!(error, SaveError::Forbidden(_)));
        assert!(!target.exists());
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn rejects_the_system_temp_directory_by_default() {
        let scratch = scratch_dir("temp-dir");
        let target = scratch.join("photo.jpg");

        let error = save_image(target.to_str().unwrap(), b"x", &scratch.join("app"))
            .expect_err("temp dir must be rejected");

        assert!(matches!(error, SaveError::Forbidden(_)));
        assert!(!target.exists());
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn rejects_traversal_into_the_app_data_directory() {
        let scratch = scratch_dir("traversal");
        let app_dir = scratch.join("app");
        std::fs::create_dir_all(&app_dir).unwrap();
        let target = scratch
            .join("elsewhere")
            .join("..")
            .join("app")
            .join("photo.jpg");
        std::fs::create_dir_all(scratch.join("elsewhere")).unwrap();

        let error = save_image_with_roots(target.to_str().unwrap(), b"x", &[app_dir])
            .expect_err("resolved app dir must be rejected");

        assert!(matches!(error, SaveError::Forbidden(_)));
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn never_overwrites_an_existing_file() {
        let scratch = scratch_dir("overwrite");
        let target = scratch.join("photo.jpg");
        std::fs::write(&target, b"original").unwrap();

        let error = save_image_with_roots(target.to_str().unwrap(), b"new", &[])
            .expect_err("existing file must be rejected");

        assert!(matches!(error, SaveError::AlreadyExists(_)));
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn rejects_a_missing_parent_directory() {
        let scratch = scratch_dir("missing-parent");
        let target = scratch.join("no-such-dir").join("photo.jpg");

        let error = save_image_with_roots(target.to_str().unwrap(), b"x", &[])
            .expect_err("missing parent must be rejected");

        assert!(matches!(error, SaveError::MissingParent(_)));
        std::fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(
            save_image_with_roots("   ", b"x", &[]),
            Err(SaveError::Empty)
        ));
    }
}
