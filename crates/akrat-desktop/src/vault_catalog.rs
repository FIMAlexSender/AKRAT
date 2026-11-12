use akrat_core::VaultFileLock;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default)]
pub struct CatalogLoad {
    pub paths: Vec<PathBuf>,
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogDocument {
    version: u8,
    selected: Option<String>,
    entries: Vec<CatalogEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogEntry {
    id: String,
    path: PathBuf,
    #[serde(default)]
    last_used: Option<u64>,
}

pub fn load(default_path: &Path) -> CatalogLoad {
    let path = catalog_path(default_path);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(mut document) = serde_json::from_slice::<CatalogDocument>(&bytes)
            && document.version == 1
        {
            normalize_document(&mut document);
            return CatalogLoad {
                paths: ordered_paths(document),
                warning: None,
            };
        }
        if let Ok(legacy) = serde_json::from_slice::<Vec<PathBuf>>(&bytes) {
            let paths = deduplicated(legacy);
            return CatalogLoad {
                paths,
                warning: None,
            };
        }
    }
    let backup = backup_path(&path);
    if let Ok(backup_bytes) = std::fs::read(&backup) {
        if let Ok(document) = serde_json::from_slice::<CatalogDocument>(&backup_bytes) {
            return CatalogLoad {
                paths: ordered_paths(document),
                warning: Some(format!(
                    "Catalogue endommagé ; copie de récupération chargée. Le fichier d’origine est conservé : {}",
                    path.display()
                )),
            };
        }
        if let Ok(paths) = serde_json::from_slice::<Vec<PathBuf>>(&backup_bytes) {
            return CatalogLoad {
                paths: deduplicated(paths),
                warning: Some(format!(
                    "Catalogue endommagé ; ancienne copie chargée. Le fichier d’origine est conservé : {}",
                    path.display()
                )),
            };
        }
    }
    if path.exists() {
        CatalogLoad {
            paths: Vec::new(),
            warning: Some(format!(
                "Le catalogue des coffres est illisible. Aucun coffre n’a été modifié. Réimportez vos fichiers .akrat. ({})",
                path.display()
            )),
        }
    } else {
        CatalogLoad::default()
    }
}

pub fn save(default_path: &Path, paths: &[PathBuf]) -> Result<(), String> {
    let path = catalog_path(default_path);
    let _catalog_lock = VaultFileLock::acquire(&path)
        .map_err(|error| format!("Impossible de verrouiller le catalogue des coffres : {error}"))?;
    let previous = load(default_path).paths;
    let mut entries = Vec::new();
    for (index, entry_path) in deduplicated(paths.to_vec()).into_iter().enumerate() {
        let id = previous
            .iter()
            .position(|old| same_path(old, &entry_path))
            .and_then(|old_index| read_entry_id(&path, old_index))
            .unwrap_or_else(random_id);
        entries.push(CatalogEntry {
            id,
            path: entry_path,
            last_used: if index == 0 { Some(unix_time()) } else { None },
        });
    }
    let document = CatalogDocument {
        version: 1,
        selected: entries.first().map(|entry| entry.id.clone()),
        entries,
    };
    write_document(&path, &document)
}

pub fn replace_and_save(
    default_path: &Path,
    old: &Path,
    new: PathBuf,
) -> Result<Vec<PathBuf>, String> {
    let path = catalog_path(default_path);
    let _catalog_lock = VaultFileLock::acquire(&path)
        .map_err(|error| format!("Impossible de verrouiller le catalogue des coffres : {error}"))?;
    let mut document = read_document(&path).unwrap_or_else(|| {
        let paths = load(default_path).paths;
        CatalogDocument {
            version: 1,
            selected: None,
            entries: paths
                .into_iter()
                .map(|path| CatalogEntry {
                    id: random_id(),
                    path,
                    last_used: None,
                })
                .collect(),
        }
    });
    normalize_document(&mut document);
    let Some(index) = document
        .entries
        .iter()
        .position(|entry| same_path(&entry.path, old))
    else {
        return Err("Ce coffre n’est plus enregistré dans le catalogue.".into());
    };
    if document
        .entries
        .iter()
        .enumerate()
        .any(|(entry_index, entry)| entry_index != index && same_path(&entry.path, &new))
    {
        return Err("Un autre coffre utilise déjà cet emplacement.".into());
    }
    document.entries[index].path = new;
    write_document(&path, &document)?;
    Ok(ordered_paths(document))
}

pub fn add(paths: &mut Vec<PathBuf>, path: PathBuf) -> bool {
    if paths.iter().any(|existing| same_path(existing, &path)) {
        return false;
    }
    paths.insert(0, path);
    true
}

pub fn select(paths: &mut Vec<PathBuf>, path: &Path) -> bool {
    let Some(index) = paths.iter().position(|entry| same_path(entry, path)) else {
        return false;
    };
    if index > 0 {
        let selected = paths.remove(index);
        paths.insert(0, selected);
    }
    true
}

#[cfg(test)]
pub fn id_for_path(default_path: &Path, path: &Path) -> Option<String> {
    let bytes = std::fs::read(catalog_path(default_path)).ok()?;
    let document: CatalogDocument = serde_json::from_slice(&bytes).ok()?;
    document
        .entries
        .iter()
        .find(|entry| same_path(&entry.path, path))
        .map(|entry| entry.id.clone())
}

pub fn remove(paths: &mut Vec<PathBuf>, path: &Path) {
    paths.retain(|existing| !same_path(existing, path));
}

pub fn preferred_existing_path(paths: &[PathBuf]) -> Option<PathBuf> {
    paths
        .first()
        .filter(|path| path.is_file())
        .or_else(|| paths.iter().find(|path| path.is_file()))
        .cloned()
}

pub fn replace(paths: &mut Vec<PathBuf>, old: &Path, new: PathBuf) -> bool {
    let Some(index) = paths.iter().position(|existing| same_path(existing, old)) else {
        return false;
    };
    paths[index] = new;
    *paths = deduplicated(std::mem::take(paths));
    true
}

fn catalog_path(default_path: &Path) -> PathBuf {
    default_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("vaults.json")
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("json.bak")
}

fn read_document(path: &Path) -> Option<CatalogDocument> {
    let bytes = std::fs::read(path).ok()?;
    if let Ok(document) = serde_json::from_slice::<CatalogDocument>(&bytes)
        && document.version == 1
    {
        return Some(document);
    }
    let paths = serde_json::from_slice::<Vec<PathBuf>>(&bytes).ok()?;
    Some(CatalogDocument {
        version: 1,
        selected: None,
        entries: deduplicated(paths)
            .into_iter()
            .map(|path| CatalogEntry {
                id: random_id(),
                path,
                last_used: None,
            })
            .collect(),
    })
}

fn write_document(path: &Path, document: &CatalogDocument) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Dossier de configuration introuvable.".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("Impossible de créer le dossier de configuration : {error}"))?;
    let bytes = serde_json::to_vec_pretty(document)
        .map_err(|error| format!("Impossible d’encoder la liste des coffres : {error}"))?;
    atomic_write(path, &bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write_with_interruption(path, bytes, false)
}

fn atomic_write_with_interruption(
    path: &Path,
    bytes: &[u8],
    interrupt_before_replace: bool,
) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".vaults-{}-{sequence}.tmp", std::process::id()));
    let backup = backup_path(path);
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let verification = std::fs::read(&temporary)?;
        if verification != bytes {
            return Err(std::io::Error::other(
                "temporary catalogue verification failed",
            ));
        }
        if path.exists() {
            if is_readable_catalog(path) || !backup.exists() {
                std::fs::copy(path, &backup)?;
                let backup_file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&backup)?;
                backup_file.sync_all()?;
            }
            #[cfg(not(windows))]
            std::fs::File::open(parent)?.sync_all()?;
        }
        if interrupt_before_replace {
            return Err(std::io::Error::other(
                "injected interruption before replace",
            ));
        }
        replace_file(&temporary, path)?;
        #[cfg(not(windows))]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write_result
        .map_err(|error| format!("Impossible d’enregistrer le catalogue des coffres : {error}"))
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn is_readable_catalog(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    serde_json::from_slice::<CatalogDocument>(&bytes).is_ok_and(|document| document.version == 1)
        || serde_json::from_slice::<Vec<PathBuf>>(&bytes).is_ok()
}

fn read_entry_id(path: &Path, old_index: usize) -> Option<String> {
    let document: CatalogDocument = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    document
        .entries
        .get(old_index)
        .map(|entry| entry.id.clone())
}

fn normalize_document(document: &mut CatalogDocument) {
    let selected_index = document.selected.as_ref().and_then(|selected| {
        document
            .entries
            .iter()
            .position(|entry| &entry.id == selected)
    });
    if let Some(index) = selected_index {
        document.entries.swap(0, index);
    }
    let mut seen = Vec::<PathBuf>::new();
    document.entries.retain(|entry| {
        if seen.iter().any(|path| same_path(path, &entry.path)) {
            false
        } else {
            seen.push(entry.path.clone());
            true
        }
    });
}

fn ordered_paths(document: CatalogDocument) -> Vec<PathBuf> {
    let mut document = document;
    normalize_document(&mut document);
    document
        .entries
        .into_iter()
        .map(|entry| entry.path)
        .collect()
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        bytes[..8].copy_from_slice(&unix_time().to_le_bytes());
        bytes[8..].copy_from_slice(&TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    }
    hex::encode(bytes)
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ if cfg!(windows) => left
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy()),
        _ => left == right,
    }
}

fn deduplicated(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut unique: Vec<PathBuf> = Vec::with_capacity(paths.len());
    for path in paths {
        if !unique.iter().any(|existing| same_path(existing, &path)) {
            unique.push(path);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn default_path(directory: &Path) -> PathBuf {
        directory.join("default.akrat")
    }

    #[test]
    fn empty_catalog_does_not_invent_a_vault() {
        let directory = tempdir().unwrap();
        let state = load(&default_path(directory.path()));
        assert!(state.paths.is_empty());
        assert!(state.warning.is_none());
    }

    #[test]
    fn migrates_legacy_path_list_and_saves_versioned_catalog() {
        let directory = tempdir().unwrap();
        let default = default_path(directory.path());
        let one = directory.path().join("one.akrat");
        let two = directory.path().join("two.akrat");
        std::fs::write(
            catalog_path(&default),
            serde_json::to_vec(&vec![&one, &two]).unwrap(),
        )
        .unwrap();
        let loaded = load(&default);
        assert_eq!(loaded.paths, vec![one.clone(), two.clone()]);
        save(&default, &[two.clone(), one.clone()]).unwrap();
        let document: CatalogDocument =
            serde_json::from_slice(&std::fs::read(catalog_path(&default)).unwrap()).unwrap();
        assert_eq!(document.version, 1);
        assert_eq!(document.entries[0].path, two);
        assert_eq!(load(&default).paths[0], document.entries[0].path);
    }

    #[test]
    fn damaged_catalog_is_preserved_and_recovery_copy_is_used() {
        let directory = tempdir().unwrap();
        let default = default_path(directory.path());
        let valid = CatalogDocument {
            version: 1,
            selected: None,
            entries: vec![CatalogEntry {
                id: "test".into(),
                path: PathBuf::from("portable.akrat"),
                last_used: None,
            }],
        };
        std::fs::write(
            backup_path(&catalog_path(&default)),
            serde_json::to_vec(&valid).unwrap(),
        )
        .unwrap();
        std::fs::write(catalog_path(&default), b"{broken").unwrap();
        let loaded = load(&default);
        assert_eq!(loaded.paths, vec![PathBuf::from("portable.akrat")]);
        assert!(loaded.warning.is_some());
        assert_eq!(std::fs::read(catalog_path(&default)).unwrap(), b"{broken");
    }

    #[test]
    fn interruption_before_catalogue_replacement_keeps_main_file_and_recovery_copy() {
        let directory = tempdir().unwrap();
        let default = default_path(directory.path());
        let selected = directory.path().join("selected.akrat");
        save(&default, std::slice::from_ref(&selected)).unwrap();
        let path = catalog_path(&default);
        let previous = std::fs::read(&path).unwrap();
        assert!(atomic_write_with_interruption(&path, b"replacement", true).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), previous);
        assert_eq!(std::fs::read(backup_path(&path)).unwrap(), previous);
        assert_eq!(load(&default).paths, vec![selected]);
    }

    #[test]
    fn two_damaged_catalogue_copies_are_preserved_without_inventing_or_deleting_vaults() {
        let directory = tempdir().unwrap();
        let default = default_path(directory.path());
        let path = catalog_path(&default);
        let backup = backup_path(&path);
        std::fs::write(&path, b"damaged main").unwrap();
        std::fs::write(&backup, b"damaged recovery copy").unwrap();
        let loaded = load(&default);
        assert!(loaded.paths.is_empty());
        assert!(loaded.warning.is_some());
        assert_eq!(std::fs::read(&path).unwrap(), b"damaged main");
        assert_eq!(std::fs::read(&backup).unwrap(), b"damaged recovery copy");
    }

    #[test]
    fn saving_after_corruption_keeps_the_recovery_copy() {
        let directory = tempdir().unwrap();
        let default = default_path(directory.path());
        let recovered_path = PathBuf::from("portable.akrat");
        let valid = CatalogDocument {
            version: 1,
            selected: None,
            entries: vec![CatalogEntry {
                id: "stable-id".into(),
                path: recovered_path.clone(),
                last_used: None,
            }],
        };
        let backup = backup_path(&catalog_path(&default));
        std::fs::write(&backup, serde_json::to_vec(&valid).unwrap()).unwrap();
        std::fs::write(catalog_path(&default), b"{broken").unwrap();
        save(
            &default,
            &[recovered_path.clone(), PathBuf::from("new.akrat")],
        )
        .unwrap();
        let retained: CatalogDocument =
            serde_json::from_slice(&std::fs::read(backup).unwrap()).unwrap();
        assert_eq!(retained.entries[0].path, recovered_path);
        assert_eq!(load(&default).paths.len(), 2);
    }

    #[test]
    fn deduplicates_paths_and_keeps_missing_external_paths() {
        let directory = tempdir().unwrap();
        let default = default_path(directory.path());
        let missing = PathBuf::from("Z:/external/portable.akrat");
        save(&default, &[missing.clone(), missing.clone()]).unwrap();
        assert_eq!(load(&default).paths, vec![missing]);
    }

    #[test]
    fn replacement_preserves_selection_order() {
        let mut paths = vec![PathBuf::from("first.akrat"), PathBuf::from("second.akrat")];
        assert!(replace(
            &mut paths,
            Path::new("first.akrat"),
            PathBuf::from("renamed.akrat")
        ));
        assert_eq!(paths[0], PathBuf::from("renamed.akrat"));
    }

    #[test]
    fn selecting_a_vault_persists_it_as_the_startup_preference() {
        let mut paths = vec![PathBuf::from("first.akrat"), PathBuf::from("second.akrat")];
        assert!(select(&mut paths, Path::new("second.akrat")));
        assert_eq!(paths[0], PathBuf::from("second.akrat"));
        assert!(!select(&mut paths, Path::new("unknown.akrat")));
    }

    #[test]
    fn startup_uses_last_selected_file_or_first_available_entry() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("first.akrat");
        let selected = directory.path().join("selected.akrat");
        std::fs::write(&first, b"vault").unwrap();
        std::fs::write(&selected, b"vault").unwrap();
        assert_eq!(
            preferred_existing_path(&[selected.clone(), first.clone()]),
            Some(selected)
        );
        assert_eq!(
            preferred_existing_path(&[PathBuf::from("missing.akrat"), first.clone()]),
            Some(first)
        );
        assert_eq!(
            preferred_existing_path(&[PathBuf::from("missing.akrat")]),
            None
        );
    }
}
