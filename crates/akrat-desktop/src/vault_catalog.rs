use std::path::{Path, PathBuf};

pub fn load(default_path: &Path) -> Vec<PathBuf> {
    let mut paths = std::fs::read(catalog_path(default_path))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Vec<PathBuf>>(&bytes).ok())
        .unwrap_or_default();
    if paths.is_empty() {
        paths.insert(0, default_path.to_path_buf());
    }
    deduplicate(&mut paths);
    paths
}

pub fn save(default_path: &Path, paths: &[PathBuf]) -> Result<(), String> {
    let path = catalog_path(default_path);
    let parent = path
        .parent()
        .ok_or_else(|| "Dossier de configuration introuvable.".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("Impossible de créer le dossier de configuration : {error}"))?;
    let bytes = serde_json::to_vec(paths)
        .map_err(|error| format!("Impossible d’enregistrer la liste des coffres : {error}"))?;
    std::fs::write(path, bytes)
        .map_err(|error| format!("Impossible d’enregistrer la liste des coffres : {error}"))
}

pub fn add(paths: &mut Vec<PathBuf>, path: PathBuf) -> bool {
    if paths.iter().any(|existing| same_path(existing, &path)) {
        return false;
    }
    paths.push(path);
    true
}

pub fn remove(paths: &mut Vec<PathBuf>, path: &Path) {
    paths.retain(|existing| !same_path(existing, path));
}

pub fn replace(paths: &mut Vec<PathBuf>, old: &Path, new: PathBuf) -> bool {
    let Some(index) = paths.iter().position(|existing| same_path(existing, old)) else {
        return false;
    };
    paths[index] = new;
    deduplicate(paths);
    true
}

fn catalog_path(default_path: &Path) -> PathBuf {
    default_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("vaults.json")
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn deduplicate(paths: &mut Vec<PathBuf>) {
    let mut unique = Vec::with_capacity(paths.len());
    for path in paths.drain(..) {
        add(&mut unique, path);
    }
    *paths = unique;
}
