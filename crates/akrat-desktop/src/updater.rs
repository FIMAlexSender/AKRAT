use serde::Deserialize;

#[cfg(all(
    feature = "desktop",
    not(feature = "mobile"),
    not(any(target_os = "android", target_os = "ios"))
))]
use sha2::{Digest, Sha256};

const RELEASES_API: &str = "https://api.github.com/repos/FIMAlexSender/AKRAT/releases?per_page=100";
const MAX_ARCHIVE_SIZE: u64 = 64 * 1024 * 1024;
#[cfg(all(
    feature = "desktop",
    not(feature = "mobile"),
    not(any(target_os = "android", target_os = "ios"))
))]
const MAX_EXECUTABLE_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct UpdateRelease {
    pub version: String,
    pub release_url: String,
    pub download_url: String,
    pub digest: String,
    pub size: u64,
    executable_name: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UpdateStatus {
    Checking,
    Current,
    Available(UpdateRelease),
    Installing,
    Failed(String),
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
    size: u64,
}

pub async fn check_latest() -> Result<Option<UpdateRelease>, String> {
    let target = platform_asset();
    let Some((asset_suffix, extension, executable_name)) = target else {
        return Ok(None);
    };

    let client = reqwest::Client::builder()
        .user_agent(concat!("AKRAT/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let releases = client
        .get(RELEASES_API)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|error| format!("GitHub inaccessible : {error}"))?
        .error_for_status()
        .map_err(|error| format!("GitHub a refusé la vérification : {error}"))?
        .json::<Vec<GithubRelease>>()
        .await
        .map_err(|error| format!("Réponse GitHub invalide : {error}"))?;

    let current_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("Version locale invalide : {error}"))?;
    let available = releases
        .into_iter()
        .filter_map(|release| {
            if release.prerelease {
                return None;
            }
            let version = semver::Version::parse(release.tag_name.trim_start_matches('v')).ok()?;
            if version <= current_version {
                return None;
            }
            let expected_name = format!("AKRAT-{}-{asset_suffix}.{extension}", release.tag_name);
            let asset = release
                .assets
                .into_iter()
                .find(|asset| asset.name == expected_name)?;
            let digest = asset
                .digest
                .filter(|digest| digest.starts_with("sha256:") && digest.len() == 71)?;
            if asset.size == 0 || asset.size > MAX_ARCHIVE_SIZE {
                return None;
            }
            Some((version, release, asset, digest))
        })
        .max_by(|left, right| left.0.cmp(&right.0));
    let Some((latest_version, release, asset, digest)) = available else {
        return Ok(None);
    };

    Ok(Some(UpdateRelease {
        version: latest_version.to_string(),
        release_url: release.html_url,
        download_url: asset.browser_download_url,
        digest,
        size: asset.size,
        executable_name,
    }))
}

#[cfg(all(
    feature = "desktop",
    not(feature = "mobile"),
    not(any(target_os = "android", target_os = "ios"))
))]
pub async fn install(release: UpdateRelease) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("AKRAT/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .get(&release.download_url)
        .timeout(std::time::Duration::from_secs(300))
        .send()
        .await
        .map_err(|error| format!("Téléchargement impossible : {error}"))?
        .error_for_status()
        .map_err(|error| format!("Téléchargement refusé : {error}"))?;
    if response
        .content_length()
        .is_some_and(|size| size != release.size)
    {
        return Err("La taille téléchargée ne correspond pas à la release.".into());
    }
    let archive = response
        .bytes()
        .await
        .map_err(|error| format!("Téléchargement interrompu : {error}"))?;
    if archive.len() as u64 != release.size {
        return Err("L’archive téléchargée est incomplète.".into());
    }
    let actual_digest = format!("sha256:{}", hex::encode(Sha256::digest(&archive)));
    if actual_digest != release.digest {
        return Err("La vérification SHA-256 a échoué ; la mise à jour a été annulée.".into());
    }

    let executable_name = release.executable_name;
    let executable = tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive))
            .map_err(|error| format!("Archive ZIP invalide : {error}"))?;
        let mut entry = zip
            .by_name(executable_name)
            .map_err(|error| format!("Exécutable absent de l’archive : {error}"))?;
        if entry.size() == 0 || entry.size() > MAX_EXECUTABLE_SIZE {
            return Err("La taille de l’exécutable est invalide.".to_string());
        }
        let expected_size = entry.size();
        let mut bytes = Vec::with_capacity(expected_size as usize);
        std::io::Read::take(&mut entry, MAX_EXECUTABLE_SIZE + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("Lecture de l’exécutable impossible : {error}"))?;
        if bytes.len() as u64 != expected_size {
            return Err("L’exécutable extrait est incomplet.".to_string());
        }
        validate_executable(&bytes)?;
        Ok::<_, String>(bytes)
    })
    .await
    .map_err(|error| format!("Extraction interrompue : {error}"))??;

    tokio::task::spawn_blocking(move || replace_and_restart(executable))
        .await
        .map_err(|error| format!("Installation interrompue : {error}"))??;
    Ok(())
}

#[cfg(not(all(
    feature = "desktop",
    not(feature = "mobile"),
    not(any(target_os = "android", target_os = "ios"))
)))]
pub async fn install(_release: UpdateRelease) -> Result<(), String> {
    Err("Android demande une confirmation système pour installer un APK ; téléchargez-le depuis la page de release.".into())
}

#[cfg(all(
    feature = "desktop",
    not(feature = "mobile"),
    not(any(target_os = "android", target_os = "ios"))
))]
fn replace_and_restart(executable: Vec<u8>) -> Result<(), String> {
    use std::io::Write;

    let current_exe = std::env::current_exe()
        .map_err(|error| format!("Chemin de l’application introuvable : {error}"))?;
    let parent = current_exe
        .parent()
        .ok_or_else(|| "Dossier de l’application introuvable.".to_string())?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    let staged = parent.join(format!(
        ".akrat-update-{}-{:x}.tmp",
        std::process::id(),
        u64::from_le_bytes(random)
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .map_err(|error| format!("Dossier d’installation non accessible : {error}"))?;
    file.write_all(&executable)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("Écriture de la mise à jour impossible : {error}"))?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&current_exe)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
    }

    if let Err(error) = self_replace::self_replace(&staged) {
        let _ = std::fs::remove_file(&staged);
        return Err(format!(
            "Remplacement de l’application impossible : {error}"
        ));
    }
    let _ = std::fs::remove_file(&staged);
    std::process::Command::new(&current_exe)
        .spawn()
        .map_err(|error| format!("Mise à jour installée, mais redémarrage impossible : {error}"))?;
    std::process::exit(0);
}

#[cfg(all(
    feature = "desktop",
    not(feature = "mobile"),
    not(any(target_os = "android", target_os = "ios"))
))]
fn validate_executable(bytes: &[u8]) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let valid = bytes.starts_with(b"MZ");
    #[cfg(target_os = "linux")]
    let valid = bytes.starts_with(b"\x7fELF");
    #[cfg(target_os = "macos")]
    let valid = matches!(
        bytes.get(..4),
        Some([0xfe, 0xed, 0xfa, 0xce])
            | Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xfe, 0xed, 0xfa, 0xcf])
            | Some([0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xca, 0xfe, 0xba, 0xbe])
            | Some([0xbe, 0xba, 0xfe, 0xca])
    );
    if valid {
        Ok(())
    } else {
        Err("Le fichier téléchargé n’est pas un exécutable AKRAT pour cette plateforme.".into())
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn platform_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("windows-x64", "zip", "akrat-desktop.exe"))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("linux-x64", "zip", "akrat-desktop"))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn platform_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("macos-aarch64", "zip", "akrat-desktop"))
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn platform_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("macos-x64", "zip", "akrat-desktop"))
}

#[cfg(target_os = "android")]
fn platform_asset() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("android", "apk", "app-debug.apk"))
}

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "x86_64"),
    all(
        target_os = "macos",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ),
    target_os = "android"
)))]
fn platform_asset() -> Option<(&'static str, &'static str, &'static str)> {
    None
}
