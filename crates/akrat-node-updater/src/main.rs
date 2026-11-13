use akrat_trust::{
    RELEASE_REPOSITORY, ReleaseAttestation, VerifiedDistribution, verify_attested_artifact,
    verify_official_release_attestation,
};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_METADATA_BYTES: usize = 1_048_576;
const MAX_SIGNATURE_BYTES: usize = 256;
const MAX_BINARY_BYTES: usize = 128 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "akrat-node-updater",
    version,
    about = "Mise à jour authentifiée des nœuds AKRAT"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    Apply {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        approve: bool,
    },
    Auto {
        #[arg(long)]
        config: PathBuf,
    },
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        asset_name: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Channel {
    Stable,
    Experimental,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Policy {
    Manual,
    Approval,
    Automatic,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Component {
    Mailbox,
    Relay,
    IrohRelay,
}

impl Component {
    fn asset_name(self, tag: &str) -> String {
        let suffix = match self {
            Self::Mailbox => "mailbox-linux-x64",
            Self::Relay => "relay-linux-x64",
            Self::IrohRelay => "iroh-relay-linux-x64",
        };
        format!("AKRAT-{tag}-{suffix}")
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::Mailbox => "akrat-mailbox",
            Self::Relay => "akrat-relay",
            Self::IrohRelay => "iroh-relay",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    install_dir: PathBuf,
    service: String,
    components: Vec<Component>,
    channel: Channel,
    policy: Policy,
    maintenance_start_hour: u8,
    maintenance_end_hour: u8,
    #[serde(default)]
    mailbox_config: Option<PathBuf>,
    #[serde(default)]
    relay_health_url: Option<String>,
    #[serde(default)]
    database_backups: Option<PathBuf>,
    #[serde(default)]
    sqlite_databases: Vec<PathBuf>,
    #[serde(default)]
    allow_mailbox_auto_update: bool,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubAsset {
    name: String,
    url: String,
    size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: String,
    installed_at_unix_seconds: u64,
    components: Vec<String>,
}

#[derive(Debug)]
struct Candidate {
    tag: String,
    distribution: VerifiedDistribution,
    assets: BTreeMap<Component, GithubAsset>,
    attestation_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify {
            manifest,
            signature,
            artifact,
            asset_name,
        } => {
            verify_files(&manifest, &signature, &artifact, &asset_name)?;
            println!("Attestation, artefact et empreinte vérifiés.");
        }
        Command::Check { config } => {
            let config = load_config(&config)?;
            if let Some(candidate) = latest_candidate(&config).await? {
                println!(
                    "Mise à jour authentifiée disponible : {} ({})",
                    candidate.distribution.version, candidate.tag
                );
            } else {
                println!("Aucune mise à jour stable admissible.");
            }
        }
        Command::Apply { config, approve } => {
            let config = load_config(&config)?;
            if !approve {
                return Err(
                    "L’application manuelle exige --approve après le contrôle de la version."
                        .into(),
                );
            }
            apply(&config).await?;
        }
        Command::Auto { config } => {
            let config = load_config(&config)?;
            validate_auto(&config)?;
            if !maintenance_window_open(&config) {
                println!("Hors fenêtre de maintenance ; vérification reportée.");
                return Ok(());
            }
            apply(&config).await?;
        }
    }
    Ok(())
}

fn validate_auto(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.policy != Policy::Automatic || config.channel != Channel::Stable {
        return Err("Le mode automatique exige policy=automatic et channel=stable.".into());
    }
    if config.components.contains(&Component::Mailbox) && !config.allow_mailbox_auto_update {
        return Err("Mailbox automatique désactivée : validez explicitement les migrations de schéma avec allow_mailbox_auto_update.".into());
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() > 65_536 {
        return Err("Configuration trop volumineuse.".into());
    }
    let config: Config = serde_json::from_slice(&bytes)?;
    if config.install_dir.as_os_str().is_empty()
        || config.service.is_empty()
        || config.service.len() > 128
        || !config.service.starts_with("akrat-")
        || config.service.starts_with('-')
        || !config
            .service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.@:-".contains(&byte))
        || config.components.is_empty()
        || config.components.len() > 3
        || config
            .components
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.components.len()
        || config.maintenance_start_hour > 23
        || config.maintenance_end_hour > 23
    {
        return Err("Configuration de nœud invalide.".into());
    }
    if config.components.contains(&Component::Mailbox)
        && (config.mailbox_config.is_none()
            || config.database_backups.is_none()
            || config.sqlite_databases.is_empty())
    {
        return Err("La mise à jour Mailbox exige son fichier de configuration et les chemins des bases SQLite à sauvegarder.".into());
    }
    if config.components.contains(&Component::Relay) && config.relay_health_url.is_none() {
        return Err("La mise à jour Relay exige une URL locale de contrôle /health.".into());
    }
    let database_names = config
        .sqlite_databases
        .iter()
        .filter_map(|path| path.file_name())
        .collect::<std::collections::BTreeSet<_>>();
    if database_names.len() != config.sqlite_databases.len() {
        return Err("Les chemins SQLite doivent avoir des noms de fichiers distincts.".into());
    }
    Ok(config)
}

fn maintenance_window_open(config: &Config) -> bool {
    if config.maintenance_start_hour == config.maintenance_end_hour {
        return true;
    }
    let hour = chrono::Local::now().hour() as u8;
    if config.maintenance_start_hour < config.maintenance_end_hour {
        (config.maintenance_start_hour..config.maintenance_end_hour).contains(&hour)
    } else {
        hour >= config.maintenance_start_hour || hour < config.maintenance_end_hour
    }
}

use chrono::Timelike;

fn client() -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("AKRAT-node-updater/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?)
}

fn api_url() -> String {
    format!("https://api.github.com/repos/{RELEASE_REPOSITORY}")
}

fn authorize(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match std::env::var("AKRAT_GITHUB_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(token) => request.header(AUTHORIZATION, format!("Bearer {token}")),
        None => request,
    }
}

async fn limited_bytes(
    response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut response = response.error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > max as u64)
    {
        return Err("Réponse distante trop volumineuse.".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > max)
        {
            return Err("Réponse distante trop volumineuse.".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn trusted_asset_url(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = reqwest::Url::parse(value)?;
    if url.scheme() != "https"
        || url.host_str() != Some("api.github.com")
        || url.username() != ""
        || url.password().is_some()
        || !url
            .path()
            .starts_with(&format!("/repos/{RELEASE_REPOSITORY}/releases/assets/"))
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("URL d’asset GitHub hors du dépôt officiel.".into());
    }
    Ok(())
}

async fn latest_candidate(
    config: &Config,
) -> Result<Option<Candidate>, Box<dyn std::error::Error>> {
    let client = client()?;
    let url = format!("{}/releases?per_page=100", api_url().trim_end_matches('/'));
    let releases: Vec<GithubRelease> = serde_json::from_slice(
        &limited_bytes(authorize(client.get(url)).send().await?, 8 * 1024 * 1024).await?,
    )?;
    let current = if state_path(&config.install_dir).exists() {
        Some(semver::Version::parse(
            &read_state(&config.install_dir)?.version,
        )?)
    } else {
        Some(semver::Version::parse(env!("CARGO_PKG_VERSION"))?)
    };
    let mut candidates = releases
        .into_iter()
        .filter(|release| {
            !release.draft
                && match config.channel {
                    Channel::Stable => {
                        !release.prerelease
                            && semver::Version::parse(release.tag_name.trim_start_matches('v'))
                                .is_ok_and(|v| v.pre.is_empty())
                    }
                    Channel::Experimental => true,
                }
        })
        .filter_map(|release| {
            let version = semver::Version::parse(release.tag_name.trim_start_matches('v')).ok()?;
            if current
                .as_ref()
                .is_some_and(|installed| version <= *installed)
            {
                return None;
            }
            Some((version, release))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| right.0.cmp(&left.0));
    for (_, release) in candidates {
        if let Some(candidate) = candidate_from_release(config, &client, release).await? {
            return Ok(Some(candidate));
        }
        if config.channel == Channel::Stable {
            continue;
        }
    }
    Ok(None)
}

async fn candidate_from_release(
    config: &Config,
    client: &reqwest::Client,
    release: GithubRelease,
) -> Result<Option<Candidate>, Box<dyn std::error::Error>> {
    let tag = release.tag_name;
    let manifest_name = format!("AKRAT-{tag}-release-attestation.json");
    let signature_name = format!("AKRAT-{tag}-release-attestation.sig");
    let Some(manifest_asset) = release
        .assets
        .iter()
        .find(|asset| asset.name == manifest_name)
    else {
        return Ok(None);
    };
    let Some(signature_asset) = release
        .assets
        .iter()
        .find(|asset| asset.name == signature_name)
    else {
        return Ok(None);
    };
    trusted_asset_url(&manifest_asset.url)?;
    trusted_asset_url(&signature_asset.url)?;
    let manifest_bytes = limited_bytes(
        authorize(
            client
                .get(&manifest_asset.url)
                .header(ACCEPT, "application/octet-stream"),
        )
        .send()
        .await?,
        MAX_METADATA_BYTES,
    )
    .await?;
    let signature_bytes = limited_bytes(
        authorize(
            client
                .get(&signature_asset.url)
                .header(ACCEPT, "application/octet-stream"),
        )
        .send()
        .await?,
        MAX_SIGNATURE_BYTES,
    )
    .await?;
    let attestation: ReleaseAttestation = serde_json::from_slice(&manifest_bytes)?;
    let signature = std::str::from_utf8(&signature_bytes)?.trim();
    let distribution = verify_official_release_attestation(&attestation, signature)?;
    if distribution.tag != tag || distribution.version != tag.trim_start_matches('v') {
        return Err("Attestation non liée au tag publié.".into());
    }
    let mut assets = BTreeMap::new();
    for component in &config.components {
        let name = component.asset_name(&tag);
        let Some(asset) = release.assets.iter().find(|asset| asset.name == name) else {
            return Ok(None);
        };
        trusted_asset_url(&asset.url)?;
        if asset.size == 0 || asset.size > MAX_BINARY_BYTES as u64 {
            return Err(format!("Taille invalide pour {name}.").into());
        }
        let declared_hash = distribution
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .map(|asset| asset.sha256.as_str());
        if declared_hash.is_none() {
            return Err(format!("Artefact absent de l’attestation : {name}").into());
        }
        assets.insert(*component, asset.clone());
    }
    Ok(Some(Candidate {
        tag,
        distribution,
        assets,
        attestation_bytes: manifest_bytes,
        signature_bytes,
    }))
}

async fn apply(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let lock = acquire_lock(&config.install_dir)?;
    let Some(candidate) = latest_candidate(config).await? else {
        println!("Aucune mise à jour authentifiée disponible.");
        return Ok(());
    };
    let client = client()?;
    let mut staged = Vec::new();
    for (component, asset) in &candidate.assets {
        let bytes = limited_bytes(
            authorize(
                client
                    .get(&asset.url)
                    .header(ACCEPT, "application/octet-stream"),
            )
            .send()
            .await?,
            MAX_BINARY_BYTES,
        )
        .await?;
        if bytes.len() as u64 != asset.size {
            return Err(format!("Taille téléchargée invalide : {}.", asset.name).into());
        }
        let hash = hex::encode(Sha256::digest(&bytes));
        verify_attested_artifact(&candidate.distribution, &asset.name, &hash)?;
        if !bytes.starts_with(b"\x7fELF") {
            return Err(format!("Binaire Linux invalide : {}.", asset.name).into());
        }
        staged.push((*component, bytes));
    }
    let database_backup = if config.components.contains(&Component::Mailbox) {
        systemctl(config, "stop")?;
        match backup_databases(config, &candidate.distribution.version) {
            Ok(path) => Some(path),
            Err(error) => {
                return match systemctl(config, "restart") {
                    Ok(()) => Err(error),
                    Err(restart_error) => Err(format!("Sauvegarde SQLite échouée : {error}. Le service n’a pas pu redémarrer : {restart_error}").into()),
                };
            }
        }
    } else {
        None
    };
    install_transaction(config, &candidate, staged, database_backup.as_deref())?;
    drop(lock);
    println!(
        "Version {} installée et service {} actif.",
        candidate.distribution.version, config.service
    );
    Ok(())
}

fn acquire_lock(dir: &Path) -> Result<std::fs::File, Box<dyn std::error::Error>> {
    if !dir.is_absolute() {
        return Err("Le répertoire d’installation doit être absolu.".into());
    }
    std::fs::create_dir_all(dir)?;
    if std::fs::canonicalize(dir)? != dir {
        return Err("Le répertoire d’installation ne peut contenir de lien symbolique ou de segments relatifs.".into());
    }
    let lock_path = dir.join(".akrat-update.lock");
    if let Ok(metadata) = std::fs::symlink_metadata(&lock_path)
        && !metadata.file_type().is_file()
    {
        return Err("Le verrou de mise à jour doit être un fichier régulier.".into());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    file.try_lock_exclusive()
        .map_err(|_| "Une autre mise à jour est déjà en cours.")?;
    Ok(file)
}

fn install_transaction(
    config: &Config,
    candidate: &Candidate,
    binaries: Vec<(Component, Vec<u8>)>,
    database_backup: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut systemd = SystemdControl { config };
    install_transaction_with(config, candidate, binaries, database_backup, &mut systemd)
}

trait ServiceControl {
    fn command(&mut self, command: &str) -> Result<(), Box<dyn std::error::Error>>;
    fn wait_ready(&mut self, timeout: Duration) -> Result<bool, Box<dyn std::error::Error>>;
    fn health(&mut self) -> Result<(), Box<dyn std::error::Error>>;
}

struct SystemdControl<'a> {
    config: &'a Config,
}

impl ServiceControl for SystemdControl<'_> {
    fn command(&mut self, command: &str) -> Result<(), Box<dyn std::error::Error>> {
        systemctl(self.config, command)
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<bool, Box<dyn std::error::Error>> {
        wait_for_service(&self.config.service, timeout)
    }

    fn health(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        verify_component_health(self.config)
    }
}

fn install_transaction_with(
    config: &Config,
    candidate: &Candidate,
    binaries: Vec<(Component, Vec<u8>)>,
    database_backup: Option<&Path>,
    service: &mut impl ServiceControl,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let install_dir = &config.install_dir;
    std::fs::create_dir_all(install_dir)?;
    let mut files = binaries
        .into_iter()
        .map(|(component, bytes)| (component.file_name().to_string(), bytes))
        .collect::<Vec<_>>();
    if config.components.contains(&Component::Relay) {
        files.push((
            format!("AKRAT-{}-release-attestation.json", candidate.tag),
            candidate.attestation_bytes.clone(),
        ));
        files.push((
            format!("AKRAT-{}-release-attestation.sig", candidate.tag),
            candidate.signature_bytes.clone(),
        ));
    }
    let mut replacements = Vec::new();
    let nonce = std::process::id();
    for (name, bytes) in files {
        let target = install_dir.join(&name);
        if let Ok(metadata) = std::fs::symlink_metadata(&target)
            && !metadata.file_type().is_file()
        {
            cleanup_staged(&replacements);
            return Err(format!("Refus de remplacer un fichier non régulier : {name}").into());
        }
        let staged = install_dir.join(format!(".{name}.{nonce}.new"));
        let backup = install_dir.join(format!(".{name}.{nonce}.bak"));
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
        {
            Ok(file) => file,
            Err(error) => {
                cleanup_staged(&replacements);
                return Err(error.into());
            }
        };
        replacements.push((target, staged.clone(), backup));
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            cleanup_staged(&replacements);
            return Err(error.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if name.starts_with("AKRAT-") {
                0o644
            } else {
                0o755
            };
            if let Err(error) =
                std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))
            {
                cleanup_staged(&replacements);
                return Err(error.into());
            }
        }
    }
    let old_state = if state_path(install_dir).exists() {
        match read_state(install_dir) {
            Ok(state) => Some(state),
            Err(error) => {
                cleanup_staged(&replacements);
                return Err(error);
            }
        }
    } else {
        None
    };
    let mut committed = Vec::new();
    let transaction = (|| -> Result<(), Box<dyn std::error::Error>> {
        for (target, staged, backup) in &replacements {
            committed.push((target.clone(), backup.clone()));
            if target.exists() {
                std::fs::rename(target, backup)?;
            }
            std::fs::rename(staged, target)?;
        }
        let state = State {
            version: candidate.distribution.version.clone(),
            installed_at_unix_seconds: chrono::Utc::now().timestamp().max(0) as u64,
            components: config
                .components
                .iter()
                .map(|c| c.file_name().to_string())
                .collect(),
        };
        write_state(install_dir, &state)?;
        service.command("restart")?;
        if !service.wait_ready(Duration::from_secs(30))? {
            return Err("Contrôle de santé systemd négatif après redémarrage.".into());
        }
        service.health()?;
        Ok(())
    })();
    if let Err(error) = transaction {
        let mut rollback_errors = Vec::new();
        if let Err(rollback_error) = service.command("stop") {
            rollback_errors.push(rollback_error.to_string());
        }
        for (target, backup) in committed.into_iter().rev() {
            if target.exists()
                && let Err(rollback_error) = std::fs::remove_file(&target)
            {
                rollback_errors.push(rollback_error.to_string());
            }
            if backup.exists()
                && let Err(rollback_error) = std::fs::rename(backup, target)
            {
                rollback_errors.push(rollback_error.to_string());
            }
        }
        if let Some(state) = old_state {
            if let Err(rollback_error) = write_state(install_dir, &state) {
                rollback_errors.push(rollback_error.to_string());
            }
        } else if let Err(rollback_error) = std::fs::remove_file(state_path(install_dir))
            && rollback_error.kind() != std::io::ErrorKind::NotFound
        {
            rollback_errors.push(rollback_error.to_string());
        }
        if let Some(backup_dir) = database_backup
            && let Err(rollback_error) = restore_databases(config, backup_dir)
        {
            rollback_errors.push(rollback_error.to_string());
        }
        for (_, staged, _) in &replacements {
            let _ = std::fs::remove_file(staged);
        }
        if rollback_errors.is_empty() {
            if let Err(rollback_error) = service.command("restart") {
                rollback_errors.push(rollback_error.to_string());
            } else {
                match service.wait_ready(Duration::from_secs(30)) {
                    Ok(true) => {
                        if let Err(rollback_error) = service.health() {
                            rollback_errors.push(rollback_error.to_string());
                        }
                    }
                    Ok(false) => {
                        rollback_errors.push("service did not restart after rollback".into())
                    }
                    Err(rollback_error) => rollback_errors.push(rollback_error.to_string()),
                }
            }
        }
        if !rollback_errors.is_empty() {
            return Err(format!(
                "Mise à jour refusée : {error}. Restauration incomplète : {}. Le service peut être arrêté; consultez journalctl.",
                rollback_errors.join("; ")
            ).into());
        }
        return Err(error);
    }
    for (_, _, backup) in replacements {
        let _ = std::fs::remove_file(backup);
    }
    Ok(())
}

fn cleanup_staged(replacements: &[(PathBuf, PathBuf, PathBuf)]) {
    for (_, staged, _) in replacements {
        let _ = std::fs::remove_file(staged);
    }
}

fn backup_databases(config: &Config, version: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let destination_root = config
        .database_backups
        .as_ref()
        .ok_or("database_backups is required")?;
    std::fs::create_dir_all(destination_root)?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup_dir = destination_root.join(format!("{version}-{stamp}"));
    std::fs::create_dir(&backup_dir)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        for source in &config.sqlite_databases {
            let name = source.file_name().ok_or("SQLite path has no filename")?;
            if !source.is_file() {
                return Err(format!("SQLite database does not exist: {}", source.display()).into());
            }
            let destination = backup_dir.join(name);
            let source_connection = rusqlite::Connection::open_with_flags(
                source,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let mut destination_connection = rusqlite::Connection::open(&destination)?;
            rusqlite::backup::Backup::new(&source_connection, &mut destination_connection)?
                .run_to_completion(16, std::time::Duration::from_millis(100), None)?;
            let check: String =
                destination_connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
            if check != "ok" {
                return Err(format!(
                    "SQLite backup validation failed for {}: {check}",
                    source.display()
                )
                .into());
            }
            destination_connection.close().map_err(|(_, error)| error)?;
            source_connection.close().map_err(|(_, error)| error)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&backup_dir);
        return Err(error);
    }
    Ok(backup_dir)
}

fn restore_databases(config: &Config, backup_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for source in &config.sqlite_databases {
        let name = source.file_name().ok_or("SQLite path has no filename")?;
        let backup = backup_dir.join(name);
        if !backup.is_file() {
            return Err(format!("SQLite backup missing: {}", backup.display()).into());
        }
        let temporary = source.with_extension(format!("akrat-restore-{}.tmp", std::process::id()));
        let mut input = std::fs::File::open(&backup)?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        if let Err(error) = std::io::copy(&mut input, &mut output).and_then(|_| output.sync_all()) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error.into());
        }
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{suffix}", source.display()));
            if let Err(error) = std::fs::remove_file(sidecar)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                let _ = std::fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        if let Err(error) = std::fs::rename(&temporary, source) {
            let _ = std::fs::remove_file(temporary);
            return Err(error.into());
        }
    }
    Ok(())
}

fn verify_component_health(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    if config.components.contains(&Component::Mailbox) {
        let config_path = config
            .mailbox_config
            .as_ref()
            .ok_or("mailbox_config is required")?;
        let mut healthy = false;
        for _ in 0..30 {
            let status = std::process::Command::new(config.install_dir.join("akrat-mailbox"))
                .arg("--config")
                .arg(config_path)
                .arg("health")
                .output()?;
            if status.status.success() {
                healthy = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if !healthy {
            return Err("Mailbox health check failed after restart.".into());
        }
    }
    if config.components.contains(&Component::Relay) {
        let url = config
            .relay_health_url
            .as_deref()
            .ok_or("relay_health_url is required")?;
        let parsed = reqwest::Url::parse(url)?;
        if parsed.scheme() != "http"
            || !matches!(parsed.host_str(), Some("127.0.0.1" | "::1" | "localhost"))
            || !parsed.path().ends_with("/health")
        {
            return Err("Relay health URL must be a local HTTP /health endpoint.".into());
        }
        let mut healthy = false;
        for _ in 0..30 {
            if relay_health_ok(&parsed).unwrap_or(false) {
                healthy = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        if !healthy {
            return Err("Relay HTTP health check failed after restart.".into());
        }
    }
    Ok(())
}

fn systemctl(config: &Config, command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("/usr/bin/systemctl")
        .args([command, &config.service])
        .status()?;
    if !status.success() {
        return Err(format!("systemctl {command} {} a échoué.", config.service).into());
    }
    Ok(())
}

fn relay_health_ok(url: &reqwest::Url) -> Result<bool, Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    let host = url.host_str().ok_or("relay health URL has no host")?;
    let port = url
        .port_or_known_default()
        .ok_or("relay health URL has no port")?;
    let address = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or("local health endpoint did not resolve")?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    if url.query().is_some() {
        return Err("query not permitted in health URL".into());
    }
    write!(
        stream,
        "GET {} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n",
        url.path()
    )?;
    let mut response = Vec::new();
    let mut limited = stream.take(4096);
    let mut chunk = [0_u8; 1024];
    loop {
        match limited.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => response.extend_from_slice(&chunk[..count]),
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    let response = std::str::from_utf8(&response)?;
    Ok(response.starts_with("HTTP/1.1 200 ")
        && response
            .split_once("\r\n\r\n")
            .is_some_and(|(_, body)| body.trim() == "ok"))
}

fn service_active(service: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(std::process::Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", service])
        .status()?
        .success())
}

fn wait_for_service(service: &str, timeout: Duration) -> Result<bool, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if service_active(service)? {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join(".akrat-update-state.json")
}
fn read_state(dir: &Path) -> Result<State, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&std::fs::read(state_path(dir))?)?)
}
fn write_state(dir: &Path, state: &State) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let tmp = dir.join(format!(".akrat-update-state.{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.sync_all()?;
    std::fs::rename(tmp, state_path(dir))?;
    Ok(())
}

fn verify_files(
    manifest_path: &Path,
    signature_path: &Path,
    artifact_path: &Path,
    asset_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_bytes = std::fs::read(manifest_path)?;
    let signature_bytes = std::fs::read(signature_path)?;
    let artifact = std::fs::read(artifact_path)?;
    if manifest_bytes.len() > MAX_METADATA_BYTES
        || signature_bytes.len() > MAX_SIGNATURE_BYTES
        || artifact.len() > MAX_BINARY_BYTES
    {
        return Err("Fichier dépasse la limite autorisée.".into());
    }
    let attestation: ReleaseAttestation = serde_json::from_slice(&manifest_bytes)?;
    let signature = std::str::from_utf8(&signature_bytes)?.trim();
    let distribution = verify_official_release_attestation(&attestation, signature)?;
    verify_attested_artifact(
        &distribution,
        asset_name,
        &hex::encode(Sha256::digest(&artifact)),
    )?;
    if !artifact.starts_with(b"\x7fELF") {
        return Err("Le fichier n’est pas un exécutable ELF.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TransactionService {
        commands: Vec<String>,
        fail_first_restart: bool,
    }

    impl ServiceControl for TransactionService {
        fn command(&mut self, command: &str) -> Result<(), Box<dyn std::error::Error>> {
            self.commands.push(command.to_string());
            if command == "restart" && self.fail_first_restart {
                self.fail_first_restart = false;
                return Err("simulated restart failure".into());
            }
            Ok(())
        }

        fn wait_ready(&mut self, _timeout: Duration) -> Result<bool, Box<dyn std::error::Error>> {
            Ok(true)
        }

        fn health(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    fn transaction_candidate() -> Candidate {
        Candidate {
            tag: "v0.1.14".into(),
            distribution: VerifiedDistribution {
                repository: RELEASE_REPOSITORY.into(),
                tag: "v0.1.14".into(),
                version: "0.1.14".into(),
                source_commit: "a".repeat(40),
                protocol_version: 1,
                assets: Vec::new(),
            },
            assets: BTreeMap::new(),
            attestation_bytes: Vec::new(),
            signature_bytes: Vec::new(),
        }
    }

    fn transaction_config(install_dir: PathBuf) -> Config {
        Config {
            install_dir,
            service: "akrat-node.service".into(),
            components: vec![Component::IrohRelay],
            channel: Channel::Stable,
            policy: Policy::Manual,
            maintenance_start_hour: 3,
            maintenance_end_hour: 5,
            mailbox_config: None,
            relay_health_url: None,
            database_backups: None,
            sqlite_databases: Vec::new(),
            allow_mailbox_auto_update: false,
        }
    }

    struct FakeService {
        database: PathBuf,
        restarts: usize,
        health_checks: usize,
    }

    impl ServiceControl for FakeService {
        fn command(&mut self, command: &str) -> Result<(), Box<dyn std::error::Error>> {
            if command == "restart" {
                self.restarts += 1;
                if self.restarts == 1 {
                    rusqlite::Connection::open(&self.database)?
                        .execute("UPDATE records SET value = 'after'", [])?;
                }
            }
            Ok(())
        }

        fn wait_ready(&mut self, _timeout: Duration) -> Result<bool, Box<dyn std::error::Error>> {
            Ok(true)
        }

        fn health(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            self.health_checks += 1;
            if self.health_checks == 1 {
                Err("simulated unhealthy update".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_update_configuration() {
        for text in [
            r#"{"install_dir":"/opt/akrat","service":"akrat-node.service","components":["mailbox","mailbox"],"channel":"stable","policy":"automatic","maintenance_start_hour":1,"maintenance_end_hour":2}"#,
            r#"{"install_dir":"/opt/akrat","service":"","components":["relay"],"channel":"stable","policy":"automatic","maintenance_start_hour":1,"maintenance_end_hour":2}"#,
            r#"{"install_dir":"/opt/akrat","service":"akrat-node.service","components":["relay"],"channel":"stable","policy":"automatic","maintenance_start_hour":24,"maintenance_end_hour":2}"#,
        ] {
            assert!(serde_json::from_str::<Config>(text).is_ok());
            let path = tempfile::NamedTempFile::new().expect("config temp file");
            std::fs::write(path.path(), text).expect("write config");
            assert!(load_config(path.path()).is_err());
        }
    }

    #[test]
    fn maps_node_components_to_expected_signed_linux_assets() {
        assert_eq!(
            Component::Mailbox.asset_name("v0.1.14"),
            "AKRAT-v0.1.14-mailbox-linux-x64"
        );
        assert_eq!(
            Component::Relay.asset_name("v0.1.14"),
            "AKRAT-v0.1.14-relay-linux-x64"
        );
        assert_eq!(
            Component::IrohRelay.asset_name("v0.1.14"),
            "AKRAT-v0.1.14-iroh-relay-linux-x64"
        );
    }

    #[test]
    fn only_official_github_asset_urls_are_accepted() {
        assert!(
            trusted_asset_url(
                "https://api.github.com/repos/FIMAlexSender/AKRAT/releases/assets/123"
            )
            .is_ok()
        );
        assert!(
            trusted_asset_url(
                "https://attacker.example/repos/FIMAlexSender/AKRAT/releases/assets/123"
            )
            .is_err()
        );
        assert!(
            trusted_asset_url("https://api.github.com/repos/other/AKRAT/releases/assets/123")
                .is_err()
        );
        assert!(
            trusted_asset_url(
                "http://api.github.com/repos/FIMAlexSender/AKRAT/releases/assets/123"
            )
            .is_err()
        );
    }

    #[test]
    fn automatic_policy_requires_stable_channel_and_explicit_mailbox_opt_in() {
        let config = Config {
            install_dir: PathBuf::from("/opt/akrat"),
            service: "akrat-node.service".into(),
            components: vec![Component::Mailbox],
            channel: Channel::Stable,
            policy: Policy::Automatic,
            maintenance_start_hour: 3,
            maintenance_end_hour: 5,
            mailbox_config: Some(PathBuf::from("/etc/akrat/mailbox.json")),
            relay_health_url: None,
            database_backups: Some(PathBuf::from("/var/lib/akrat-updater/backups")),
            sqlite_databases: vec![PathBuf::from("/var/lib/akrat/mailbox.sqlite3")],
            allow_mailbox_auto_update: false,
        };
        assert!(validate_auto(&config).is_err());
        let mut approved = config;
        approved.allow_mailbox_auto_update = true;
        assert!(validate_auto(&approved).is_ok());
        approved.channel = Channel::Experimental;
        assert!(validate_auto(&approved).is_err());
    }

    #[test]
    fn relay_health_requires_an_ok_response() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept health request");
            let mut request = Vec::new();
            let mut chunk = [0; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut chunk).expect("read health request");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write health response");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("close health response");
            let _ = stream.read(&mut chunk);
        });
        let url = reqwest::Url::parse(&format!("http://{address}/health")).expect("health URL");
        assert!(relay_health_ok(&url).expect("valid health response"));
        server.join().expect("health server");
    }

    #[test]
    fn successful_install_commits_binary_and_version_after_health_check() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let install_dir = directory.path().join("install");
        std::fs::create_dir(&install_dir).expect("create install directory");
        let executable = install_dir.join(Component::IrohRelay.file_name());
        std::fs::write(&executable, b"old executable").expect("old executable");
        let config = transaction_config(install_dir.clone());
        let mut service = TransactionService {
            commands: Vec::new(),
            fail_first_restart: false,
        };

        install_transaction_with(
            &config,
            &transaction_candidate(),
            vec![(Component::IrohRelay, b"new executable".to_vec())],
            None,
            &mut service,
        )
        .expect("healthy install transaction");

        assert_eq!(
            std::fs::read(executable).expect("read installed executable"),
            b"new executable"
        );
        assert_eq!(
            read_state(&install_dir)
                .expect("read committed update state")
                .version,
            "0.1.14"
        );
        assert_eq!(service.commands, ["restart"]);
    }

    #[test]
    fn failed_restart_restores_executable_and_previous_version() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let install_dir = directory.path().join("install");
        std::fs::create_dir(&install_dir).expect("create install directory");
        let executable = install_dir.join(Component::IrohRelay.file_name());
        std::fs::write(&executable, b"old executable").expect("old executable");
        write_state(
            &install_dir,
            &State {
                version: "0.1.13".into(),
                installed_at_unix_seconds: 1,
                components: vec![Component::IrohRelay.file_name().into()],
            },
        )
        .expect("write previous update state");
        let config = transaction_config(install_dir.clone());
        let mut service = TransactionService {
            commands: Vec::new(),
            fail_first_restart: true,
        };

        assert!(
            install_transaction_with(
                &config,
                &transaction_candidate(),
                vec![(Component::IrohRelay, b"new executable".to_vec())],
                None,
                &mut service,
            )
            .is_err()
        );

        assert_eq!(
            std::fs::read(executable).expect("read restored executable"),
            b"old executable"
        );
        assert_eq!(
            read_state(&install_dir)
                .expect("read restored update state")
                .version,
            "0.1.13"
        );
        assert_eq!(service.commands, ["restart", "stop", "restart"]);
    }

    #[test]
    fn rejects_release_attestation_with_invalid_signature() {
        use akrat_trust::{DistributionAsset, RELEASE_ATTESTATION_SCHEMA, RELEASE_WORKFLOW};
        let directory = tempfile::tempdir().expect("temporary directory");
        let artifact = b"\x7fELFfake-binary";
        let asset_name = "AKRAT-v0.1.14-mailbox-linux-x64";
        let attestation = ReleaseAttestation {
            schema: RELEASE_ATTESTATION_SCHEMA.into(),
            repository: RELEASE_REPOSITORY.into(),
            tag: "v0.1.14".into(),
            version: "0.1.14".into(),
            source_commit: "a".repeat(40),
            workflow: RELEASE_WORKFLOW.into(),
            workflow_ref: format!("{RELEASE_REPOSITORY}/{RELEASE_WORKFLOW}@refs/tags/v0.1.14"),
            run_id: 1,
            issued_unix_seconds: 1,
            protocol_version: 1,
            assets: vec![DistributionAsset {
                name: asset_name.into(),
                sha256: hex::encode(Sha256::digest(artifact)),
            }],
        };
        let manifest_path = directory.path().join("manifest.json");
        let signature_path = directory.path().join("manifest.sig");
        let artifact_path = directory.path().join("artifact");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&attestation).expect("serialize manifest"),
        )
        .expect("write manifest");
        std::fs::write(&signature_path, "00".repeat(64)).expect("write invalid signature");
        std::fs::write(&artifact_path, artifact).expect("write artifact");
        assert!(verify_files(&manifest_path, &signature_path, &artifact_path, asset_name).is_err());
    }

    #[test]
    fn sqlite_backup_is_consistent_and_restorable() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database = directory.path().join("mailbox.sqlite3");
        let connection = rusqlite::Connection::open(&database).expect("open database");
        connection
            .execute_batch(
                "CREATE TABLE records(value TEXT); INSERT INTO records VALUES ('before');",
            )
            .expect("seed database");
        drop(connection);
        let config = Config {
            install_dir: directory.path().join("install"),
            service: "akrat-node.service".into(),
            components: vec![Component::Mailbox],
            channel: Channel::Stable,
            policy: Policy::Manual,
            maintenance_start_hour: 3,
            maintenance_end_hour: 5,
            mailbox_config: Some(directory.path().join("mailbox.toml")),
            relay_health_url: None,
            database_backups: Some(directory.path().join("backups")),
            sqlite_databases: vec![database.clone()],
            allow_mailbox_auto_update: false,
        };
        let backup = backup_databases(&config, "0.1.14").expect("consistent backup");
        let connection = rusqlite::Connection::open(&database).expect("reopen database");
        connection
            .execute("INSERT INTO records VALUES ('after')", [])
            .expect("mutate database");
        drop(connection);
        restore_databases(&config, &backup).expect("restore backup");
        let connection = rusqlite::Connection::open(&database).expect("open restored database");
        let rows: Vec<String> = connection
            .prepare("SELECT value FROM records ORDER BY rowid")
            .expect("prepare query")
            .query_map([], |row| row.get(0))
            .expect("query records")
            .collect::<Result<_, _>>()
            .expect("collect rows");
        assert_eq!(rows, ["before"]);
    }

    #[test]
    fn failed_health_check_restores_executable_state_and_sqlite_data() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let install_dir = directory.path().join("install");
        std::fs::create_dir(&install_dir).expect("create install directory");
        let executable = install_dir.join("akrat-mailbox");
        std::fs::write(&executable, b"old executable").expect("old executable");
        write_state(
            &install_dir,
            &State {
                version: "0.1.13".into(),
                installed_at_unix_seconds: 1,
                components: vec!["akrat-mailbox".into()],
            },
        )
        .expect("initial update state");
        let database = directory.path().join("mailbox.sqlite3");
        let connection = rusqlite::Connection::open(&database).expect("open database");
        connection
            .execute_batch(
                "CREATE TABLE records(value TEXT); INSERT INTO records VALUES ('before');",
            )
            .expect("seed database");
        drop(connection);
        let config = Config {
            install_dir: install_dir.clone(),
            service: "akrat-node.service".into(),
            components: vec![Component::Mailbox],
            channel: Channel::Stable,
            policy: Policy::Manual,
            maintenance_start_hour: 3,
            maintenance_end_hour: 5,
            mailbox_config: Some(directory.path().join("mailbox.json")),
            relay_health_url: None,
            database_backups: Some(directory.path().join("backups")),
            sqlite_databases: vec![database.clone()],
            allow_mailbox_auto_update: false,
        };
        let backup = backup_databases(&config, "0.1.14").expect("consistent backup");
        let candidate = Candidate {
            tag: "v0.1.14".into(),
            distribution: VerifiedDistribution {
                repository: RELEASE_REPOSITORY.into(),
                tag: "v0.1.14".into(),
                version: "0.1.14".into(),
                source_commit: "a".repeat(40),
                protocol_version: 1,
                assets: Vec::new(),
            },
            assets: BTreeMap::new(),
            attestation_bytes: Vec::new(),
            signature_bytes: Vec::new(),
        };
        let mut service = FakeService {
            database: database.clone(),
            restarts: 0,
            health_checks: 0,
        };
        let result = install_transaction_with(
            &config,
            &candidate,
            vec![(Component::Mailbox, b"new executable".to_vec())],
            Some(&backup),
            &mut service,
        );
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(executable).expect("restored executable"),
            b"old executable"
        );
        let connection = rusqlite::Connection::open(database).expect("open restored database");
        let value: String = connection
            .query_row("SELECT value FROM records", [], |row| row.get(0))
            .expect("read restored record");
        assert_eq!(value, "before");
        let state = read_state(&install_dir).expect("restored update state");
        assert_eq!(state.version, "0.1.13");
        assert_eq!(service.restarts, 2);
        assert_eq!(service.health_checks, 2);
    }
}
