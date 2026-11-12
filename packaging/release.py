from __future__ import annotations

import argparse
import hashlib
import shutil
import stat
import zipfile
from pathlib import Path


def add_file(archive: zipfile.ZipFile, source: Path, name: str, mode: int) -> None:
    info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | mode) << 16
    archive.writestr(info, source.read_bytes())


def copy_asset(source: Path, output: Path, name: str) -> Path:
    if not source.is_file():
        raise SystemExit(f"Missing release input: {source}")
    destination = output / name
    shutil.copy2(source, destination)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--version", default="0.1.9")
    args = parser.parse_args()

    root = args.root.resolve()
    release = root / "target" / "release"
    output = release / f"AKRAT-v{args.version}"
    output.mkdir(parents=True, exist_ok=True)

    windows = [
        (release / "akrat-desktop.exe", "akrat-desktop.exe"),
        (release / "akrat.exe", "akrat.exe"),
        (release / "akrat-mailbox.exe", "akrat-mailbox.exe"),
    ]
    linux = [
        (release / "akrat-desktop-linux-x64", "akrat-desktop"),
        (release / "akrat-linux-x64", "akrat"),
        (release / "akrat-mailbox-linux-x64", "akrat-mailbox"),
    ]

    windows_zip = output / f"AKRAT-v{args.version}-windows-x64.zip"
    with zipfile.ZipFile(windows_zip, "w") as archive:
        for source, name in windows:
            add_file(archive, source, name, 0o755)

    linux_zip = output / f"AKRAT-v{args.version}-linux-x64.zip"
    with zipfile.ZipFile(linux_zip, "w") as archive:
        for source, name in linux:
            add_file(archive, source, name, 0o755)
        add_file(archive, root / "packaging" / "linux" / "akrat-mailbox.service", "akrat-mailbox.service", 0o644)

    assets = [
        copy_asset(release / f"AKRAT-Setup-v{args.version}.exe", output, f"AKRAT-v{args.version}-windows-installer.exe"),
        copy_asset(release / "akrat-mailbox.exe", output, f"AKRAT-v{args.version}-mailbox-windows-x64.exe"),
        copy_asset(release / "akrat-mailbox-linux-x64", output, f"AKRAT-v{args.version}-mailbox-linux-x64"),
        copy_asset(release / f"AKRAT-v{args.version}-android.apk", output, f"AKRAT-v{args.version}-android.apk"),
        windows_zip,
        linux_zip,
    ]

    sums = []
    for asset in sorted(assets):
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        sums.append(f"{digest}  {asset.name}")
    (output / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    notes = (
        f"## AKRAT v{args.version}\n\n"
        "Livraison vérifiée localement sur Windows et Ubuntu 24.04. L’APK Android est signé avec la clé de test persistante et conserve la compatibilité de mise à jour. Aucun binaire macOS n’est fourni ni annoncé comme validé.\n\n"
        "### Artefacts\n\n"
        "- Windows x64 : installateur, archive portable et serveur Mailbox autonome.\n"
        "- Linux x64 : archive portable Desktop, CLI et Mailbox, plus le service systemd.\n"
        "- Android : APK installable de test.\n\n"
        "Les empreintes SHA-256 sont dans `SHA256SUMS`.\n\n"
        "### Limites connues\n\n"
        "- La rotation des clés de reçus est authentifiée par la racine et propagée par les annonces fédérées ; les anciennes clés ne valident que les reçus créés pendant leur période d’activité. La compromission de la racine exige un réépinglage hors bande.\n"
        "- Le serveur applique des limites de débit en mémoire ; elles repartent à zéro au redémarrage et ne protègent pas d’un déni de service distribué.\n"
        "- Le prekey Kyber signé n’est pas un pool de prekeys PQ à usage unique.\n"
        "- Aucun audit cryptographique indépendant n’a été réalisé.\n"
    )
    notes_path = output / "release-notes.md"
    notes_path.write_text(notes, encoding="utf-8")
    print(f"Release assets staged in {output}")
    for asset in assets:
        print(f"{asset.name} {asset.stat().st_size}")
    print(f"SHA256SUMS {len(sums)} artifacts")


if __name__ == "__main__":
    main()
