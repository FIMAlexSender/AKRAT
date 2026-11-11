#!/usr/bin/env python3
"""Replace Dioxus 0.7.10's stock Android launcher icon in its generated project."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from PIL import Image


ANDROID_DENSITIES = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192,
}
BACKGROUND = (17, 21, 28, 255)


def make_icon(source: Path, size: int, *, adaptive_foreground: bool) -> Image.Image:
    logo = Image.open(source).convert("RGBA")
    if adaptive_foreground:
        # The source is a circled mark. The Android adaptive safe zone would
        # shrink that whole circle too much, so use the central A as the
        # foreground and let the OS apply the launcher mask.
        width, height = logo.size
        logo = logo.crop((round(width * 0.20), round(height * 0.27), round(width * 0.80), round(height * 0.74)))
        extent = round(size * 0.70)
    else:
        extent = round(size * 0.88)
    logo.thumbnail((extent, extent), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0) if adaptive_foreground else BACKGROUND)
    canvas.alpha_composite(logo, ((size - logo.width) // 2, (size - logo.height) // 2))
    return canvas


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, required=True, help="Generated Dioxus Android project root")
    parser.add_argument("--icon", type=Path, required=True, help="AKRAT logo PNG")
    args = parser.parse_args()

    resources = args.project / "app" / "src" / "main" / "res"
    if not (args.project / "app" / "build.gradle.kts").is_file():
        raise SystemExit(f"Generated Android project not found: {args.project}")
    if not args.icon.is_file():
        raise SystemExit(f"Launcher logo not found: {args.icon}")

    # Keep Android installs upgradeable: Dioxus currently emits versionCode=1
    # for every build, which prevents users from receiving subsequent builds.
    gradle = args.project / "app" / "build.gradle.kts"
    gradle_text = gradle.read_text(encoding="utf-8")
    version_match = re.search(r'versionName\s*=\s*"(\d+)\.(\d+)\.(\d+)"', gradle_text)
    if not version_match:
        raise SystemExit(f"Could not read semantic version from {gradle}")
    major, minor, patch = map(int, version_match.groups())
    version_code = major * 1_000_000 + minor * 1_000 + patch
    gradle_text, replacements = re.subn(
        r"versionCode\s*=\s*\d+", f"versionCode = {version_code}", gradle_text, count=1
    )
    if replacements != 1:
        raise SystemExit(f"Could not update Android versionCode in {gradle}")
    gradle.write_text(gradle_text, encoding="utf-8")

    manifest = args.project / "app" / "src" / "main" / "AndroidManifest.xml"
    manifest_text = manifest.read_text(encoding="utf-8")
    manifest_text, replacements = re.subn(
        r'android:icon="@mipmap/ic_launcher"(?!\s+android:roundIcon)',
        'android:icon="@mipmap/ic_launcher" android:roundIcon="@mipmap/ic_launcher"',
        manifest_text,
        count=1,
    )
    if replacements != 1:
        raise SystemExit(f"Could not configure launcher icons in {manifest}")
    manifest.write_text(manifest_text, encoding="utf-8")

    for folder, size in ANDROID_DENSITIES.items():
        directory = resources / folder
        directory.mkdir(parents=True, exist_ok=True)
        # PNG is the most widely supported legacy launcher format.
        (directory / "ic_launcher.webp").unlink(missing_ok=True)
        make_icon(args.icon, size, adaptive_foreground=False).convert("RGB").save(
            directory / "ic_launcher.png", "PNG", optimize=True
        )

    foreground = resources / "drawable-nodpi" / "akrat_launcher_foreground.png"
    foreground.parent.mkdir(parents=True, exist_ok=True)
    make_icon(args.icon, 108, adaptive_foreground=True).save(foreground, "PNG", optimize=True)

    background = resources / "drawable" / "ic_launcher_background.xml"
    background.parent.mkdir(parents=True, exist_ok=True)
    background.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<shape xmlns:android="http://schemas.android.com/apk/res/android" android:shape="rectangle">\n'
        '    <solid android:color="#11151c" />\n'
        '</shape>\n',
        encoding="utf-8",
    )

    foreground_vector = resources / "drawable-v24" / "ic_launcher_foreground.xml"
    foreground_vector.parent.mkdir(parents=True, exist_ok=True)
    foreground_vector.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<bitmap xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '    android:src="@drawable/akrat_launcher_foreground"\n'
        '    android:gravity="center" />\n',
        encoding="utf-8",
    )

    adaptive = resources / "mipmap-anydpi-v26" / "ic_launcher.xml"
    adaptive.parent.mkdir(parents=True, exist_ok=True)
    adaptive.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <background android:drawable="@drawable/ic_launcher_background" />\n'
        '    <foreground android:drawable="@drawable/ic_launcher_foreground" />\n'
        '</adaptive-icon>\n',
        encoding="utf-8",
    )

    print(f"AKRAT launcher icon installed in {resources}")


if __name__ == "__main__":
    main()
