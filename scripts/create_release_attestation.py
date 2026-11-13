import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_release_attestation.py <release-directory>")
    root = Path(sys.argv[1]).resolve()
    tag = os.environ["GITHUB_REF_NAME"]
    version = tag.removeprefix("v")
    source_commit = os.environ["GITHUB_SHA"].lower()
    workflow_ref = os.environ["GITHUB_WORKFLOW_REF"]
    run_id = int(os.environ["GITHUB_RUN_ID"])
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise SystemExit("release tag must be a stable semantic version")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SystemExit("release source commit must be a full lowercase Git SHA")
    if workflow_ref != f"FIMAlexSender/AKRAT/.github/workflows/build.yml@refs/tags/{tag}":
        raise SystemExit("release workflow identity does not match the official tag")
    if run_id <= 0 or not root.is_dir():
        raise SystemExit("release run metadata is invalid")
    assets = []
    for path in sorted(root.glob("AKRAT-*"), key=lambda item: item.name):
        if path.name.endswith("-release-attestation.json") or path.name.endswith(
            "-release-attestation.sig"
        ) or path.suffix == ".zip":
            continue
        if not path.is_file():
            raise SystemExit(f"release asset is not a regular file: {path.name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assets.append({"name": path.name, "sha256": digest})
    if not assets:
        raise SystemExit("release has no distributable assets")
    attestation = {
        "schema": "akrat-release-attestation/v1",
        "repository": "FIMAlexSender/AKRAT",
        "tag": tag,
        "version": version,
        "source_commit": source_commit,
        "workflow": ".github/workflows/build.yml",
        "workflow_ref": workflow_ref,
        "run_id": run_id,
        "issued_unix_seconds": int(time.time()),
        "protocol_version": 1,
        "assets": assets,
    }
    destination = root / f"AKRAT-{tag}-release-attestation.json"
    destination.write_text(
        json.dumps(attestation, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
