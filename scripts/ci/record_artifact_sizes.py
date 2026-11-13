#!/usr/bin/env python3
"""Record exact sizes for build outputs without changing them."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("platform")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    files = []
    missing = []
    for value in args.paths:
        path = Path(value)
        if path.is_file():
            files.append({"path": value.replace("\\", "/"), "size_bytes": path.stat().st_size})
        else:
            missing.append(value)
    if missing:
        parser.error(f"artifact files are missing: {', '.join(missing)}")
    record = {"platform": args.platform, "files": files}
    output = Path("target/ci-metrics") / f"sizes-{args.platform}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
