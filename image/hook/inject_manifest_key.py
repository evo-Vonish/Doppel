#!/usr/bin/env python3
"""Inject a Chrome extension public key into an MV3 manifest."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3 or not sys.argv[2]:
        print("usage: inject_manifest_key.py MANIFEST PUBLIC_KEY", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["key"] = sys.argv[2]
    path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
