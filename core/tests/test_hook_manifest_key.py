"""Build helper tests for the MV3 extension key injection step."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INJECTOR = REPO_ROOT / "image" / "hook" / "inject_manifest_key.py"


def test_inject_manifest_key_preserves_manifest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"manifest_version": 3, "name": "Tishen Hook"}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(INJECTOR), str(manifest_path), "base64-public-key"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest == {
        "manifest_version": 3,
        "name": "Tishen Hook",
        "key": "base64-public-key",
    }


def test_inject_manifest_key_rejects_empty_key(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(INJECTOR), str(manifest_path), ""],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == {}
