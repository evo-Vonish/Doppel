from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_runtime_installs_xcvt_for_dynamic_modelines():
    dockerfile = (REPO_ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    runtime_stage = dockerfile.split("FROM ${UBUNTU} AS runtime", 1)[1].split(
        "FROM runtime AS i18n", 1
    )[0]
    display_packages = runtime_stage.split(
        "apt-get install -y --no-install-recommends", 1
    )[1].split("&& rm -rf /var/lib/apt/lists/*", 1)[0]

    packages = {
        line.strip().removesuffix(" \\") for line in display_packages.splitlines()
    }

    assert "xcvt" in packages
