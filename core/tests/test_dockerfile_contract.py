from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_runtime_installs_xcvt_for_dynamic_modelines():
    dockerfile = (REPO_ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    runtime_stage = dockerfile.split("FROM ${UBUNTU} AS runtime", 1)[1].split(
        "FROM runtime AS i18n", 1
    )[0]
    display_packages = runtime_stage.split(
        "install -y --no-install-recommends", 1
    )[1].split("&& rm -rf /var/lib/apt/lists/*", 1)[0]

    packages = {
        line.strip().removesuffix(" \\") for line in display_packages.splitlines()
    }

    assert "xcvt" in packages


def test_runtime_installs_glxinfo_for_grid3_renderer_gate():
    dockerfile = (REPO_ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    runtime_stage = dockerfile.split("FROM ${UBUNTU} AS runtime", 1)[1].split(
        "FROM runtime AS i18n", 1
    )[0]
    display_packages = runtime_stage.split(
        "install -y --no-install-recommends", 1
    )[1].split("&& rm -rf /var/lib/apt/lists/*", 1)[0]

    packages = {
        line.strip().removesuffix(" \\") for line in display_packages.splitlines()
    }

    assert "mesa-utils" in packages


def test_all_apt_transactions_retry_without_http_pipelining():
    dockerfile = (REPO_ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    apt_commands = [line for line in dockerfile.splitlines() if "apt-get" in line]

    assert apt_commands
    assert all("apt-get ${APT_NETWORK_OPTS}" in line for line in apt_commands)
    assert "Acquire::Retries=5" in dockerfile
    assert "Acquire::http::Pipeline-Depth=0" in dockerfile


def test_hook_main_world_script_is_present_in_extension_pack_directory():
    dockerfile = (REPO_ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    assert (
        "COPY image/hook/tishen_hook.js "
        "/opt/tishen/hook-ext/tishen_hook.js"
    ) in dockerfile
