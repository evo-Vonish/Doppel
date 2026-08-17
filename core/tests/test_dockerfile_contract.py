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


def test_tishen_stage_installs_grid3_probe_and_supported_locales_in_isolated_layer():
    dockerfile = (REPO_ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    runtime_stage = dockerfile.split("FROM ${UBUNTU} AS runtime", 1)[1].split(
        "FROM runtime AS i18n", 1
    )[0]
    assert "mesa-utils" not in runtime_stage

    tishen_stage = dockerfile.split("FROM chrome AS tishen", 1)[1].split(
        "FROM tishen AS stream", 1
    )[0]
    probe_layer = tishen_stage.split("# 格 3 真机门禁工具", 1)[1].split(
        "# 拷贝镜像层自带资产", 1
    )[0]

    assert "apt-get ${APT_NETWORK_OPTS} update" in probe_layer
    assert "mesa-utils" in probe_layer
    assert "locales" in probe_layer
    for locale in (
        "de_DE.UTF-8", "en_CA.UTF-8", "en_GB.UTF-8", "en_HK.UTF-8",
        "en_US.UTF-8", "fr_CA.UTF-8", "ja_JP.UTF-8", "zh_CN.UTF-8",
        "zh_HK.UTF-8", "zh_TW.UTF-8",
    ):
        assert locale in probe_layer
    assert "rm -rf /var/lib/apt/lists/*" in probe_layer


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


def test_stream_stage_uses_digest_pinned_official_neko_assets():
    dockerfile = (REPO_ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    stream_section = dockerfile.split("# ── L5 流层", 1)[1]

    assert (
        "FROM ghcr.io/m1k1o/neko/base:2.8.0@sha256:"
        "c952e71cd81c1e16eb46e1ca6da688c43cfc8c46633baaf4c4f2e93a4b293324 "
        "AS neko_v2"
    ) in stream_section
    assert "COPY --from=neko_v2 /usr/bin/neko /opt/neko/neko" in stream_section
    assert "COPY --from=neko_v2 /var/www/ /var/www/" in stream_section
    assert 'grep -F "Version ${NEKO_VERSION}"' in stream_section
    assert 'tishen.neko.version="${NEKO_VERSION}"' in stream_section

    # v2.8.0 未发布 GitHub tar asset，也不得再允许空 SHA 绕过校验。
    assert "releases/download" not in stream_section
    assert "NEKO_SHA256" not in stream_section
