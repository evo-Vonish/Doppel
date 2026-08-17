from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SMOKE_PAGE = REPO_ROOT / "tools" / "adversarial" / "harness" / "hook_smoke.html"


def test_hook_smoke_page_covers_real_machine_a8_producers():
    source = SMOKE_PAGE.read_text(encoding="utf-8")

    for producer in (
        'toDataURL()',
        'localStorage.setItem(',
        'new Worker(',
        'WebAssembly.instantiate(',
    ):
        assert producer in source
    assert "new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0])" in source


def test_hook_smoke_page_is_self_contained_and_reports_completion():
    source = SMOKE_PAGE.read_text(encoding="utf-8")

    assert "http://" not in source
    assert "https://" not in source
    assert 'document.title = "Tishen Hook Smoke DONE"' in source
    assert 'document.title = "Tishen Hook Smoke FAILED"' in source
