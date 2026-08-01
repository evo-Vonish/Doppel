"""观测守护的最小权限启动契约。"""

from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "image"
    / "scripts"
    / "observability-daemon.sh"
).read_text(encoding="utf-8")


def test_pcap_volume_is_handed_to_tcpdump_before_capture_starts():
    handoff = 'chown -R tcpdump:tcpdump "$PCAP_DIR"'
    start = "start_tcpdump\n"
    assert handoff in SCRIPT
    assert 'chmod 0750 "$PCAP_DIR"' in SCRIPT
    assert SCRIPT.index(handoff) < SCRIPT.index(start)


def test_tcpdump_still_drops_privileges_instead_of_forcing_root():
    assert "-Z root" not in SCRIPT
    assert 'tcpdump -i any -w "$PCAP_DIR/$RING_BASENAME"' in SCRIPT
