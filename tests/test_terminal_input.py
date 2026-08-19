"""Terminal control traffic must never become chat prompt text."""

from harness.tui import _strip_terminal_input_sequences


def test_strips_sgr_mouse_reports() -> None:
    assert _strip_terminal_input_sequences(
        "scan target\x1b[<35;141;31M") == "scan target"
    # Some terminals lose ESC before the input widget receives the report.
    assert _strip_terminal_input_sequences(
        "scan target[<35;141;31M") == "scan target"


def test_strips_bracketed_paste_markers_but_keeps_text() -> None:
    assert _strip_terminal_input_sequences(
        "\x1b[200~nmap target\x1b[201~") == "nmap target"
