import ipaddress

import pytest

from harness.errors import ScopeError
from harness.scope import (
    Engagement,
    ScopeGate,
    command_binaries,
    extract_target_refs,
    extract_network_command_hostnames,
    new_engagement_id,
    path_within,
    shell_binary_allowed,
    url_in_scope,
)


def make_engagements(tmp_path, packages):
    root = tmp_path / "proj"
    root.mkdir(exist_ok=True)
    engs = [
        Engagement(id="eng-01", label="Codebase audit", target=str(root),
                   package="read-only"),
        Engagement(id="eng-02", label="lab net", target="192.168.1.0/24",
                   package="defensive"),
    ]
    return root, engs


def test_new_engagement_ids_are_opaque_and_unique():
    first = new_engagement_id()
    second = new_engagement_id()
    assert first != second
    assert first.startswith("eng_") and len(first) == 36


def test_scope_gate_rejects_duplicate_engagement_ids(tmp_path, packages):
    root, engagements = make_engagements(tmp_path, packages)
    duplicate = Engagement(id=engagements[0].id, label="duplicate",
                           target=str(root), package="read-only")
    with pytest.raises(ScopeError, match="duplicate engagement id"):
        ScopeGate(engagements + [duplicate], packages, {})


def test_path_prefix_confusion(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    ok, _ = path_within(str(root), str(root / "src" / "main.py"))
    assert ok
    evil = tmp_path / "proj.evil"
    evil.mkdir()
    ok, reason = path_within(str(root), str(evil / "x"))
    assert not ok and "escapes" in reason


def test_dotdot_escape(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    ok, _ = path_within(str(root), str(root / ".." / "secret.txt"))
    assert not ok


def test_symlink_escape(tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    outside = tmp_path / "outside-secret"
    outside.write_text("top secret")
    (root / "link").symlink_to(outside)
    ok, _ = path_within(str(root), str(root / "link"))
    assert not ok, "symlink pointing outside scope must be rejected"
    # link to inside is fine
    inside = root / "ok.txt"
    inside.write_text("hi")
    (root / "goodlink").symlink_to(inside)
    ok, _ = path_within(str(root), str(root / "goodlink"))
    assert ok


def test_engagement_matches_network():
    e = Engagement(id="e", label="l", target="192.168.1.0/24", package="defensive")
    assert e.matches_target("192.168.1.10")
    assert not e.matches_target("192.168.2.10")
    p = Engagement(id="p", label="p", target="/opt/project", package="read-only")
    assert not p.matches_target("192.168.1.10")


def test_invalid_url_port_is_denied_without_raising():
    engagement = Engagement(id="e", label="lab", target="127.0.0.1",
                            package="read-only")
    allowed, reason = url_in_scope("http://127.0.0.1:not-a-port/", engagement)
    assert not allowed
    assert "invalid URL port" in reason


def test_gate_tool_gating_per_engagement(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    assert gate.check_tool("read_file", "eng-01") == (True, "")
    assert gate.check_tool("shell", "eng-01")[0] is False
    assert gate.check_tool("scan", "eng-02")[0] is True  # defensive allows scan
    assert gate.check_tool("scan", "eng-01")[0] is False  # read-only denies scan


def test_paused_engagement_denied(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    engs[0].status = "paused"
    gate = ScopeGate(engs, packages, {})
    ok, reason, _ = gate.authorize("read_file", {"path": str(root / "a.py")}, "eng-01")
    assert not ok and "not active" in reason


def test_cross_engagement_denial(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    ok, reason, _ = gate.authorize("read_file", {"path": str(root / "a.py")}, "eng-02")
    assert not ok, "network engagement cannot read the codebase engagement's files"
    ok, reason, _ = gate.authorize(
        "scan", {"targets": ["192.168.1.10"], "ports": ["80"]}, "eng-01")
    assert not ok, "codebase engagement cannot scan the lab network"


def test_network_engagement_can_use_only_its_private_scratch(tmp_path, packages):
    _, engs = make_engagements(tmp_path, packages)
    scratch = tmp_path / "scratch" / "eng-02"
    scratch.mkdir(parents=True)
    engs[1].scratch_dir = str(scratch)
    gate = ScopeGate(engs, packages, {})

    ok, reason, _ = gate.authorize(
        "read_file", {"path": str(scratch / "notes.json")}, "eng-02")
    assert ok, reason
    ok, _, _ = gate.authorize(
        "read_file", {"path": str(tmp_path / "other" / "notes.json")}, "eng-02")
    assert not ok
    ok, reason = gate.check_shell(f"nmap -oN {scratch / 'scan.txt'} 192.168.1.10", engs[1])
    assert ok, reason


def test_glob_without_path_requires_private_scratch(tmp_path, packages):
    root, engagements = make_engagements(tmp_path, packages)
    gate = ScopeGate(engagements, packages, {})

    ok, reason, _ = gate.authorize("glob", {"pattern": "*.py"}, "eng-01")

    assert not ok
    assert "scratch directory" in reason


def test_missing_engagement_id(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    ok, reason, eng = gate.authorize("read_file", {"path": "x"}, "")
    assert not ok and "missing engagement_id" in reason and eng is None


def test_overrides_win_over_package(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {"shell": True})
    ok, _ = gate.check_tool("shell", "eng-01")
    assert ok
    gate2 = ScopeGate(engs, packages, {"shell": False})
    ok, _ = gate2.check_tool("shell", "eng-02")
    assert not ok


def test_url_scope_with_fake_resolver(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    resolver = lambda h: {ipaddress.ip_address("192.168.1.10")}
    ok, reason = gate.check_url("http://lab.local:80/path", engs[1], resolver=resolver)
    assert ok, reason
    resolver_out = lambda h: {ipaddress.ip_address("10.0.0.1")}
    ok, reason = gate.check_url("http://lab.local", engs[1], resolver=resolver_out)
    assert not ok and "outside" in reason
    # path engagement has no network scope
    ok, reason = gate.check_url("http://192.168.1.10", engs[0], resolver=resolver)
    assert not ok and "no network scope" in reason
    # non-http scheme
    ok, reason = gate.check_url("ftp://192.168.1.10", engs[1], resolver=resolver)
    assert not ok and "scheme" in reason
    # userinfo forbidden
    ok, reason = gate.check_url("http://user:pw@192.168.1.10", engs[1], resolver=resolver)
    assert not ok and "credentials" in reason


def test_http_method_gating(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    resolver = lambda h: {ipaddress.ip_address("192.168.1.10")}
    ok, reason, _ = gate.authorize(
        "http", {"url": "http://192.168.1.10/", "method": "POST"}, "eng-02",
        resolver=resolver)
    assert not ok and "method" in reason  # defensive allows GET/HEAD/OPTIONS
    ok, reason, _ = gate.authorize(
        "http", {"url": "http://192.168.1.10/", "method": "GET"}, "eng-02",
        resolver=resolver)
    assert ok


def test_scan_target_validation(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    ok, reason = gate.check_scan_targets(["192.168.1.0/24"], ["1-100"], engs[1])
    assert ok, reason
    ok, reason = gate.check_scan_targets(["10.0.0.0/24"], ["80"], engs[1])
    assert not ok and "outside" in reason
    ok, reason = gate.check_scan_targets([f"192.168.1.{i}" for i in range(11)],
                                         ["80"], engs[1])
    assert not ok and "too many targets" in reason
    ok, reason = gate.check_scan_targets(["192.168.1.1"], ["1-65535"], engs[1])
    assert not ok and "too many ports" in reason


def test_shell_guard_integration(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    ok, reason = gate.check_shell("nmap -sV 192.168.1.10", engs[1])
    assert ok, reason
    ok, reason = gate.check_shell("sudo nmap 192.168.1.10", engs[1])
    assert not ok and "deny" in reason
    ok, reason = gate.check_shell("whoami", engs[1])
    assert ok, reason  # reaches the mandatory operator-approval prompt
    ok, reason = gate.check_shell("nmap -sV 10.9.9.9", engs[1])
    assert not ok, "out-of-scope IP in command must be rejected"


def test_shell_scope_ignores_dotted_note_text(tmp_path, packages):
    _, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    command = "printf '%s\\n' 'Express ^4.17.1 attacker@evil.com main-es2015.js'"
    ok, reason = gate.check_shell(command, engs[1])
    assert ok, reason


def test_shell_scope_checks_bare_hostname_operand(tmp_path, packages):
    _, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    ok, reason = gate.check_shell("nmap evil.example", engs[1])
    assert not ok and "host 'evil.example' is outside engagement scope" in reason


def test_network_hostname_extraction_is_command_aware():
    note = "printf '%s\\n' 'Express ^4.17.1 attacker@evil.com main-es2015.js'"
    assert extract_network_command_hostnames(note) == []
    assert extract_network_command_hostnames("nmap target.example") == ["target.example"]
    hosts = extract_network_command_hostnames(
        "curl -s http://192.168.1.10/ui/select -o select.html")
    assert "select.html" not in hosts
    assert extract_network_command_hostnames(
        "curl --output=select.html evil.example") == ["evil.example"]


def test_shell_scope_ignores_network_tool_output_filename(tmp_path, packages):
    _, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    ok, reason = gate.check_shell(
        "nmap -oN select.html 192.168.1.10", engs[1])
    assert ok, reason


def test_http_save_as_must_stay_in_engagement_scratch(tmp_path, packages):
    _, engs = make_engagements(tmp_path, packages)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    engs[1].scratch_dir = str(scratch)
    gate = ScopeGate(engs, packages, {})
    args = {"url": "http://192.168.1.10/ui/select", "save_as": "select.html"}
    ok, reason, _ = gate.authorize("http", args, "eng-02")
    assert ok, reason
    args["save_as"] = "../outside.html"
    ok, reason, _ = gate.authorize("http", args, "eng-02")
    assert not ok and "escapes engagement scope" in reason


def test_process_capability_enables_pane_tools(tmp_path, packages):
    _, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    assert gate.check_tool("pane_spawn", "eng-02")[0] is True
    assert gate.any_active_engagement_permits("pane_read")


def test_command_binaries_direct_exec():
    assert command_binaries("curl a | nc b") == ["curl"]
    assert command_binaries("a && b; c") == ["a"]


def test_shell_binary_allowlist():
    assert shell_binary_allowed("impacket-secretsdump", ["impacket-"])
    assert shell_binary_allowed("impacket-x-evil", ["impacket-"])  # prefix match
    assert not shell_binary_allowed("nmapX", ["nmap"])
    assert shell_binary_allowed("testssl.sh", ["testssl.sh"])
    assert not shell_binary_allowed("testssl.shx", ["testssl.sh"])
    assert not shell_binary_allowed("python3", ["nmap"])


def test_extract_target_refs():
    refs = extract_target_refs("nmap -sV 192.168.1.10 -oG /tmp/out")
    assert "192.168.1.10" in refs and "/tmp/out" in refs


def test_schema_visibility_vs_authorization(tmp_path, packages):
    root, engs = make_engagements(tmp_path, packages)
    gate = ScopeGate(engs, packages, {})
    # read_file is visible (eng-01 read-only), shell visible (eng-02 defensive)
    assert gate.any_active_engagement_permits("read_file")
    assert gate.any_active_engagement_permits("shell")
    assert not gate.any_active_engagement_permits("write_file")
