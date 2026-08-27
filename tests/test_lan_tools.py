import struct

from halgate.scope import Engagement, ScopeGate
from halgate.tools.mdns import _parse_records
from halgate.tools.packet_capture import PACKET_CAPTURE_SCHEMA


def test_mdns_parser_extracts_ptr_srv_and_txt():
    # one PTR answer plus a service instance's SRV and TXT additional records
    service = b"\x05_http\x04_tcp\x05local\0"
    instance = b"\x06device\xc0\x0c"
    host = b"\x07halgate\x05local\0"
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 3, 0, 0)
    ptr = service + struct.pack("!HHIH", 12, 1, 120, len(instance)) + instance
    srv_data = struct.pack("!HHH", 0, 0, 8080) + host
    srv = b"\x06device\xc0\x0c" + struct.pack("!HHIH", 33, 1, 120, len(srv_data)) + srv_data
    txt_data = b"\x0cfriendly=Lab"
    txt = b"\x06device\xc0\x0c" + struct.pack("!HHIH", 16, 1, 120, len(txt_data)) + txt_data
    records = _parse_records(header + ptr + srv + txt)
    assert any(record[1] == 12 and record[2] == "device._http._tcp.local." for record in records)
    assert any(record[1] == 33 and record[2] == (8080, "halgate.local.") for record in records)
    assert any(record[1] == 16 and record[2] == ["friendly=Lab"] for record in records)


def test_lan_tools_require_a_network_engagement(packages, tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    gate = ScopeGate([Engagement("eng-path", "files", str(root), "defensive")], packages, {})
    for tool in ("mdns_browse", "packet_capture"):
        ok, reason, _ = gate.authorize(tool, {"engagement_id": "eng-path"}, "eng-path")
        assert not ok
        assert "network-scoped" in reason


def test_packet_capture_schema_exposes_only_builtin_filters():
    properties = PACKET_CAPTURE_SCHEMA["parameters"]["properties"]
    assert "bpf" not in properties and "path" not in properties
    assert properties["protocol"]["enum"] == ["mdns", "dns", "dhcp", "tcp_syn"]
