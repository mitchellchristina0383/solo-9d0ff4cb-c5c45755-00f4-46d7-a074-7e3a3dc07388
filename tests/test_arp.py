"""ARP contention diagnostics: attribution, overlap, VLAN, truncation, API."""

import struct
from pathlib import Path

from fastapi.testclient import TestClient

from app.arp import analyze_arp_contention
from app.main import app

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "arp_contention.pcap"

client = TestClient(app)

GW = "192.168.1.1"
PROBER_MAC = "020000000010"
PROBER_IP = "10.0.0.10"
GATEWAY_MAC = "020000000001"
IMPOSTOR_MAC = "020000000099"
BROADCAST = "ff" * 6
ZERO = "00" * 6
WAIT_S = 0.5


def ip_b(addr: str) -> bytes:
    return bytes(int(x) for x in addr.split("."))


def arp_frame(op, sha, spa, tha, tpa, vlan=None):
    body = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
        + bytes.fromhex(sha) + ip_b(spa) + bytes.fromhex(tha) + ip_b(tpa)
    )
    dst = bytes.fromhex(BROADCAST if op == 1 else tha)
    if vlan is None:
        return dst + bytes.fromhex(sha) + struct.pack("!H", 0x0806) + body
    return dst + bytes.fromhex(sha) + struct.pack("!HHH", 0x8100, vlan, 0x0806) + body


def request(ts, vlan=10, prober_mac=PROBER_MAC, prober_ip=PROBER_IP, target=GW):
    return (ts, arp_frame(1, prober_mac, prober_ip, ZERO, target, vlan), None)


def reply(ts, claimer=GATEWAY_MAC, vlan=10, target_mac=PROBER_MAC,
          target_ip=PROBER_IP, claimed=GW, cut=None):
    frame = arp_frame(2, claimer, claimed, target_mac, target_ip, vlan)
    if cut is not None:
        return (ts, frame[:cut], len(frame))
    return (ts, frame, None)


def pcap(records):
    out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for ts, frame, orig in records:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        out.append(struct.pack("<IIII", sec, usec, len(frame),
                               orig if orig is not None else len(frame)))
        out.append(frame)
    return b"".join(out)


def diagnose(records, wait=WAIT_S):
    return analyze_arp_contention(pcap(records), GW, wait)


def finding_for(result, packet_index):
    for f in result["findings"]:
        if f["probe"]["packet_index"] == packet_index:
            return f
    raise AssertionError(f"no finding for probe packet {packet_index}")


# ---------------------------------------------------------------------------
# unit tests on synthetic captures
# ---------------------------------------------------------------------------

def test_contention_two_macs_answer_same_probe():
    r = diagnose([request(1.0), reply(1.01, GATEWAY_MAC), reply(1.02, IMPOSTOR_MAC)])
    assert r["verdict"] == "suspected_contention"
    f = finding_for(r, 0)
    assert f["status"] == "suspected_contention"
    parties = {p["sender_mac"]: p["reply_packets"] for p in f["parties"]}
    assert parties == {
        "02:00:00:00:00:01": [1],
        "02:00:00:00:00:99": [2],
    }
    assert r["summary"]["suspected_contentions"] == 1


def test_same_mac_twice_is_single_responder_not_contention():
    r = diagnose([request(1.0), reply(1.01, GATEWAY_MAC), reply(1.02, GATEWAY_MAC)])
    f = finding_for(r, 0)
    assert f["status"] == "single_responder"
    assert f["responder_mac"] == "02:00:00:00:00:01"
    assert f["reply_packets"] == [1, 2]
    assert r["verdict"] == "no_contention_observed"


def test_overlapping_probe_windows_make_replies_pending_not_evidence():
    # Two probes 100 ms apart, wait 500 ms -> windows overlap.  Both replies
    # land in the overlap and match BOTH probes: ambiguous, must be parked.
    r = diagnose([
        request(2.0),                    # idx 0, window [2.0, 2.5]
        request(2.1),                    # idx 1, window [2.1, 2.6]
        reply(2.15, GATEWAY_MAC),        # idx 2, matches both
        reply(2.16, IMPOSTOR_MAC),       # idx 3, matches both
    ])
    assert r["verdict"] == "no_contention_observed"  # honest: evidence insufficient
    assert r["summary"]["suspected_contentions"] == 0
    assert r["summary"]["pending_replies"] == 2
    for pending in r["pending_replies"]:
        assert pending["candidate_probe_packets"] == [0, 1]
        assert "no transaction id" in pending["reason"]
    # neither probe may claim the parked replies
    for idx in (0, 1):
        f = finding_for(r, idx)
        assert f["status"] == "no_valid_reply"
        assert "pending" in f["detail"]
    # a reply must not be used twice: attributed replies total == 0
    assert all("reply_packets" not in f for f in r["findings"])


def test_sequential_probes_attribute_normally_when_windows_do_not_overlap():
    r = diagnose([
        request(1.0), reply(1.01, GATEWAY_MAC),    # window [1.0, 1.5]
        request(2.0), reply(2.01, IMPOSTOR_MAC),   # window [2.0, 2.5]
    ])
    assert finding_for(r, 0)["responder_mac"] == "02:00:00:00:00:01"
    assert finding_for(r, 2)["responder_mac"] == "02:00:00:00:00:99"
    assert r["summary"]["pending_replies"] == 0
    # each probe saw exactly one (different) MAC -> no contention anywhere
    assert r["verdict"] == "no_contention_observed"


def test_reply_in_other_vlan_is_not_attributed():
    r = diagnose([
        request(1.0, vlan=10),                  # idx 0
        reply(1.01, IMPOSTOR_MAC, vlan=20),     # idx 1: wrong VLAN
        reply(1.02, GATEWAY_MAC, vlan=10),      # idx 2: right VLAN
    ])
    f = finding_for(r, 0)
    assert f["status"] == "single_responder"
    assert f["responder_mac"] == "02:00:00:00:00:01"
    assert [u["packet_index"] for u in r["unmatched_replies"]] == [1]
    assert r["unmatched_replies"][0]["vlan"] == 20


def test_same_exchange_on_two_vlans_is_correlated_per_vlan():
    r = diagnose([
        request(1.0, vlan=10), reply(1.01, GATEWAY_MAC, vlan=10),
        request(2.0, vlan=20), reply(2.01, IMPOSTOR_MAC, vlan=20),
    ])
    assert finding_for(r, 0)["responder_mac"] == "02:00:00:00:00:01"
    assert finding_for(r, 2)["responder_mac"] == "02:00:00:00:00:99"
    assert r["summary"]["unmatched_replies"] == 0


def test_truncated_reply_never_counts_as_evidence():
    full = arp_frame(2, IMPOSTOR_MAC, GW, PROBER_MAC, PROBER_IP, 10)
    records = [
        request(1.0),                        # idx 0
        reply(1.01, GATEWAY_MAC),            # idx 1
        (1.02, full[:14 + 8], len(full)),    # idx 2: snaplen cut inside ARP body
    ]
    r = diagnose(records)
    f = finding_for(r, 0)
    assert f["status"] == "single_responder"  # NOT contention
    assert r["summary"]["arp_truncated_excluded"] == 1
    assert r["summary"]["replies"] == 1


def test_frame_cut_after_arp_body_still_excluded():
    # incl_len < orig_len even though the ARP body itself looks complete:
    # the packet was truncated, so it must not count.
    full = arp_frame(2, IMPOSTOR_MAC, GW, PROBER_MAC, PROBER_IP, 10)
    records = [
        request(1.0),
        reply(1.01, GATEWAY_MAC),
        (1.02, full[:-2], len(full)),  # only padding/FCS missing, still cut
    ]
    r = diagnose(records)
    assert finding_for(r, 0)["status"] == "single_responder"
    assert r["summary"]["arp_truncated_excluded"] == 1


def test_no_reply_within_window():
    r = diagnose([request(1.0)])
    f = finding_for(r, 0)
    assert f["status"] == "no_valid_reply"
    assert "no reply" in f["detail"]
    assert r["verdict"] == "no_contention_observed"


def test_reply_outside_wait_window_is_unmatched():
    r = diagnose([request(1.0), reply(1.0 + WAIT_S + 0.01, GATEWAY_MAC)])
    assert finding_for(r, 0)["status"] == "no_valid_reply"
    assert [u["packet_index"] for u in r["unmatched_replies"]] == [1]


def test_gratuitous_broadcast_reply_is_unmatched():
    r = diagnose([
        request(1.0),
        reply(1.01, GATEWAY_MAC),
        (1.02, arp_frame(2, IMPOSTOR_MAC, GW, BROADCAST, GW, 10), None),
    ])
    assert finding_for(r, 0)["status"] == "single_responder"
    assert [u["packet_index"] for u in r["unmatched_replies"]] == [2]


def test_traffic_for_other_addresses_is_ignored():
    r = diagnose([
        request(1.0), reply(1.01, GATEWAY_MAC),
        request(2.0, target="192.168.1.254"),               # not our gateway
        reply(2.01, "0200000000fe", claimed="192.168.1.254"),
    ])
    assert r["summary"]["probes"] == 1
    assert r["summary"]["replies"] == 1
    assert r["summary"]["unmatched_replies"] == 0


def test_untagged_frames_correlate_with_untagged_only():
    r = diagnose([
        request(1.0, vlan=None), reply(1.01, GATEWAY_MAC, vlan=None),
        reply(1.02, IMPOSTOR_MAC, vlan=10),  # tagged reply must not leak in
    ])
    f = finding_for(r, 0)
    assert f["status"] == "single_responder"
    assert f["probe"]["vlan"] is None
    assert [u["packet_index"] for u in r["unmatched_replies"]] == [2]


def test_no_probes_found_verdict():
    r = diagnose([reply(1.0, GATEWAY_MAC)])
    assert r["verdict"] == "no_probes_found"
    assert r["findings"] == []
    assert r["summary"]["unmatched_replies"] == 1


# ---------------------------------------------------------------------------
# API tests against the bundled ARP sample
# ---------------------------------------------------------------------------

def analyze_arp_sample(wait_ms=500.0):
    with SAMPLE.open("rb") as fh:
        resp = client.post(
            "/analyze/arp",
            files={"file": ("arp_contention.pcap", fh)},
            data={"gateway_ip": GW, "wait_ms": str(wait_ms)},
        )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_sample_file_exists():
    assert SAMPLE.exists(), "run scripts/make_arp_sample_pcap.py"


def test_api_sample_summary_counts():
    r = analyze_arp_sample()
    s = r["summary"]
    assert s["frames_total"] == 18
    assert s["arp_frames"] == 17
    assert s["arp_truncated_excluded"] == 1
    assert s["probes"] == 6
    assert s["replies"] == 8
    assert s["suspected_contentions"] == 1
    assert s["probes_single_responder"] == 2
    assert s["probes_no_valid_reply"] == 3
    assert s["pending_replies"] == 2
    assert s["unmatched_replies"] == 2
    assert r["verdict"] == "suspected_contention"


def test_api_sample_contention_finding_lists_probe_parties_and_packets():
    r = analyze_arp_sample()
    f = finding_for(r, 0)
    assert f["status"] == "suspected_contention"
    assert f["probe"]["vlan"] == 10
    assert f["probe"]["prober_ip"] == PROBER_IP
    parties = {p["sender_mac"]: p["reply_packets"] for p in f["parties"]}
    assert parties == {"02:00:00:00:00:01": [1], "02:00:00:00:00:99": [2]}


def test_api_sample_overlap_replies_are_pending_not_evidence():
    r = analyze_arp_sample()
    pending = {p["packet_index"]: p for p in r["pending_replies"]}
    assert set(pending) == {5, 6}
    assert pending[5]["candidate_probe_packets"] == [3, 4]
    assert pending[6]["candidate_probe_packets"] == [3, 4]
    # the overlapping probes got no usable evidence
    assert finding_for(r, 3)["status"] == "no_valid_reply"
    assert finding_for(r, 4)["status"] == "no_valid_reply"


def test_api_sample_cross_vlan_and_truncation():
    r = analyze_arp_sample()
    # VLAN 20 probe (idx 10): only the gateway's VLAN-20 reply counts; the
    # impostor's VLAN-20 reply was truncated and the VLAN-10 one is foreign.
    f = finding_for(r, 10)
    assert f["status"] == "single_responder"
    assert f["responder_mac"] == "02:00:00:00:00:01"
    unmatched = {u["packet_index"] for u in r["unmatched_replies"]}
    assert unmatched == {12, 14}  # cross-VLAN impostor + gratuitous broadcast


def test_api_sample_endpoints():
    resp = client.post("/analyze/arp/sample")
    assert resp.status_code == 200, resp.text
    assert resp.json()["verdict"] == "suspected_contention"
    resp = client.get("/sample/arp")
    assert resp.status_code == 200
    assert resp.content == SAMPLE.read_bytes()


def test_api_rejects_bad_gateway_ip():
    with SAMPLE.open("rb") as fh:
        resp = client.post(
            "/analyze/arp",
            files={"file": ("x.pcap", fh)},
            data={"gateway_ip": "999.1.2.3", "wait_ms": "500"},
        )
    assert resp.status_code == 400


def test_api_rejects_bad_wait_and_empty_file():
    with SAMPLE.open("rb") as fh:
        resp = client.post(
            "/analyze/arp",
            files={"file": ("x.pcap", fh)},
            data={"gateway_ip": GW, "wait_ms": "0"},
        )
    assert resp.status_code == 400
    resp = client.post(
        "/analyze/arp",
        files={"file": ("empty.pcap", b"")},
        data={"gateway_ip": GW, "wait_ms": "500"},
    )
    assert resp.status_code == 400


def test_api_rejects_non_pcap_upload():
    resp = client.post(
        "/analyze/arp",
        files={"file": ("x.bin", b"definitely not a pcap")},
        data={"gateway_ip": GW, "wait_ms": "500"},
    )
    assert resp.status_code == 400


def test_http_analysis_still_works():
    # regression: the original HTTP endpoint is untouched by the ARP feature
    resp = client.post("/analyze/sample")
    assert resp.status_code == 200
    assert resp.json()["summary"]["flows"] == 9
