"""End-to-end tests against the FastAPI app and the bundled sample pcap."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "sample.pcap"

client = TestClient(app)


def analyze_sample() -> dict:
    with SAMPLE.open("rb") as fh:
        resp = client.post("/analyze", files={"file": ("sample.pcap", fh)})
    assert resp.status_code == 200, resp.text
    return resp.json()


def flow_by_client_port(result: dict, port: int) -> dict:
    for flow in result["flows"]:
        conn = flow.get("connection") or {}
        if conn.get("client_port") == port:
            return flow
    raise AssertionError(f"flow with client port {port} not found")


def test_root_and_docs():
    assert client.get("/").status_code == 200
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_sample_endpoint_download():
    resp = client.get("/sample")
    assert resp.status_code == 200
    assert resp.content == SAMPLE.read_bytes()


def test_analyze_sample_endpoint():
    resp = client.post("/analyze/sample")
    assert resp.status_code == 200
    assert resp.json()["summary"]["flows"] == 9


def test_summary_counts():
    result = analyze_sample()
    summary = result["summary"]
    assert summary["flows"] == 9
    assert summary["ok"] == 2          # A (simple) + B (retrans/out-of-order)
    assert summary["unreliable"] == 3  # C (gap) + D (conflict) + H (truncated)
    assert summary["skipped"] == 4     # E, F, G, I


def test_simple_ok_flow():
    flow = flow_by_client_port(analyze_sample(), 50001)
    assert flow["status"] == "ok"
    assert flow["connection"]["server"] == "93.184.216.34:80"
    assert flow["request"]["request_line"] == "GET /index.html HTTP/1.1"
    assert flow["request"]["host"] == "example.com"
    assert flow["response"]["status_code"] == 200


def test_retransmission_flow_ok_and_not_double_counted():
    flow = flow_by_client_port(analyze_sample(), 50002)
    assert flow["status"] == "ok"
    assert flow["request"]["request_line"] == "GET /page HTTP/1.1"
    assert flow["request"]["host"] == "retrans.example"
    assert flow["response"]["status_code"] == 200
    d = flow["directions"]["client_to_server"]
    assert d["reassembled_bytes"] == len(b"GET /page HTTP/1.1\r\nHost: retrans.example\r\n\r\n")
    assert d["gaps"] == [] and d["conflicts"] == []


def test_gap_flow_request_unreliable_response_kept():
    flow = flow_by_client_port(analyze_sample(), 50003)
    assert flow["status"] == "unreliable"
    assert flow["request"] is None
    assert flow["response"]["status_code"] == 404
    d = flow["directions"]["client_to_server"]
    assert not d["reliable"]
    assert d["gaps"] and d["gaps"][0]["length"] == len(b"Host: gap.example\r\n")


def test_conflict_flow_response_unreliable_request_kept():
    flow = flow_by_client_port(analyze_sample(), 50004)
    assert flow["status"] == "unreliable"
    assert flow["request"]["host"] == "conflict.example"
    assert flow["response"] is None
    assert flow["directions"]["server_to_client"]["conflicts"]


def test_no_handshake_skipped():
    flow = flow_by_client_port(analyze_sample(), 50005)
    assert flow["status"] == "skipped"
    assert "handshake" in flow["reasons"][0]


def test_other_port_skipped():
    flow = flow_by_client_port(analyze_sample(), 50006)
    assert flow["status"] == "skipped"
    assert "not 80" in flow["reasons"][0]


def test_pipelined_skipped():
    flow = flow_by_client_port(analyze_sample(), 50007)
    assert flow["status"] == "skipped"
    assert "more than one request" in flow["reasons"][0]


def test_truncated_flow_unreliable():
    flow = flow_by_client_port(analyze_sample(), 50008)
    assert flow["status"] == "unreliable"
    assert flow["request"] is None
    assert flow["response"]["status_code"] == 200
    assert flow["directions"]["client_to_server"]["truncated"]


def test_http10_skipped():
    flow = flow_by_client_port(analyze_sample(), 50009)
    assert flow["status"] == "skipped"
    assert "HTTP/1.1" in flow["reasons"][0]


def test_bad_upload_rejected():
    resp = client.post("/analyze", files={"file": ("x.bin", b"not a pcap")})
    assert resp.status_code == 400
