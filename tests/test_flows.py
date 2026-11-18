"""Flow-level tests: handshake handling, reliability, single-request scope."""

from app.flows import analyze_flow
from app.pcap import ACK, PSH, SYN, TcpSegment

_idx = [0]


def seg(src_ip, sport, dst_ip, dport, seq, ack, flags, payload=b"",
        wire_len=None, ts=1.0):
    _idx[0] += 1
    return TcpSegment(
        ts=ts + _idx[0] * 0.001,
        index=_idx[0],
        src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport,
        seq=seq, ack=ack, flags=flags, payload=payload,
        wire_payload_len=len(payload) if wire_len is None else wire_len,
    )


C = ("10.0.0.1", 40000)
S = ("93.184.216.34", 80)


def handshake(c_isn=100, s_isn=900):
    return [
        seg(*C, *S, c_isn, 0, SYN),
        seg(*S, *C, s_isn, c_isn + 1, SYN | ACK),
        seg(*C, *S, c_isn + 1, s_isn + 1, ACK),
    ]


def data(src, dst, seq, ack, payload, **kw):
    return seg(*src, *dst, seq, ack, PSH | ACK, payload, **kw)


REQ = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


def test_ok_flow():
    segs = handshake() + [
        data(C, S, 101, 901, REQ[:15]),
        data(C, S, 116, 901, REQ[15:]),
        data(S, C, 901, 101 + len(REQ), RESP),
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "ok"
    assert r["connection"]["client"] == "10.0.0.1:40000"
    assert r["connection"]["server"] == "93.184.216.34:80"
    assert r["request"]["request_line"] == "GET / HTTP/1.1"
    assert r["request"]["host"] == "example.com"
    assert r["response"]["status_code"] == 200


def test_retransmission_and_out_of_order_not_double_counted():
    segs = handshake() + [
        data(C, S, 115, 901, REQ[14:]),   # second chunk first
        data(C, S, 101, 901, REQ[:14]),   # then the first chunk
        data(C, S, 101, 901, REQ[:14]),   # identical retransmission
        data(C, S, 115, 901, REQ[14:]),   # identical retransmission
        data(S, C, 901, 138, RESP),
        data(S, C, 901, 138, RESP),       # duplicate response
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "ok"
    assert r["request"]["host"] == "example.com"
    d = r["directions"]["client_to_server"]
    assert d["reassembled_bytes"] == len(REQ)
    assert d["gaps"] == [] and d["conflicts"] == []


def test_gap_in_request_headers_marks_direction_unreliable():
    # bytes 0..13 of the request missing -> gap before end of headers
    segs = handshake() + [
        data(C, S, 101 + 13, 901, REQ[13:]),
        data(S, C, 901, 101 + len(REQ), RESP),
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "unreliable"
    assert r["request"] is None
    assert r["response"]["status_code"] == 200  # other direction still reported
    d = r["directions"]["client_to_server"]
    assert not d["reliable"] and d["gaps"] == [{"offset": 0, "length": 13}]
    assert r["directions"]["server_to_client"]["reliable"]


def test_conflicting_overlap_marks_response_unreliable():
    segs = handshake() + [
        data(C, S, 101, 901, REQ),
        data(S, C, 901, 138, RESP),
        data(S, C, 901, 138, b"HTTP/1.1 500 ERR\r\n\r\n"),  # conflicts
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "unreliable"
    assert r["request"]["host"] == "example.com"  # request side still reported
    assert r["response"] is None
    d = r["directions"]["server_to_client"]
    assert not d["reliable"] and d["conflicts"]


def test_truncated_packet_marks_direction_unreliable():
    segs = handshake() + [
        data(C, S, 101, 901, REQ[:20], wire_len=len(REQ)),  # snaplen cut
        data(S, C, 901, 101 + len(REQ), RESP),
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "unreliable"
    assert r["request"] is None
    assert r["response"]["status_code"] == 200
    assert r["directions"]["client_to_server"]["truncated"]


def test_missing_handshake_is_skipped():
    r = analyze_flow(0, [data(C, S, 101, 901, REQ)])
    assert r["status"] == "skipped"
    assert "handshake" in r["reasons"][0]


def test_incomplete_handshake_is_skipped():
    segs = handshake()[:2]  # SYN + SYN-ACK only
    r = analyze_flow(0, segs)
    assert r["status"] == "skipped"
    assert "final ACK" in r["reasons"][0]


def test_non_port_80_is_skipped():
    segs = [
        seg(*C, "93.184.216.34", 8080, 100, 0, SYN),
        seg("93.184.216.34", 8080, *C, 900, 101, SYN | ACK),
        seg(*C, "93.184.216.34", 8080, 101, 901, ACK),
        data(C, ("93.184.216.34", 8080), 101, 901, REQ),
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "skipped"
    assert "not 80" in r["reasons"][0]


def test_http10_is_skipped():
    segs = handshake() + [
        data(C, S, 101, 901, b"GET / HTTP/1.0\r\n\r\n"),
        data(S, C, 901, 118, b"HTTP/1.0 200 OK\r\n\r\n"),
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "skipped"
    assert "HTTP/1.1" in r["reasons"][0]


def test_pipelined_requests_are_skipped():
    two = REQ + b"GET /2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    segs = handshake() + [
        data(C, S, 101, 901, two),
        data(S, C, 901, 101 + len(two), RESP),
        data(S, C, 901 + len(RESP), 101 + len(two), RESP),
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "skipped"
    assert "more than one request" in r["reasons"][0]


def test_non_http_traffic_is_skipped():
    segs = handshake() + [data(C, S, 101, 901, b"\x00\x01\x02binarygarbage")]
    r = analyze_flow(0, segs)
    assert r["status"] == "skipped"


def test_unreliable_request_does_not_steal_another_response():
    """A gapped request must not get a response 'assigned' from elsewhere:
    the response shown is the one on the *same* connection, and the request
    fields stay null."""
    segs = handshake() + [
        data(C, S, 101 + 5, 901, REQ[5:]),  # gap at the start
        data(S, C, 901, 200, b"HTTP/1.1 503 Unavailable\r\n\r\n"),
    ]
    r = analyze_flow(0, segs)
    assert r["status"] == "unreliable"
    assert r["request"] is None
    assert r["response"]["status_code"] == 503
