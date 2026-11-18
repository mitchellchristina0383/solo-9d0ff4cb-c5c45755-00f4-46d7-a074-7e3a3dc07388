"""Group TCP segments into connections and analyse each HTTP/1.1 flow."""

from __future__ import annotations

from .httpmsg import (
    looks_like_http_request_start,
    parse_request_head,
    parse_response_head,
)
from .pcap import ACK, SYN, TcpSegment
from .reassembly import AssembledStream, DirectionStream

_MOD32 = 1 << 32
_HALF32 = 1 << 31


def flow_key(seg: TcpSegment) -> tuple:
    """Direction-independent connection key (4-tuple, normalised)."""
    a = (seg.src_ip, seg.src_port)
    b = (seg.dst_ip, seg.dst_port)
    return (a, b) if a <= b else (b, a)


def group_flows(segments: list[TcpSegment]) -> dict[tuple, list[TcpSegment]]:
    flows: dict[tuple, list[TcpSegment]] = {}
    for seg in segments:
        flows.setdefault(flow_key(seg), []).append(seg)
    return flows


def _direction_report(stream: AssembledStream, reliable: bool) -> dict:
    return {
        "reliable": reliable,
        "header_complete": stream.header_end is not None,
        "reassembled_bytes": stream.covered,
        "contiguous_bytes": stream.contiguous,
        "gaps": [{"offset": off, "length": length} for off, length in stream.gaps],
        "conflicts": stream.conflicts,
        "truncated": stream.truncated,
    }


def _skipped(flow_id: int, segs: list[TcpSegment], reason: str,
             client: tuple | None = None, server: tuple | None = None) -> dict:
    result = {
        "id": flow_id,
        "status": "skipped",
        "reasons": [reason],
        "connection": None,
        "request": None,
        "response": None,
        "directions": None,
        "packet_count": len(segs),
        "first_seen": min(s.ts for s in segs),
        "last_seen": max(s.ts for s in segs),
    }
    if client and server:
        result["connection"] = _connection_dict(client, server)
    return result


def _connection_dict(client: tuple, server: tuple) -> dict:
    return {
        "client": f"{client[0]}:{client[1]}",
        "server": f"{server[0]}:{server[1]}",
        "client_ip": client[0],
        "client_port": client[1],
        "server_ip": server[0],
        "server_port": server[1],
    }


def analyze_flow(flow_id: int, segments: list[TcpSegment]) -> dict:
    """Analyse one connection.

    Returns a JSON-serialisable dict.  ``status`` is one of:

    * ``ok``         – handshake + single HTTP/1.1 request + response, both
                       directions reliably reassembled up to header end;
    * ``unreliable`` – targeted flow, but at least one direction has a gap /
                       conflict / truncation before the end of its headers;
    * ``skipped``    – flow is outside the scope of this tool (no complete
                       handshake, not port 80, not HTTP/1.1, more than one
                       request on the connection, ...).
    """
    segs = sorted(segments, key=lambda s: (s.ts, s.index))

    # --- three-way handshake must be fully captured -------------------------
    syn = next((s for s in segs if s.flags & SYN and not s.flags & ACK), None)
    if syn is None:
        first = segs[0]
        return _skipped(flow_id, segs, "no TCP handshake (SYN) captured",
                        (first.src_ip, first.src_port),
                        (first.dst_ip, first.dst_port))
    client = (syn.src_ip, syn.src_port)
    server = (syn.dst_ip, syn.dst_port)

    synack = next(
        (
            s for s in segs
            if (s.src_ip, s.src_port) == server
            and s.flags & SYN
            and s.flags & ACK
            and (s.ack - syn.seq) % _MOD32 == 1
        ),
        None,
    )
    if synack is None:
        return _skipped(flow_id, segs,
                        "incomplete handshake: SYN-ACK not captured", client, server)

    ack3 = next(
        (
            s for s in segs
            if (s.src_ip, s.src_port) == client
            and s.flags & ACK
            and not s.flags & SYN
            and (s.ack - synack.seq) % _MOD32 == 1
            and (s.ts, s.index) >= (synack.ts, synack.index)
        ),
        None,
    )
    if ack3 is None:
        return _skipped(flow_id, segs,
                        "incomplete handshake: final ACK not captured", client, server)

    if server[1] != 80:
        return _skipped(flow_id, segs,
                        f"destination port {server[1]} is not 80", client, server)

    # --- reassemble both directions -----------------------------------------
    base_c2s = (syn.seq + 1) % _MOD32
    base_s2c = (synack.seq + 1) % _MOD32
    c2s, s2c = DirectionStream(), DirectionStream()
    for s in segs:
        if (s.src_ip, s.src_port) == client:
            stream, base = c2s, base_c2s
        else:
            stream, base = s2c, base_s2c
        if s.truncated and s.wire_payload_len > 0:
            stream.mark_truncated()
        offset = (s.seq - base) % _MOD32
        if offset < _HALF32:  # guards against pre-handshake sequence numbers
            stream.add(offset, s.payload)

    req_stream = c2s.build()
    resp_stream = s2c.build()
    req_reliable = req_stream.reliable_upto_header()
    resp_reliable = resp_stream.reliable_upto_header()

    conn = _connection_dict(client, server)
    reasons: list[str] = []

    # --- request side ---------------------------------------------------------
    if not c2s.has_data:
        return _skipped(flow_id, segs, "no client-to-server data", client, server)

    request_json = None
    if req_reliable:
        req = parse_request_head(req_stream.data)
        if req is None:
            return _skipped(flow_id, segs,
                            "client data is not a parseable HTTP request", client, server)
        if req.version != "HTTP/1.1":
            return _skipped(flow_id, segs,
                            f"request version {req.version} is not HTTP/1.1", client, server)
        # Scope: exactly one request per connection.  Any byte beyond the
        # first request message (headers + Content-Length body) means a
        # second/pipelined request; pairing responses would be ambiguous.
        message_end = req.header_end + req.content_length
        if req_stream.covered > message_end:
            return _skipped(
                flow_id, segs,
                "connection carries more than one request "
                "(only single-request connections are analysed)",
                client, server,
            )
        request_json = {
            "request_line": req.request_line,
            "method": req.method,
            "target": req.target,
            "version": req.version,
            "host": req.host,
        }
    else:
        prefix = req_stream.data[: req_stream.contiguous]
        if prefix and not looks_like_http_request_start(prefix):
            return _skipped(flow_id, segs,
                            "client data does not look like an HTTP request",
                            client, server)
        reasons.append("client_to_server: " + _unreliable_reason(req_stream))

    # --- response side --------------------------------------------------------
    response_json = None
    if resp_reliable:
        resp = parse_response_head(resp_stream.data)
        if resp is None:
            resp_reliable = False
            reasons.append("server_to_client: response head is not a parseable "
                           "HTTP response")
        else:
            response_json = {
                "status_line": resp.status_line,
                "version": resp.version,
                "status_code": resp.status_code,
                "reason": resp.reason,
            }
    if not resp_reliable and not any(r.startswith("server_to_client") for r in reasons):
        reasons.append("server_to_client: " + _unreliable_reason(resp_stream))

    status = "ok" if (req_reliable and resp_reliable and request_json
                      and response_json) else "unreliable"
    return {
        "id": flow_id,
        "status": status,
        "reasons": reasons,
        "connection": conn,
        "request": request_json,
        "response": response_json,
        "directions": {
            "client_to_server": _direction_report(req_stream, req_reliable),
            "server_to_client": _direction_report(resp_stream, resp_reliable),
        },
        "packet_count": len(segs),
        "first_seen": segs[0].ts,
        "last_seen": segs[-1].ts,
    }


def _unreliable_reason(stream: AssembledStream) -> str:
    parts = []
    if stream.header_end is None:
        parts.append("headers incomplete (end of header block not captured)")
    if stream.truncated:
        parts.append("a packet was truncated by the capture (snaplen)")
    pre_header_gaps = [
        (off, length) for off, length in stream.gaps
        if stream.header_end is None or off < stream.header_end
    ]
    if pre_header_gaps:
        parts.append(
            "gap(s) before end of headers: "
            + ", ".join(f"{length}B@{off}" for off, length in pre_header_gaps)
        )
    end = stream.header_end
    pre_header_conflicts = [o for o in stream.conflicts if end is None or o < end]
    if pre_header_conflicts:
        parts.append("conflicting overlapping bytes at offset(s) "
                     + ", ".join(str(o) for o in pre_header_conflicts))
    return "; ".join(parts) if parts else "unreliable"
