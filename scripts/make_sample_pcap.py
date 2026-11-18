#!/usr/bin/env python3
"""Generate samples/sample.pcap with flows exercising every code path.

Flows (all Ethernet/IPv4/TCP, classic pcap, little-endian):

  A  simple OK flow, request/response headers each split over 2 segments
  B  out-of-order delivery + identical retransmissions (must still be OK)
  C  gap in the request headers      -> request direction unreliable
  D  conflicting overlapping bytes in the response -> response unreliable
  E  no handshake captured           -> skipped
  F  destination port 8080           -> skipped
  G  two pipelined requests          -> skipped (not single-request)
  H  snaplen-truncated request packet -> request direction unreliable
  I  HTTP/1.0 request                -> skipped (not HTTP/1.1)
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ip_packet(src: str, dst: str, payload: bytes, proto: int = 6) -> bytes:
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0x4000, 64, proto, 0, src_b, dst_b,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int,
                seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                         5 << 4, flags, 65535, 0, 0)
    pseudo = (bytes(int(x) for x in src_ip.split("."))
              + bytes(int(x) for x in dst_ip.split("."))
              + struct.pack("!BBH", 0, 6, len(header) + len(payload)))
    csum = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return header + payload


def eth_frame(src_ip: str, dst_ip: str, tcp: bytes) -> bytes:
    return SERVER_MAC + CLIENT_MAC + b"\x08\x00" + ip_packet(src_ip, dst_ip, tcp)


class PcapWriter:
    def __init__(self) -> None:
        self.records: list[tuple[float, bytes, int]] = []
        self._ts = 1_700_000_000.0

    def tick(self, dt: float = 0.001) -> float:
        self._ts += dt
        return self._ts

    def add(self, frame: bytes, cut: int | None = None) -> None:
        """Append a frame; ``cut`` emulates snaplen truncation."""
        ts = self.tick()
        if cut is not None:
            self.records.append((ts, frame[:cut], len(frame)))
        else:
            self.records.append((ts, frame, len(frame)))

    def to_bytes(self) -> bytes:
        out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        for ts, data, orig_len in self.records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            out.append(struct.pack("<IIII", sec, usec, len(data), orig_len))
            out.append(data)
        return b"".join(out)


class Flow:
    """Bookkeeping helper for one client/server connection."""

    def __init__(self, w: PcapWriter, c_ip: str, c_port: int,
                 s_ip: str, s_port: int = 80,
                 c_isn: int = 1000, s_isn: int = 5000) -> None:
        self.w = w
        self.c = (c_ip, c_port)
        self.s = (s_ip, s_port)
        self.c_seq = c_isn
        self.s_seq = s_isn

    def _send(self, src, dst, seq, ack, flags, payload=b"", cut=None):
        frame = eth_frame(src[0], dst[0],
                          tcp_segment(src[0], dst[0], src[1], dst[1],
                                      seq, ack, flags, payload))
        self.w.add(frame, cut=cut)

    def handshake(self) -> None:
        self._send(self.c, self.s, self.c_seq, 0, SYN)
        self.c_seq += 1
        self._send(self.s, self.c, self.s_seq, self.c_seq, SYN | ACK)
        self.s_seq += 1
        self._send(self.c, self.s, self.c_seq, self.s_seq, ACK)

    def c2s(self, payload: bytes, seq: int | None = None, cut: int | None = None) -> int:
        seq = self.c_seq if seq is None else seq
        self._send(self.c, self.s, seq, self.s_seq, PSH | ACK, payload, cut=cut)
        self.c_seq = max(self.c_seq, seq + len(payload))
        return seq

    def s2c(self, payload: bytes, seq: int | None = None) -> int:
        seq = self.s_seq if seq is None else seq
        self._send(self.s, self.c, seq, self.c_seq, PSH | ACK, payload)
        self.s_seq = max(self.s_seq, seq + len(payload))
        return seq

    def close(self) -> None:
        self._send(self.c, self.s, self.c_seq, self.s_seq, FIN | ACK)
        self.c_seq += 1
        self._send(self.s, self.c, self.s_seq, self.c_seq, FIN | ACK)
        self.s_seq += 1
        self._send(self.c, self.s, self.c_seq, self.s_seq, ACK)


def build() -> bytes:
    w = PcapWriter()

    # --- A: simple OK flow, heads split over two segments each --------------
    f = Flow(w, "10.0.0.10", 50001, "93.184.216.34")
    f.handshake()
    req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
    f.c2s(req[:29])
    f.c2s(req[29:])
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    f.s2c(resp[:25])
    f.s2c(resp[25:])
    f.close()

    # --- B: out-of-order + identical retransmissions, still OK ---------------
    f = Flow(w, "10.0.0.11", 50002, "93.184.216.35")
    f.handshake()
    req = b"GET /page HTTP/1.1\r\nHost: retrans.example\r\n\r\n"
    p1, p2 = req[:20], req[20:]
    seq1, seq2 = f.c_seq, f.c_seq + len(p1)
    f.c2s(p2, seq=seq2)          # second half arrives first
    f.c2s(p1, seq=seq1)          # then the first half
    f.c2s(p1, seq=seq1)          # identical retransmission
    f.c2s(p2, seq=seq2)          # identical retransmission
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    r1, r2 = resp[:17], resp[17:]
    rseq = f.s_seq
    f.s2c(r2, seq=rseq + len(r1))
    f.s2c(r1, seq=rseq)
    f.s2c(r1, seq=rseq)              # duplicate
    f.close()

    # --- C: gap in the request headers ---------------------------------------
    f = Flow(w, "10.0.0.12", 50003, "93.184.216.36")
    f.handshake()
    q1 = b"GET /gap HTTP/1.1\r\n"
    q2 = b"Host: gap.example\r\n"   # never captured -> gap
    q3 = b"\r\n"
    f.c2s(q1)
    f.c2s(q3, seq=f.c_seq + len(q2))   # leaves a hole where q2 belongs
    f.s2c(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    f.close()

    # --- D: conflicting retransmission in the response -----------------------
    f = Flow(w, "10.0.0.13", 50004, "93.184.216.37")
    f.handshake()
    f.c2s(b"GET /conflict HTTP/1.1\r\nHost: conflict.example\r\n\r\n")
    resp_seq = f.s_seq
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    f.s2c(b"HTTP/1.1 500 ERR\r\n\r\n", seq=resp_seq)  # overlaps, differs
    f.close()

    # --- E: data without any handshake ---------------------------------------
    f = Flow(w, "10.0.0.14", 50005, "93.184.216.38")
    f.c_seq += 1  # pretend a handshake happened before the capture started
    f.s_seq += 1
    f.c2s(b"GET /nohs HTTP/1.1\r\nHost: nohs.example\r\n\r\n")

    # --- F: destination port 8080 --------------------------------------------
    f = Flow(w, "10.0.0.15", 50006, "93.184.216.39", s_port=8080)
    f.handshake()
    f.c2s(b"GET / HTTP/1.1\r\nHost: otherport.example\r\n\r\n")
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    f.close()

    # --- G: two pipelined requests on one connection -------------------------
    f = Flow(w, "10.0.0.16", 50007, "93.184.216.40")
    f.handshake()
    f.c2s(b"GET /1 HTTP/1.1\r\nHost: pipe.example\r\n\r\n"
          b"GET /2 HTTP/1.1\r\nHost: pipe.example\r\n\r\n")
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    f.close()

    # --- H: snaplen-truncated request packet ----------------------------------
    f = Flow(w, "10.0.0.17", 50008, "93.184.216.41")
    f.handshake()
    req = b"GET /truncated HTTP/1.1\r\nHost: trunc.example\r\n\r\n"
    header_len = 14 + 20 + 20  # eth + ip + tcp
    f.c2s(req, cut=header_len + 20)  # only the first 20 payload bytes captured
    f.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    f.close()

    # --- I: HTTP/1.0 request ---------------------------------------------------
    f = Flow(w, "10.0.0.18", 50009, "93.184.216.42")
    f.handshake()
    f.c2s(b"GET /old HTTP/1.0\r\n\r\n")
    f.s2c(b"HTTP/1.0 200 OK\r\n\r\n")
    f.close()

    return w.to_bytes()


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "samples" / "sample.pcap"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
