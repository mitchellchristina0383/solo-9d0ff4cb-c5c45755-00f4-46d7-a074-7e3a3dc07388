"""Readers for classic PCAP / PCAPNG captures and Ethernet/IPv4/TCP decoding.

Only what the analyzer needs is implemented:

* classic pcap (both byte orders, microsecond and nanosecond resolution)
* pcapng (Section Header / Interface Description / Enhanced Packet /
  Simple Packet blocks, per-interface link types)
* link layers: Ethernet (incl. 802.1Q VLAN tags), raw IPv4, Linux SLL

Anything that is not IPv4/TCP is skipped.  Fragmented IP datagrams are
skipped as well (IP reassembly is out of scope; the TCP stream they
belonged to will simply show a gap and be marked unreliable).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# TCP flag bits
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

# link types
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_VLAN = (0x8100, 0x88A8, 0x9100)
_IPPROTO_TCP = 6


@dataclass
class TcpSegment:
    """One decoded TCP segment."""

    ts: float
    index: int  # position inside the capture file
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes  # payload bytes actually captured
    wire_payload_len: int  # payload length as it was on the wire

    @property
    def truncated(self) -> bool:
        """True when the capture cut the segment's payload short (snaplen)."""
        return len(self.payload) < self.wire_payload_len


def read_segments(data: bytes) -> list[TcpSegment]:
    """Decode all TCP segments from a capture file (pcap or pcapng)."""
    if len(data) < 4:
        raise ValueError("file too small to be a pcap/pcapng capture")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return _read_pcap(data)
    if magic == b"\x0a\x0d\x0d\x0a":
        return _read_pcapng(data)
    raise ValueError("unsupported capture format (not classic pcap or pcapng)")


# ---------------------------------------------------------------------------
# classic pcap
# ---------------------------------------------------------------------------

def _read_pcap(data: bytes) -> list[TcpSegment]:
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, nano = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, nano = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, nano = "<", True
    else:
        endian, nano = ">", True
    if len(data) < 24:
        raise ValueError("truncated pcap global header")
    _magic, _maj, _min, _tz, _sig, _snap, linktype = struct.unpack(
        endian + "IHHIIII", data[:24]
    )
    segments: list[TcpSegment] = []
    offset = 24
    index = 0
    while offset + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(
            endian + "IIII", data[offset : offset + 16]
        )
        offset += 16
        frame = data[offset : offset + incl_len]
        offset += incl_len
        ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
        seg = decode_frame(linktype, frame, ts, index)
        if seg is not None:
            segments.append(seg)
        index += 1
    return segments


# ---------------------------------------------------------------------------
# pcapng (minimal)
# ---------------------------------------------------------------------------

def _read_pcapng(data: bytes) -> list[TcpSegment]:
    segments: list[TcpSegment] = []
    offset = 0
    index = 0
    endian = "<"
    linktypes: list[int] = []
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        # The section header block type is palindromic; use it to (re)detect
        # byte order for each new section.
        if data[offset : offset + 4] == b"\x0a\x0d\x0d\x0a":
            if offset + 12 > len(data):
                break
            bom = data[offset + 8 : offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("pcapng: bad byte-order magic")
            block_len = struct.unpack_from(endian + "I", data, offset + 4)[0]
            linktypes = []
        if block_len < 12 or offset + block_len > len(data):
            break
        body = data[offset + 8 : offset + block_len - 4]
        if block_type == 0x00000001:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            linktypes.append(linktype)
        elif block_type == 0x00000006:  # Enhanced Packet Block
            if_id, ts_hi, ts_lo, cap_len, _orig_len = struct.unpack_from(
                endian + "IIIII", body, 0
            )
            frame = body[20 : 20 + cap_len]
            ts = ((ts_hi << 32) | ts_lo) / 1e6  # default resolution: microseconds
            linktype = linktypes[if_id] if if_id < len(linktypes) else LINKTYPE_ETHERNET
            seg = decode_frame(linktype, frame, ts, index)
            if seg is not None:
                segments.append(seg)
            index += 1
        elif block_type == 0x00000003:  # Simple Packet Block
            orig_len = struct.unpack_from(endian + "I", body, 0)[0]
            frame = body[4:]
            linktype = linktypes[0] if linktypes else LINKTYPE_ETHERNET
            seg = decode_frame(linktype, frame, 0.0, index)
            if seg is not None:
                segments.append(seg)
            index += 1
        offset += block_len
    return segments


# ---------------------------------------------------------------------------
# frame decoding
# ---------------------------------------------------------------------------

def decode_frame(linktype: int, frame: bytes, ts: float, index: int) -> TcpSegment | None:
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from("!H", frame, 12)[0]
        pos = 14
        while ethertype in _ETHERTYPE_VLAN:  # stacked VLAN tags
            if len(frame) < pos + 4:
                return None
            ethertype = struct.unpack_from("!H", frame, pos + 2)[0]
            pos += 4
        if ethertype != _ETHERTYPE_IPV4:
            return None
        ip = frame[pos:]
    elif linktype == LINKTYPE_RAW:
        ip = frame
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        if struct.unpack_from("!H", frame, 14)[0] != _ETHERTYPE_IPV4:
            return None
        ip = frame[16:]
    else:
        return None
    return _decode_ipv4(ip, ts, index)


def _decode_ipv4(ip: bytes, ts: float, index: int) -> TcpSegment | None:
    if len(ip) < 20:
        return None
    ver_ihl = ip[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    total_len = struct.unpack_from("!H", ip, 2)[0]
    if total_len < ihl:
        return None
    flags_frag = struct.unpack_from("!H", ip, 6)[0]
    more_fragments = bool(flags_frag & 0x2000)
    frag_offset = flags_frag & 0x1FFF
    if more_fragments or frag_offset != 0:
        return None  # fragmented: out of scope, will surface as a stream gap
    if ip[9] != _IPPROTO_TCP:
        return None
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    # bytes of the IP datagram that were actually captured
    captured = ip[:total_len] if len(ip) >= total_len else ip
    return _decode_tcp(captured[ihl:], total_len - ihl, ts, index, src_ip, dst_ip)


def _decode_tcp(
    segment: bytes, wire_len: int, ts: float, index: int, src_ip: str, dst_ip: str
) -> TcpSegment | None:
    if len(segment) < 20:
        return None
    src_port, dst_port, seq, ack = struct.unpack_from("!HHII", segment, 0)
    data_offset = (segment[12] >> 4) * 4
    if data_offset < 20 or len(segment) < data_offset:
        return None
    flags = segment[13]
    payload = segment[data_offset:]
    wire_payload_len = max(0, wire_len - data_offset)
    return TcpSegment(
        ts=ts,
        index=index,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        payload=payload,
        wire_payload_len=wire_payload_len,
    )
