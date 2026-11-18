#!/usr/bin/env python3
"""Generate samples/arp_contention.pcap exercising every ARP-diagnosis path.

Story: the operator probes the registered gateway 192.168.1.1 from
10.0.0.10.  The capture (classic pcap, little-endian, Ethernet) contains:

  * one probe answered by TWO different MACs (registered gateway +
    impostor)                       -> suspected_contention
  * two repeated probes whose 500 ms wait windows overlap; both the
    gateway's and the impostor's replies land in the overlap
                                      -> replies pending review, NOT evidence
  * one probe answered by the gateway only
                                      -> single_responder
  * one probe with no reply at all    -> no_valid_reply
  * the same probe/reply exchange on VLAN 20 (correlation is per VLAN)
  * an impostor reply on VLAN 10 while the probe was on VLAN 20
                                      -> unmatched (cross-VLAN must not correlate)
  * an impostor reply cut by the snaplen
                                      -> excluded (truncated frames never count)
  * a gratuitous (broadcast) impostor reply
                                      -> unmatched (not directed at the prober)
  * one TCP frame and an ARP exchange for a *different* address
                                      -> ignored by the diagnosis

Layout (frame index -> content), wait window 500 ms:

  idx 0  t+1.000  req  P1 vlan10                 idx 9  t+5.000  req  P5 vlan10
  idx 1  t+1.010  rep  GW  ->P1 vlan10           idx 10 t+6.000  req  P6 vlan20
  idx 2  t+1.012  rep  BAD ->P1 vlan10           idx 11 t+6.010  rep  GW ->P6 vlan20
  idx 3  t+2.000  req  P2 vlan10                 idx 12 t+6.012  rep  BAD vlan10 (x-vlan)
  idx 4  t+2.100  req  P3 vlan10                 idx 13 t+6.020  rep  BAD vlan20 TRUNCATED
  idx 5  t+2.150  rep  GW  (pending)             idx 14 t+7.000  rep  BAD gratuitous bcast
  idx 6  t+2.160  rep  BAD (pending)             idx 15 t+8.000  TCP SYN (non-ARP)
  idx 7  t+4.000  req  P4 vlan10                 idx 16 t+8.100  req  who-has 192.168.1.254
  idx 8  t+4.010  rep  GW  ->P4 vlan10           idx 17 t+8.110  rep  192.168.1.254 is-at
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

PROBER_MAC = bytes.fromhex("020000000010")
PROBER_IP = "10.0.0.10"
GATEWAY_MAC = bytes.fromhex("020000000001")
GATEWAY_IP = "192.168.1.1"
IMPOSTOR_MAC = bytes.fromhex("020000000099")
OTHER_MAC = bytes.fromhex("0200000000fe")
OTHER_IP = "192.168.1.254"
BROADCAST = b"\xff" * 6
ZERO = b"\x00" * 6

VLAN_BLUE = 10
VLAN_RED = 20

OP_REQUEST = 1
OP_REPLY = 2


def ip_b(addr: str) -> bytes:
    return bytes(int(x) for x in addr.split("."))


def arp_packet(op: int, sha: bytes, spa: str, tha: bytes, tpa: str) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + ip_b(spa) + tha + ip_b(tpa)


def eth_frame(dst: bytes, src: bytes, payload: bytes,
              ethertype: int = 0x0806, vlan: int | None = None) -> bytes:
    if vlan is None:
        return dst + src + struct.pack("!H", ethertype) + payload
    return dst + src + struct.pack("!HHH", 0x8100, vlan, ethertype) + payload


def arp_request(prober_mac: bytes, prober_ip: str, target_ip: str,
                vlan: int | None = None) -> bytes:
    return eth_frame(BROADCAST, prober_mac,
                     arp_packet(OP_REQUEST, prober_mac, prober_ip, ZERO, target_ip),
                     vlan=vlan)


def arp_reply(claimer_mac: bytes, claimed_ip: str, target_mac: bytes, target_ip: str,
              vlan: int | None = None, broadcast: bool = False) -> bytes:
    dst = BROADCAST if broadcast else target_mac
    return eth_frame(dst, claimer_mac,
                     arp_packet(OP_REPLY, claimer_mac, claimed_ip, target_mac, target_ip),
                     vlan=vlan)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def tcp_junk_frame() -> bytes:
    """One ordinary IPv4/TCP SYN (non-ARP traffic the diagnosis must skip)."""
    src_ip, dst_ip = PROBER_IP, "93.184.216.34"
    tcp = struct.pack("!HHIIBBHHH", 40000, 80, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)
    pseudo = ip_b(src_ip) + ip_b(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    total_len = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000,
                     64, 6, 0, ip_b(src_ip), ip_b(dst_ip))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return eth_frame(PROBER_MAC, GATEWAY_MAC, ip + tcp, ethertype=0x0800)


class PcapWriter:
    def __init__(self) -> None:
        self.records: list[tuple[float, bytes, int]] = []
        self.base = 1_700_000_000.0

    def add(self, offset: float, frame: bytes, cut: int | None = None) -> None:
        """Append a frame at ``base + offset`` seconds; ``cut`` emulates snaplen."""
        if cut is not None:
            self.records.append((self.base + offset, frame[:cut], len(frame)))
        else:
            self.records.append((self.base + offset, frame, len(frame)))

    def to_bytes(self) -> bytes:
        out = [struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        for ts, data, orig_len in self.records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            out.append(struct.pack("<IIII", sec, usec, len(data), orig_len))
            out.append(data)
        return b"".join(out)


def build() -> bytes:
    w = PcapWriter()

    # --- idx 0-2: probe answered by gateway AND impostor -> contention -------
    w.add(1.000, arp_request(PROBER_MAC, PROBER_IP, GATEWAY_IP, vlan=VLAN_BLUE))
    w.add(1.010, arp_reply(GATEWAY_MAC, GATEWAY_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_BLUE))
    w.add(1.012, arp_reply(IMPOSTOR_MAC, GATEWAY_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_BLUE))

    # --- idx 3-6: overlapping wait windows -> replies pending, not evidence --
    w.add(2.000, arp_request(PROBER_MAC, PROBER_IP, GATEWAY_IP, vlan=VLAN_BLUE))
    w.add(2.100, arp_request(PROBER_MAC, PROBER_IP, GATEWAY_IP, vlan=VLAN_BLUE))
    w.add(2.150, arp_reply(GATEWAY_MAC, GATEWAY_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_BLUE))
    w.add(2.160, arp_reply(IMPOSTOR_MAC, GATEWAY_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_BLUE))

    # --- idx 7-8: clean probe, gateway only -> single_responder --------------
    w.add(4.000, arp_request(PROBER_MAC, PROBER_IP, GATEWAY_IP, vlan=VLAN_BLUE))
    w.add(4.010, arp_reply(GATEWAY_MAC, GATEWAY_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_BLUE))

    # --- idx 9: probe without any reply -> no_valid_reply --------------------
    w.add(5.000, arp_request(PROBER_MAC, PROBER_IP, GATEWAY_IP, vlan=VLAN_BLUE))

    # --- idx 10-11: same exchange on VLAN 20 (per-VLAN correlation) ----------
    w.add(6.000, arp_request(PROBER_MAC, PROBER_IP, GATEWAY_IP, vlan=VLAN_RED))
    w.add(6.010, arp_reply(GATEWAY_MAC, GATEWAY_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_RED))

    # --- idx 12: impostor reply on the WRONG VLAN -> unmatched ---------------
    w.add(6.012, arp_reply(IMPOSTOR_MAC, GATEWAY_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_BLUE))

    # --- idx 13: impostor reply on VLAN 20 but snaplen-truncated -> excluded --
    full = arp_reply(IMPOSTOR_MAC, GATEWAY_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_RED)
    w.add(6.020, full, cut=14 + 4 + 8)  # only eth+vlan+8 of 28 ARP bytes captured

    # --- idx 14: gratuitous broadcast reply -> unmatched ----------------------
    w.add(7.000, arp_reply(IMPOSTOR_MAC, GATEWAY_IP, BROADCAST, GATEWAY_IP,
                           vlan=VLAN_BLUE, broadcast=True))

    # --- idx 15: non-ARP traffic ---------------------------------------------
    w.add(8.000, tcp_junk_frame())

    # --- idx 16-17: ARP exchange for a different address -> ignored -----------
    w.add(8.100, arp_request(PROBER_MAC, PROBER_IP, OTHER_IP, vlan=VLAN_BLUE))
    w.add(8.110, arp_reply(OTHER_MAC, OTHER_IP, PROBER_MAC, PROBER_IP, vlan=VLAN_BLUE))

    return w.to_bytes()


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent.parent / "samples" / "arp_contention.pcap"
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
