"""ARP contention diagnostics over offline Ethernet captures.

Use case: a device on an isolated network is suspected of answering ARP
requests for a *registered* gateway IPv4 address.  Given a capture, the
gateway address and a reply-wait window, this module correlates ARP
probe requests ("who-has <gateway>") with ARP replies ("<gateway> is-at
<mac>") **per VLAN** and reports, for every probe, who answered.

Attribution rules (ARP has no transaction id, so they are deliberately
strict — a reply is only used as evidence when it is unambiguous):

* a reply is *attributable* to a probe only when it is the **single**
  probe that matches on all of: same VLAN, reply target (tpa/tha) equal
  to the prober's address (spa/sha), and reply timestamp inside the
  probe's wait window ``(probe.ts, probe.ts + wait]``;
* a reply matching **several** probes (repeated probes with overlapping
  wait windows) cannot be told apart — it is parked in ``pending_replies``
  and is **not** used as evidence for any of the candidate probes;
* a reply matching no captured probe is listed under
  ``unmatched_replies`` (gratuitous replies, answers to probes that were
  not captured, different VLAN, outside the wait window, ...);
* snaplen-truncated or otherwise incomplete ARP frames are excluded from
  every count and can never serve as evidence.

A probe reports ``suspected_contention`` only when **two different sender
MACs** have attributable replies for it.  One answering MAC is reported
as ``single_responder``; zero attributable replies as ``no_valid_reply``
(with a note when ambiguous replies are pending review).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .pcap import LINKTYPE_ETHERNET, CapturedFrame, read_frames

_ETHERTYPE_ARP = 0x0806
_ETHERTYPE_VLAN = (0x8100, 0x88A8, 0x9100)
_ARP_BODY_LEN = 28  # Ethernet/IPv4 ARP packet (htype..tpa)

OP_REQUEST = 1
OP_REPLY = 2


@dataclass
class ArpMessage:
    """One decoded Ethernet/IPv4 ARP packet."""

    ts: float
    index: int  # frame position inside the capture file
    vlan: int | None  # outermost 802.1Q VID, None when untagged
    op: int  # 1 = request, 2 = reply
    sha: str  # sender hardware address (the MAC making the claim)
    spa: str  # sender protocol address
    tha: str  # target hardware address
    tpa: str  # target protocol address


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def inspect_arp_frame(frame: CapturedFrame) -> tuple[str, ArpMessage | None]:
    """Classify one frame and decode it when it is a complete ARP packet.

    Returns one of:

    * ``("ok", message)``        – complete Ethernet/IPv4 ARP packet;
    * ``("not_arp", None)``      – not an ARP frame (or not Ethernet);
    * ``("truncated", None)``    – ARP frame cut short by the capture
      (snaplen) or too short to hold a full ARP body;
    * ``("malformed", None)``    – fully captured but not a standard
      Ethernet/IPv4 ARP packet (unexpected htype/ptype/hlen/plen).
    """
    if frame.linktype != LINKTYPE_ETHERNET:
        return ("not_arp", None)
    data = frame.data
    if len(data) < 14:
        return ("not_arp", None)
    ethertype = struct.unpack_from("!H", data, 12)[0]
    pos = 14
    vlan: int | None = None
    while ethertype in _ETHERTYPE_VLAN:  # stacked tags: correlate on outermost VID
        if len(data) < pos + 4:
            return ("not_arp", None)  # tag cut off: cannot tell what this was
        tci = struct.unpack_from("!H", data, pos)[0]
        if vlan is None:
            vlan = tci & 0x0FFF
        ethertype = struct.unpack_from("!H", data, pos + 2)[0]
        pos += 4
    if ethertype != _ETHERTYPE_ARP:
        return ("not_arp", None)
    # A frame cut by the snaplen is excluded even when the ARP body looks
    # complete: the packet *was* truncated, so it must not count as evidence.
    if frame.truncated or len(data) < pos + _ARP_BODY_LEN:
        return ("truncated", None)
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, pos)
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
        return ("malformed", None)
    return (
        "ok",
        ArpMessage(
            ts=frame.ts,
            index=frame.index,
            vlan=vlan,
            op=op,
            sha=_mac(data[pos + 8 : pos + 14]),
            spa=_ip4(data[pos + 14 : pos + 18]),
            tha=_mac(data[pos + 18 : pos + 24]),
            tpa=_ip4(data[pos + 24 : pos + 28]),
        ),
    )


def analyze_arp_contention(data: bytes, gateway_ip: str, wait_s: float) -> dict:
    """Decode a capture file and run the ARP contention diagnosis."""
    return diagnose_frames(read_frames(data), gateway_ip, wait_s)


def diagnose_frames(frames: list[CapturedFrame], gateway_ip: str, wait_s: float) -> dict:
    """Correlate ARP probes for ``gateway_ip`` with replies, per VLAN."""
    messages: list[ArpMessage] = []
    n_arp = n_truncated = n_malformed = 0
    for frame in frames:
        status, msg = inspect_arp_frame(frame)
        if status == "not_arp":
            continue
        n_arp += 1
        if status == "truncated":
            n_truncated += 1
        elif status == "malformed":
            n_malformed += 1
        else:
            messages.append(msg)

    probes = sorted(
        (m for m in messages if m.op == OP_REQUEST and m.tpa == gateway_ip),
        key=lambda m: (m.ts, m.index),
    )
    replies = sorted(
        (m for m in messages if m.op == OP_REPLY and m.spa == gateway_ip),
        key=lambda m: (m.ts, m.index),
    )

    # Attribute every reply to exactly one probe, or park it.  A reply is
    # attributable only when exactly one probe matches (same VLAN, reply
    # addressed to the prober, inside the wait window).
    probe_replies: list[list[ArpMessage]] = [[] for _ in probes]
    pending: list[tuple[ArpMessage, list[int]]] = []
    unmatched: list[ArpMessage] = []
    for rep in replies:
        candidates = [
            i
            for i, probe in enumerate(probes)
            if probe.vlan == rep.vlan
            and probe.spa == rep.tpa
            and probe.sha == rep.tha
            and probe.ts <= rep.ts <= probe.ts + wait_s
        ]
        if len(candidates) == 1:
            probe_replies[candidates[0]].append(rep)
        elif candidates:
            pending.append((rep, candidates))
        else:
            unmatched.append(rep)

    pending_per_probe = [0] * len(probes)
    for _rep, candidates in pending:
        for i in candidates:
            pending_per_probe[i] += 1

    findings: list[dict] = []
    n_contention = n_single = n_no_reply = 0
    for i, probe in enumerate(probes):
        by_mac: dict[str, list[int]] = {}
        for rep in probe_replies[i]:
            by_mac.setdefault(rep.sha, []).append(rep.index)
        probe_json = {
            "packet_index": probe.index,
            "timestamp": probe.ts,
            "vlan": probe.vlan,
            "prober_mac": probe.sha,
            "prober_ip": probe.spa,
        }
        if len(by_mac) >= 2:
            n_contention += 1
            findings.append(
                {
                    "probe": probe_json,
                    "status": "suspected_contention",
                    "detail": (
                        f"{len(by_mac)} different sender MACs answered this probe "
                        f"for {gateway_ip} within the wait window"
                    ),
                    "parties": [
                        {"sender_mac": mac, "reply_packets": sorted(indices)}
                        for mac, indices in sorted(by_mac.items())
                    ],
                }
            )
        elif len(by_mac) == 1:
            n_single += 1
            mac, indices = next(iter(by_mac.items()))
            findings.append(
                {
                    "probe": probe_json,
                    "status": "single_responder",
                    "detail": "only one sender MAC answered; no contention observed",
                    "responder_mac": mac,
                    "reply_packets": sorted(indices),
                }
            )
        else:
            n_no_reply += 1
            if pending_per_probe[i]:
                detail = (
                    "no reply could be unambiguously attributed to this probe: "
                    f"{pending_per_probe[i]} repl(ies) fall in overlapping probe "
                    "wait windows and are listed under pending_replies"
                )
            else:
                detail = "no reply for the gateway address arrived within the wait window"
            findings.append(
                {"probe": probe_json, "status": "no_valid_reply", "detail": detail}
            )

    pending_json = [
        {
            "packet_index": rep.index,
            "timestamp": rep.ts,
            "vlan": rep.vlan,
            "sender_mac": rep.sha,
            "target_mac": rep.tha,
            "target_ip": rep.tpa,
            "candidate_probe_packets": [probes[i].index for i in candidates],
            "reason": (
                f"matches {len(candidates)} probes whose wait windows overlap; "
                "ARP has no transaction id, so this reply cannot be attributed "
                "to a single probe and is not used as evidence"
            ),
        }
        for rep, candidates in pending
    ]
    unmatched_json = [
        {
            "packet_index": rep.index,
            "timestamp": rep.ts,
            "vlan": rep.vlan,
            "sender_mac": rep.sha,
            "target_mac": rep.tha,
            "target_ip": rep.tpa,
            "reason": (
                "no captured probe matches (different VLAN or target, outside "
                "the wait window, or the probe was not captured)"
            ),
        }
        for rep in unmatched
    ]

    verdict = (
        "suspected_contention"
        if n_contention
        else "no_contention_observed"
        if probes
        else "no_probes_found"
    )
    return {
        "gateway_ip": gateway_ip,
        "reply_wait_ms": wait_s * 1000.0,
        "verdict": verdict,
        "summary": {
            "frames_total": len(frames),
            "arp_frames": n_arp,
            "arp_truncated_excluded": n_truncated,
            "arp_malformed_excluded": n_malformed,
            "probes": len(probes),
            "replies": len(replies),
            "suspected_contentions": n_contention,
            "probes_single_responder": n_single,
            "probes_no_valid_reply": n_no_reply,
            "pending_replies": len(pending_json),
            "unmatched_replies": len(unmatched_json),
        },
        "findings": findings,
        "pending_replies": pending_json,
        "unmatched_replies": unmatched_json,
    }
