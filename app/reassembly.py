"""TCP byte-stream reassembly for one direction of one connection.

Segments are placed by their sequence-number offset.  The merger:

* sorts out-of-order segments into position (no double counting),
* drops exact retransmissions and identical overlaps (no double counting),
* records a *conflict* when overlapping bytes disagree,
* records *gaps* where bytes never arrived,
* lets the caller flag *truncation* when a captured packet was cut short
  by the snaplen.

Reliability is judged only up to the end of the HTTP header block: a gap,
conflict or truncation anywhere before that point makes the direction
unreliable; anything after it is irrelevant for this tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field

HEADER_TERMINATOR = b"\r\n\r\n"


@dataclass
class AssembledStream:
    data: bytes  # gap-filled with NUL bytes so offsets stay absolute
    covered: int  # total span covered from offset 0 (including gaps)
    contiguous: int  # bytes contiguous from offset 0 (stops at first gap)
    gaps: list[tuple[int, int]]  # (offset, length) of missing ranges
    conflicts: list[int]  # offsets where overlapping bytes disagreed
    truncated: bool  # a packet in this direction was snaplen-truncated

    @property
    def header_end(self) -> int | None:
        """Offset just past the end of the header block, or None."""
        pos = self.data.find(HEADER_TERMINATOR)
        return pos + len(HEADER_TERMINATOR) if pos >= 0 else None

    def reliable_upto_header(self) -> bool:
        end = self.header_end
        if end is None:
            return False
        if self.truncated:
            return False
        if any(start < end for start, _len in self.gaps):
            return False
        if any(off < end for off in self.conflicts):
            return False
        return True


@dataclass
class DirectionStream:
    """Collects payload segments of one direction and merges them."""

    truncated: bool = False
    _segments: list[tuple[int, bytes]] = field(default_factory=list)

    def add(self, offset: int, data: bytes) -> None:
        if data:
            self._segments.append((offset, data))

    def mark_truncated(self) -> None:
        self.truncated = True

    @property
    def has_data(self) -> bool:
        return bool(self._segments)

    def build(self) -> AssembledStream:
        # Sort by offset; for identical offsets put the longer segment first
        # so a short retransmission is the one treated as "contained".
        segs = sorted(self._segments, key=lambda s: (s[0], -len(s[1])))
        buf = bytearray()
        covered = 0
        gaps: list[tuple[int, int]] = []
        conflicts: list[int] = []
        for off, data in segs:
            if off + len(data) <= covered:
                # Fully contained: retransmission or overlap of known bytes.
                if bytes(buf[off : off + len(data)]) != data:
                    conflicts.append(off)
                continue
            if off < covered:
                # Partial overlap: verify the shared bytes, keep the new tail.
                overlap = covered - off
                if bytes(buf[off:covered]) != data[:overlap]:
                    conflicts.append(off)
                data = data[overlap:]
                off = covered
            if off > covered:
                gaps.append((covered, off - covered))
                buf.extend(b"\x00" * (off - covered))
                covered = off
            buf.extend(data)
            covered += len(data)
        contiguous = gaps[0][0] if gaps else covered
        return AssembledStream(
            data=bytes(buf),
            covered=covered,
            contiguous=contiguous,
            gaps=gaps,
            conflicts=conflicts,
            truncated=self.truncated,
        )
