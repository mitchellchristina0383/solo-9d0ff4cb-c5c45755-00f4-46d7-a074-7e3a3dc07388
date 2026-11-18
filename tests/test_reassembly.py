"""Unit tests for TCP byte-stream reassembly."""

from app.reassembly import DirectionStream


def build(segments, truncated=False):
    ds = DirectionStream()
    for offset, data in segments:
        ds.add(offset, data)
    if truncated:
        ds.mark_truncated()
    return ds.build()


class TestMerge:
    def test_in_order(self):
        a = build([(0, b"hello "), (6, b"world")])
        assert a.data == b"hello world"
        assert a.gaps == [] and a.conflicts == []
        assert a.contiguous == 11

    def test_out_of_order(self):
        a = build([(6, b"world"), (0, b"hello ")])
        assert a.data == b"hello world"
        assert a.gaps == [] and a.conflicts == []

    def test_identical_retransmission_not_double_counted(self):
        a = build([(0, b"hello "), (0, b"hello "), (6, b"world"), (6, b"world")])
        assert a.data == b"hello world"
        assert a.covered == 11
        assert a.gaps == [] and a.conflicts == []

    def test_identical_overlap_not_double_counted(self):
        a = build([(0, b"abcdef"), (3, b"defxyz")])
        assert a.data == b"abcdefxyz"
        assert a.conflicts == []

    def test_contained_segment_with_same_bytes(self):
        a = build([(0, b"abcdef"), (2, b"cd")])
        assert a.data == b"abcdef"
        assert a.conflicts == []


class TestGaps:
    def test_gap_recorded(self):
        a = build([(0, b"GET "), (8, b"HTTP/1.1\r\n\r\n")])
        assert a.gaps == [(4, 4)]
        assert a.contiguous == 4

    def test_gap_before_header_end_is_unreliable(self):
        a = build([(0, b"GET "), (8, b"HTTP/1.1\r\n\r\n")])
        assert a.header_end is not None  # terminator found after the gap
        assert not a.reliable_upto_header()

    def test_gap_after_header_end_is_fine(self):
        a = build([(0, b"GET / HTTP/1.1\r\n\r\n"), (30, b"later")])
        assert a.reliable_upto_header()

    def test_missing_header_terminator_is_unreliable(self):
        a = build([(0, b"GET / HTTP/1.1\r\nHost: x")])
        assert a.header_end is None
        assert not a.reliable_upto_header()


class TestConflicts:
    def test_conflicting_overlap(self):
        a = build([(0, b"abcdef"), (3, b"XYZ")])
        assert a.conflicts == [3]

    def test_conflicting_retransmission_same_range(self):
        a = build([(0, b"HTTP/1.1 200 OK\r\n\r\n"), (0, b"HTTP/1.1 500 ERR\r\n\r\n")])
        assert a.conflicts == [0]
        assert not a.reliable_upto_header()

    def test_conflict_after_header_end_is_fine(self):
        a = build([(0, b"GET / HTTP/1.1\r\n\r\nXXXX"), (19, b"YYYY")])
        assert a.conflicts  # conflict exists...
        assert a.reliable_upto_header()  # ...but only after the headers


class TestTruncation:
    def test_truncated_direction_is_unreliable(self):
        a = build([(0, b"GET / HTTP/1.1\r\n\r\n")], truncated=True)
        assert a.truncated
        assert not a.reliable_upto_header()

    def test_untruncated_is_reliable(self):
        a = build([(0, b"GET / HTTP/1.1\r\n\r\n")])
        assert a.reliable_upto_header()
