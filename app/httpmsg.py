"""Minimal HTTP/1.x message-head parsing (request line, status line, headers)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .reassembly import HEADER_TERMINATOR

_REQUEST_LINE_RE = re.compile(
    r"^([!#$%&'*+\-.^_`|~0-9A-Za-z]+) ([^ ]+) (HTTP/1\.[01])$"
)
_STATUS_LINE_RE = re.compile(r"^HTTP/1\.[01] (\d{3})(?: (.*))?$")

#: Methods we recognise when sanity-checking a partially captured request.
_METHOD_PREFIXES = (
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
    b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT",
)


@dataclass
class RequestHead:
    request_line: str
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    host: str | None
    content_length: int
    header_end: int  # offset just past the blank line


@dataclass
class ResponseHead:
    status_line: str
    version: str
    status_code: int
    reason: str
    header_end: int


def _parse_header_lines(block: str) -> list[tuple[str, str]] | None:
    headers: list[tuple[str, str]] = []
    for line in block.split("\r\n"):
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not name.strip():
            return None
        headers.append((name.strip(), value.strip()))
    return headers


def parse_request_head(data: bytes) -> RequestHead | None:
    end = data.find(HEADER_TERMINATOR)
    if end < 0:
        return None
    head = data[:end].decode("latin-1")
    lines = head.split("\r\n")
    match = _REQUEST_LINE_RE.match(lines[0])
    if not match:
        return None
    headers = _parse_header_lines("\r\n".join(lines[1:]))
    if headers is None:
        return None
    host = next((v for k, v in headers if k.lower() == "host"), None)
    content_length = 0
    for k, v in headers:
        if k.lower() == "content-length":
            try:
                content_length = max(0, int(v))
            except ValueError:
                content_length = 0
            break
    return RequestHead(
        request_line=lines[0],
        method=match.group(1),
        target=match.group(2),
        version=match.group(3),
        headers=headers,
        host=host,
        content_length=content_length,
        header_end=end + len(HEADER_TERMINATOR),
    )


def parse_response_head(data: bytes) -> ResponseHead | None:
    end = data.find(HEADER_TERMINATOR)
    if end < 0:
        return None
    head = data[:end].decode("latin-1")
    lines = head.split("\r\n")
    match = _STATUS_LINE_RE.match(lines[0])
    if not match:
        return None
    if _parse_header_lines("\r\n".join(lines[1:])) is None:
        return None
    version = lines[0].split(" ", 1)[0]
    return ResponseHead(
        status_line=lines[0],
        version=version,
        status_code=int(match.group(1)),
        reason=match.group(2) or "",
        header_end=end + len(HEADER_TERMINATOR),
    )


def looks_like_http_request_start(prefix: bytes) -> bool:
    """Heuristic: could these bytes be the start of an HTTP request line?

    Used when the request direction is unreliable: if even the contiguous
    prefix cannot be the beginning of a request, the flow is not HTTP at
    all and should be skipped rather than reported as unreliable.
    """
    head = prefix[:8]
    if not head:
        return False
    return any(m.startswith(head) for m in _METHOD_PREFIXES) or any(
        head.startswith(m + b" ") for m in _METHOD_PREFIXES
    )
