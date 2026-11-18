"""FastAPI application: upload a pcap, get per-flow HTTP/1.1 analysis
or ARP gateway-contention diagnostics."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

from .analyze import analyze_capture
from .arp import analyze_arp_contention

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "samples" / "sample.pcap"
ARP_SAMPLE_PATH = Path(__file__).resolve().parent.parent / "samples" / "arp_contention.pcap"
ARP_SAMPLE_GATEWAY = "192.168.1.1"  # gateway address used by the ARP sample
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB
MAX_WAIT_MS = 3_600_000.0  # 1 h

app = FastAPI(
    title="PCAP HTTP/1.1 Flow Analyzer & ARP Contention Diagnostics",
    description=(
        "HTTP analysis: upload an Ethernet/IPv4/TCP packet capture (pcap or "
        "pcapng). For every connection with a fully captured three-way "
        "handshake, destination port 80 and exactly one HTTP/1.1 request, the "
        "API returns the request line, Host header, response status code and "
        "the connection identifier. Both directions are reassembled by TCP "
        "sequence numbers (out-of-order and retransmitted bytes are not "
        "double-counted). A direction with a gap, conflicting overlap or "
        "snaplen truncation before the end of its headers is reported as "
        "unreliable instead of guessing.\n\n"
        "ARP contention diagnostics: upload an Ethernet capture, give the "
        "registered gateway IPv4 address and a reply-wait window. ARP probe "
        "requests for the gateway are correlated with ARP replies per VLAN. "
        "A probe answered by two different sender MACs is reported as "
        "suspected contention (probe, both parties and packet numbers are "
        "listed). Replies that fit several overlapping probe windows cannot "
        "be attributed (ARP has no transaction id) and are listed separately "
        "as pending instead of being used as evidence; truncated ARP frames "
        "never count."
    ),
    version="1.1.0",
)


@app.get("/", summary="Service info")
def root() -> dict:
    return {
        "service": "pcap-http-analyzer",
        "docs": "/docs",
        "endpoints": {
            "POST /analyze": "upload a pcap/pcapng file (form field 'file')",
            "GET /sample": "download the bundled sample capture",
            "POST /analyze/sample": "analyse the bundled sample capture",
            "POST /analyze/arp": (
                "upload an Ethernet pcap/pcapng (form field 'file') plus form "
                "fields 'gateway_ip' and 'wait_ms' for ARP contention diagnostics"
            ),
            "GET /sample/arp": "download the bundled ARP contention sample capture",
            "POST /analyze/arp/sample": "analyse the bundled ARP sample capture",
        },
    }


def _read_upload(data: bytes) -> bytes:
    if not data:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="file too large (100 MiB max)")
    return data


def _validate_arp_params(gateway_ip: str, wait_ms: float) -> tuple[str, float]:
    try:
        gateway = str(ipaddress.IPv4Address(gateway_ip.strip()))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise HTTPException(
            status_code=400, detail=f"invalid gateway IPv4 address: {gateway_ip!r}"
        ) from exc
    if not 0 < wait_ms <= MAX_WAIT_MS:
        raise HTTPException(
            status_code=400,
            detail=f"wait_ms must be in (0, {MAX_WAIT_MS:g}] milliseconds",
        )
    return gateway, wait_ms / 1000.0


@app.post("/analyze", summary="Analyse an uploaded capture")
async def analyze(file: UploadFile = File(...)) -> dict:
    data = _read_upload(await file.read())
    try:
        result = analyze_capture(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["filename"] = file.filename
    return result


@app.post("/analyze/arp", summary="ARP gateway-contention diagnosis of an uploaded capture")
async def analyze_arp(
    file: UploadFile = File(...),
    gateway_ip: str = Form(..., description="registered gateway IPv4 address"),
    wait_ms: float = Form(500.0, description="reply wait window per probe, milliseconds"),
) -> dict:
    data = _read_upload(await file.read())
    gateway, wait_s = _validate_arp_params(gateway_ip, wait_ms)
    try:
        result = analyze_arp_contention(data, gateway, wait_s)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result["filename"] = file.filename
    return result


@app.get("/sample", summary="Download the bundled sample pcap")
def sample() -> FileResponse:
    if not SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="sample capture not found")
    return FileResponse(
        SAMPLE_PATH,
        media_type="application/vnd.tcpdump.pcap",
        filename="sample.pcap",
    )


@app.get("/sample/arp", summary="Download the bundled ARP contention sample pcap")
def sample_arp() -> FileResponse:
    if not ARP_SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="ARP sample capture not found")
    return FileResponse(
        ARP_SAMPLE_PATH,
        media_type="application/vnd.tcpdump.pcap",
        filename="arp_contention.pcap",
    )


@app.post("/analyze/sample", summary="Analyse the bundled sample pcap")
def analyze_sample() -> dict:
    if not SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="sample capture not found")
    result = analyze_capture(SAMPLE_PATH.read_bytes())
    result["filename"] = SAMPLE_PATH.name
    return result


@app.post("/analyze/arp/sample", summary="ARP diagnosis of the bundled ARP sample pcap")
def analyze_arp_sample(
    gateway_ip: str = ARP_SAMPLE_GATEWAY,
    wait_ms: float = 500.0,
) -> dict:
    if not ARP_SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="ARP sample capture not found")
    gateway, wait_s = _validate_arp_params(gateway_ip, wait_ms)
    result = analyze_arp_contention(ARP_SAMPLE_PATH.read_bytes(), gateway, wait_s)
    result["filename"] = ARP_SAMPLE_PATH.name
    return result
