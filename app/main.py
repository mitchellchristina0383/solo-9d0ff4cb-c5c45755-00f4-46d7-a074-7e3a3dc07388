"""FastAPI application: upload a pcap, get per-flow HTTP/1.1 analysis."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from .analyze import analyze_capture

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "samples" / "sample.pcap"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB

app = FastAPI(
    title="PCAP HTTP/1.1 Flow Analyzer",
    description=(
        "Upload an Ethernet/IPv4/TCP packet capture (pcap or pcapng). "
        "For every connection with a fully captured three-way handshake, "
        "destination port 80 and exactly one HTTP/1.1 request, the API "
        "returns the request line, Host header, response status code and "
        "the connection identifier. Both directions are reassembled by TCP "
        "sequence numbers (out-of-order and retransmitted bytes are not "
        "double-counted). A direction with a gap, conflicting overlap or "
        "snaplen truncation before the end of its headers is reported as "
        "unreliable instead of guessing."
    ),
    version="1.0.0",
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
        },
    }


@app.post("/analyze", summary="Analyse an uploaded capture")
async def analyze(file: UploadFile = File(...)) -> dict:
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="file too large (100 MiB max)")
    try:
        result = analyze_capture(data)
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


@app.post("/analyze/sample", summary="Analyse the bundled sample pcap")
def analyze_sample() -> dict:
    if not SAMPLE_PATH.exists():
        raise HTTPException(status_code=404, detail="sample capture not found")
    result = analyze_capture(SAMPLE_PATH.read_bytes())
    result["filename"] = SAMPLE_PATH.name
    return result
