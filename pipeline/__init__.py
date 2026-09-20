"""Streaming and alert ingestion pipeline package."""
from .stream_simulator import (
    run_stream_simulator,
    get_severity,
    calculate_calibrated_confidence,
    extract_evidence
)

__all__ = [
    "run_stream_simulator",
    "get_severity",
    "calculate_calibrated_confidence",
    "extract_evidence"
]
