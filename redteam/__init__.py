"""Dependency-free LLM red team harness.

Run `python3 run.py --list` to see the catalog, or `python3 run.py --all`
against any OpenAI-compatible endpoint.
"""

from .config import Config
from .client import LLMClient
from .probes import Probe, build_catalog, CLASSES
from .runner import Runner, RunReport, ProbeResult, compare, select_catalog
from .report import to_json, to_markdown, terminal_summary

__all__ = [
    "Config",
    "LLMClient",
    "Probe",
    "build_catalog",
    "CLASSES",
    "Runner",
    "RunReport",
    "ProbeResult",
    "compare",
    "select_catalog",
    "to_json",
    "to_markdown",
    "terminal_summary",
]