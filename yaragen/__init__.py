"""YARAGEN - Generate candidate YARA rules from sample files.

A defensive forensics/triage tool in the spirit of yarGen: extract
distinctive strings/byte-patterns from owned sample artifacts and emit
candidate YARA detection rules for review by an analyst.
"""
from .core import (
    extract_strings,
    score_string,
    analyze_sample,
    generate_rule,
    Finding,
    SampleReport,
)

TOOL_NAME = "yaragen"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "extract_strings",
    "score_string",
    "analyze_sample",
    "generate_rule",
    "Finding",
    "SampleReport",
]
