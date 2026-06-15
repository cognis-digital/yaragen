"""YARAGEN MCP server — exposes analyze() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
import os
import sys
from yaragen.core import analyze_sample


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-yaragen[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-yaragen[mcp]'", file=sys.stderr)
        return 1
    app = FastMCP("yaragen")

    @app.tool()
    def yaragen_scan(target: str) -> str:
        """Generate candidate YARA rules from a sample file. Returns JSON findings.

        Args:
            target: Absolute path to the sample file to analyze.
        """
        if not target or not target.strip():
            return json.dumps({"error": "target path must not be empty"})
        target = target.strip()
        if not os.path.isfile(target):
            return json.dumps({"error": f"file not found: {target!r}"})
        try:
            report = analyze_sample(target)
        except PermissionError:
            return json.dumps({"error": f"permission denied reading {target!r}"})
        except OSError as exc:
            return json.dumps({"error": f"cannot read {target!r}: {exc}"})
        return json.dumps(report.to_dict(), indent=2)

    app.run()
    return 0
