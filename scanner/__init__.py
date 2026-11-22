"""Repository scanner and CALM document builder."""

from pathlib import Path

__version__ = "0.1.0"

# Vendored CALM schemas, control requirement schemas and policy live at the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
