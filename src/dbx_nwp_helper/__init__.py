"""dbx-nwp-helper — build Databricks account network policies from real observed traffic.

A visually engaging CLI that turns `system.access.audit` / `system.access.outbound_network`
traffic into proposed context-based ingress (CBI) and serverless egress (SEG) allow-lists, and
migrates existing IP access lists into CBI policies — with a dry-run-first, review-gated apply path.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    # Set at build/install time by hatch-vcs from the git tag (see pyproject.toml).
    __version__ = _version("databricks-network-policy-helper")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"
