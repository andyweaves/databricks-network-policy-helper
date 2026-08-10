"""dbx-nwp-helper — build Databricks account network policies from real observed traffic.

A visually engaging CLI that turns `system.access.audit` / `system.access.outbound_network`
traffic into proposed context-based ingress (CBI) and serverless egress (SEG) allow-lists, and
migrates existing IP access lists into CBI policies — with a dry-run-first, review-gated apply path.
"""

__version__ = "0.1.0"
