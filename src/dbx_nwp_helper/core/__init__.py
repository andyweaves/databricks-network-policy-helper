"""Core engine: analysis, enrichment, rule building, and policy apply — independent of the CLI shell.

Pure Python (pandas + the Databricks SDK dataclasses); no Rich, no dbutils. The CLI and the guided
wizard both drive these. Each `analyze_*` returns a result object carrying the review tables and the
built rule specs; `apply_*` writes via the SDK.
"""
