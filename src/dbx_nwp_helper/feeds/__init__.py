"""Enrichment feeds: threat-intel, cloud-provider, and Databricks-owned IP ranges, plus RDAP.

All feeds are free, need no API key, and are fetched over HTTPS with a small retry. Downloaded feeds
are cached locally (parquet, with a TTL) so re-runs are fast and offline-friendly — replacing the
notebooks' Delta-table materialisation.
"""
