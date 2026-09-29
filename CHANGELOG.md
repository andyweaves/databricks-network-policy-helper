# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For a CLI, the
"public API" governed by SemVer is the command and flag surface: a breaking change to it bumps
the **major** version, a backward-compatible addition bumps the **minor**, and a fix bumps the
**patch**.

The version is derived from the git tag by `hatch-vcs`, so a release is cut by tagging the
commit `vX.Y.Z` — see the "Versioning & releases" section of the README.

## [Unreleased]

## [0.2.0] - 2026-09-29

### Added

- **Interactive companion guide.** `dbx-nwp-helper guide` opens a self-contained, offline HTML
  companion (packaged with the tool): step-by-step **ingress and egress walkthroughs** that mirror
  the tool's actual flow, a collapsible **CLI options** reference (a readable version of `--help`),
  and "learn more" expanders (including what RDAP is and to treat it as a signal, not a source of
  truth). A one-line hint at the start of a run points new users to it. `--print-path` prints the
  file path instead of opening a browser, and `--pdf <path>` renders the whole guide to a PDF with
  every section expanded (via a headless Chrome / Chromium / Edge, with an on-page "Save as PDF"
  button as a fallback).
- **CBI-policy denials in the "recently denied" view.** Ingress now also reads
  `system.access.inbound_network` (when the table is available), so recently-blocked inbound
  requests are flagged whether they were denied by an IP access list (403) *or* a CBI network
  policy — merged into one view by source IP. Degrades gracefully when the table is absent.
- **Automatic IP access list detection.** When a workspace has enabled IP access lists, `ingress`
  detects them, shows their actual IP entries, and (interactively) offers a pre-checked checkbox to
  pick exactly which entries to migrate into the CBI policy (alongside the enriched observed-traffic
  rules). Scripted / `--yes` runs migrate them all.

### Changed

- **Rule selection is on by default.** The `--select-rules` checkbox now runs by default in
  interactive runs; pass `--no-select-rules` to keep everything. Scripted / `--yes` runs are
  unaffected (the selector is skipped, as before). The egress selector runs as two distinct prompts
  — one for internet FQDNs, one for storage destinations (S3 / GCS / Azure) — so each kind is
  curated separately.
- **Simpler rule labels.** Generated rules no longer carry a `(dry-run)` / `(enforced)` suffix, and
  migrated IP-ACL rules no longer carry a `migrated-acl-` prefix — labels are now verbatim.
- **Clearer account-auth errors.** When account-admin credentials can't be resolved, the CLI now
  explains that account auth is separate from the workspace `--profile` and how to set it up,
  instead of surfacing the raw SDK "cannot configure default credentials" message.

### Removed

- **`--ip-acl-handling`.** Replaced by the automatic detect-and-prompt flow above; observed-traffic
  rules are always included, and the standalone ACL-only (`migrate`) mode is gone. Use the prompt
  (or `--yes` to migrate non-interactively) to include existing IP access lists.

## [0.1.0] - 2026-09-18

First release. `dbx-nwp-helper` turns real observed traffic in the Databricks system
tables into proposed **account network policies**, with a dry-run-first, review-gated apply path.

### Added

- **Ingress (CBI).** `dbx-nwp-helper ingress` proposes and optionally applies a context-based
  ingress allow-list from `system.access.audit` source IPs — enriched with open threat-intel,
  cloud-provider and Databricks-owned IP ranges plus RDAP ownership, with minimal / optimal /
  maximum CIDR framings and optional scoping by destination (Apps / Lakebase) and identity.
- **Egress (SEG).** `dbx-nwp-helper egress` proposes and optionally applies a serverless egress
  allow-list from `system.access.outbound_network` destinations (S3 / GCS / Azure storage and
  internet FQDNs), with optional threat-intel domain blocking (abuse.ch ThreatFox).
- **Guided wizard.** `dbx-nwp-helper guided` walks through building either policy interactively.
- **Feed cache management.** `dbx-nwp-helper feeds list` / `refresh` / `clear` for the local
  threat-intel / cloud-range feed cache (free, key-less, HTTPS, TTL-cached).
- **Safety model.** Nothing is written without `--create-policy`; `dry_run` is the default mode;
  the target workspace is confirmed before any action; interactive step-through and review gates
  guard every stage (bypass with `--yes`); and pre-checks abort rather than clobber an existing
  PrivateLink / enforced policy or drop the opposite direction's enforced block.
- **Export.** `--export <path>` writes the proposed `AccountNetworkPolicy` as REST-ready JSON and
  a best-effort Terraform `.tf`, working in propose-only mode.
- **`--version`.** All commands expose the tool version via `dbx-nwp-helper --version`.

[Unreleased]: https://github.com/andyweaves/databricks-network-policy-helper/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/andyweaves/databricks-network-policy-helper/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/andyweaves/databricks-network-policy-helper/releases/tag/v0.1.0
