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

[Unreleased]: https://github.com/andyweaves/databricks-network-policy-helper/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/andyweaves/databricks-network-policy-helper/releases/tag/v0.1.0
