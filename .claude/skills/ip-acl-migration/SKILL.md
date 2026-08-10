---
name: ip-acl-migration
description: Migrate a Databricks workspace's existing IP access list (ACL) into a context-based ingress (CBI) account network policy, as-is, using the dbx-netpolicy CLI. Use when the user wants to convert / migrate an existing IP access list to a network policy, recreate their IP ACL as CBI, or stand up a network policy from the current ACL without audit-log analysis. Runs `dbx-netpolicy migrate-acl`, which reads this workspace's ACL (ALLOW->allow rules, BLOCK->deny rules) and recreates it verbatim — nothing added — then creates the account network policy (enforce or dry-run) and optionally auto-assigns it to the current workspace.
---

# IP Access List → CBI migration (simple)

Migrates **this workspace's existing IP access list** into a context-based ingress (CBI) account
network policy, **as-is** — no audit-log analysis, no enrichment, nothing added. The engine is
`dbx-netpolicy migrate-acl` (this repo).

Use the fuller **ingress-helper** skill (`dbx-netpolicy ingress`) instead when the user wants
traffic-based suggestions, threat-intel / cloud enrichment, or identity/destination scoping.

## When to use

The user wants to: migrate / convert an existing IP access list to a network policy, recreate their
IP ACL as CBI, or create a network policy from the current ACL without analysing traffic.

## Setup

`uv sync`, then `uv run dbx-netpolicy migrate-acl …`. Auth is the SDK's unified auth (`--profile` or
`DATABRICKS_*`). Reading the ACL is workspace-level; **creating/assigning the policy needs an account
admin** — pass `--account-id` with account-admin credentials (see `docs/account-admin-setup.md`).
This command does not need a SQL warehouse (no traffic analysis).

## What it does

1. Reads this workspace's enabled IP access lists (`w.ip_access_lists.list()`, workspace-level).
2. Maps **ALLOW lists → allow rules**, **BLOCK lists → deny rules** (IPv4 only; CBI is IPv4-only) —
   a verbatim recreation. The one thing it adds: if the ACL has **only BLOCK lists**, a catch-all
   allow (all public IPs) is added, because CBI RESTRICTED_ACCESS is default-deny — without it a
   deny-only policy would block everything, flipping the ACL's default-allow-except-blocked meaning.
3. With `--create-policy`, creates/updates the policy `<name_prefix>-<workspace_id>` and, if
   `--auto-assign` (default on), binds the current workspace to it. An interactive review gate
   confirms before the write (bypass with `--yes`).

> This tool deliberately does **not** auto-allow Databricks' own control-plane IPs or do any
> enrichment — it assumes the existing ACL is what the customer wants. Use `ingress-helper` for those.

## Options

- `--policy-mode` — **`enforce`** (default) or `dry_run` (log-only trial).
- `--name-prefix` — prefix for the generated policy name / rule labels (default `np-helper`).
- `--egress-policy` — egress set on create: `allow_all` / `dry_run` / `restricted`.
- `--auto-assign` / `--no-auto-assign` — bind the current workspace (default on).
- `--account-id` (+ account-admin creds) — required to create/assign.
- `--create-policy` (gate).

## Safety

Nothing is written unless `--create-policy`. Default `--policy-mode enforce` will block non-matching
source IPs on the assigned workspace — trial with `--policy-mode dry_run` first if unsure. Also
runnable via `dbx-netpolicy guided`.
