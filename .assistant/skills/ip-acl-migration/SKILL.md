---
name: ip-acl-migration
description: Migrate a Databricks workspace's existing IP access list (ACL) into a context-based ingress (CBI) account network policy, as-is. Use when the user wants to convert / migrate an existing IP access list to a network policy, recreate their IP ACL as CBI, or stand up a network policy from the current ACL without audit-log analysis. Reads this workspace's ACL (ALLOW->allow rules, BLOCK->deny rules) and recreates it verbatim — nothing added — then creates the account network policy (enforce or dry-run) and optionally auto-assigns it to the current workspace.
---

# IP Access List → CBI migration (simple)

A minimal tool that migrates **this workspace's existing IP access list** into a context-based
ingress (CBI) account network policy, **as-is** — no audit-log analysis, no enrichment, nothing
added. The engine is `notebooks/ip_acl_migration.py` in the databricks-network-policy-helper repo.

Use the fuller **cbi-helper** skill / `audit_log_cbi.py` instead when the user wants traffic-based
suggestions, threat-intel / cloud enrichment, or identity/destination scoping.

## When to use

The user wants to: migrate / convert an existing IP access list to a network policy, recreate their
IP ACL as CBI, or create a network policy from the current ACL without analysing traffic.

## What it does

1. Reads this workspace's enabled IP access lists (`w.ip_access_lists.list()`, workspace-level).
2. Maps **ALLOW lists → allow rules**, **BLOCK lists → deny rules** (IPv4 only; CBI is IPv4-only) —
   a verbatim recreation, nothing added.
3. Creates/updates the account network policy and, if `auto_assign` is on (default), binds the
   current workspace to it.

> This tool deliberately does **not** auto-allow Databricks' own control-plane IPs or do any
> enrichment — it assumes the existing ACL is what the customer wants. Use `cbi-helper` if you want
> those.

## Options (widgets)

- `policy_mode` — **`enforce`** (default) or `dry_run` (log-only trial).
- `name_prefix` — prefix for the generated policy name / rule labels (default `cbi-helper`).
- `egress_policy` — egress set on create: `allow_all` / `dry_run` / `restricted` (same as cbi-helper).
- `auto_assign` — bind the current workspace to the new policy (default true).
- Account auth (`account_id` + optional SP client_id/secret scope+key) — **account admin required**
  to create/assign the policy. See `docs/account-admin-setup.md`.
- `network_policy_id` (blank = generated `<prefix>-<timestamp>`), `apply_policy` (gate).

## Safety

Nothing is written unless `apply_policy=true`. Default `policy_mode=enforce` will block non-matching
source IPs on the assigned workspace — trial with `dry_run` first if unsure.
