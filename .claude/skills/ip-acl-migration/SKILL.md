---
name: ip-acl-migration
description: Migrate a Databricks workspace's existing IP access list (ACL) into a context-based ingress (CBI) account network policy, as-is, using the dbx-nwp-helper CLI. Use when the user wants to convert / migrate an existing IP access list to a network policy, recreate their IP ACL as CBI, or stand up a network policy from the current ACL without audit-log analysis. Runs `dbx-nwp-helper migrate-acl`, which reads this workspace's ACL (ALLOW->allow rules, BLOCK->deny rules) and recreates it verbatim — nothing added — then creates the account network policy (enforce or dry-run) and optionally auto-assigns it to the current workspace.
---

# IP Access List → CBI migration (simple)

Migrates **this workspace's existing IP access list** into a context-based ingress (CBI) account
network policy, **as-is** — no audit-log analysis, no enrichment, nothing added. The engine is
`dbx-nwp-helper migrate-acl` (this repo).

Use the fuller **ingress-helper** skill (`dbx-nwp-helper ingress`) instead when the user wants
traffic-based suggestions, threat-intel / cloud enrichment, or identity/destination scoping.

## When to use

The user wants to: migrate / convert an existing IP access list to a network policy, recreate their
IP ACL as CBI, or create a network policy from the current ACL without analysing traffic.

## Setup

`uv sync`, then `uv run dbx-nwp-helper migrate-acl …`. Auth is the SDK's unified auth (`--profile` or
`DATABRICKS_*`). **`migrate-acl` always needs account-admin access now** (pass `--account-id` with
account-admin credentials — see `docs/account-admin-setup.md`): even a propose-only / `--export` run
performs account-level pre-checks (existing network policy + PAS). This command does not need a SQL
warehouse (no traffic analysis).

## What it does

1. Reads this workspace's enabled IP access lists (`w.ip_access_lists.list()`, workspace-level), and
   the workspace-wide `enableIpAccessLists` toggle — if IP ACLs are currently **disabled**, it flags
   that the listed rules exist but aren't being enforced today (migrating them will newly restrict).
2. Maps **ALLOW lists → allow rules**, **BLOCK lists → deny rules** (IPv4 only; CBI is IPv4-only),
   recreating each rule label prefixed with `migrated-`. The one thing it adds: if the ACL has **only
   BLOCK lists**, a catch-all allow (all public IPs) is added, because CBI RESTRICTED_ACCESS is
   default-deny — without it a deny-only policy would block everything, flipping the ACL's
   default-allow-except-blocked meaning.
3. Runs account-level **pre-checks** before migrating:
   - **PAS attached?** If the workspace has a Private Access Settings object (AWS/GCP PrivateLink),
     migration to CBI isn't supported yet — it **aborts**. (Azure workspaces have no PAS, so this
     never trips there.)
   - **Existing CBI ingress policy?** Only matters when the run will **assign** the new policy
     (assigning replaces the workspace's existing one). When assigning: an **enforced** existing
     policy → **aborts** (migrating on top of it isn't supported yet); a **dry-run** existing policy →
     flags it, offers to **promote it to enforced**, then **stops** (a migration needs an enforced
     baseline first; re-run afterwards). When **not** assigning (propose-only, `--export`, or
     `--no-auto-assign`), it just **warns** that a policy exists and continues — the new policy is
     created/exported but not bound to the workspace.
4. Names the new policy from `--policy-name`; if not given it **prompts** for one (leave blank there
   to use the profile name). With `--create-policy`, creates/updates that policy and, if
   `--auto-assign` (default on), binds the current workspace to it. An interactive review gate
   confirms before the write (bypass with `--yes`).
5. With `--disable-existing-ip-acls` (off by default), after the policy is created **and** assigned,
   turns off the workspace's IP access list enforcement (`enableIpAccessLists=false`) so the old ACL
   and the new CBI policy don't both apply. The lists themselves are preserved (reversible). The CLI
   refuses this flag unless the run also creates and assigns the policy, so it can't leave the
   workspace with no ingress control.

> This tool deliberately does **not** auto-allow Databricks' own control-plane IPs or do any
> enrichment — it assumes the existing ACL is what the customer wants. Use `ingress-helper` for those.

## Options

- `--policy-mode` — **`enforce`** (default) or `dry_run` (log-only trial).
- `--policy-name` — the new policy's id. If omitted you're **prompted** (blank there = the profile
  name; falls back to the workspace id). Normalised to a lowercase, `-`-safe, length-capped id.
  (There is no longer a `--name-prefix` — the policy is named directly.)
- `--export <path>` — write the proposed network-policy JSON (a curl / REST-ready
  `AccountNetworkPolicy` body) to `<path>`. If `<path>` is a directory, it writes
  `<policy-id>.json` inside it; missing parent dirs are created. Works in propose-only mode too.
- `--egress-policy` — egress block set when creating the policy (the migration builds only ingress
  rules, so this is your egress choice): `dry_run` (**default** — restricted, log-only, blocks
  nothing) / `allow_all` (no egress restriction) / `restricted` (enforced, **blocks all serverless
  egress** since nothing is allow-listed). The CLI prints what the chosen option does; on an update
  an existing policy's egress is left unchanged.
- `--auto-assign` / `--no-auto-assign` — bind the current workspace (default on).
- `--disable-existing-ip-acls` — after create + assign, turn off the workspace's IP access lists
  (`enableIpAccessLists=false`); requires `--create-policy` (assign is on by default). Off by default.
- `--account-id` (+ account-admin creds) — **always required** now (the pre-checks and create/assign
  are all account-level).
- `--create-policy` (gate).

## Safety

The policy is only created/assigned with `--create-policy` (an interactive review gate confirms
first). By default the CLI **steps through** each section — pausing after the existing-ACL analysis
and after the proposed-policy preview to ask whether to continue (*no* aborts cleanly). **`--yes`
runs non-interactively**, skipping the step-through pauses and the review/write gate. Propose-only
and `--export` runs write nothing — they read and emit JSON. One
nuance in the create-**and**-assign path: if the workspace's existing assigned policy is dry-run,
you may be offered to promote *that* policy to enforced (a write) — only when you explicitly confirm
it — after which the migration stops so you can re-run. Default `--policy-mode enforce` will block
non-matching source IPs on the assigned workspace — trial with `--policy-mode dry_run` first if
unsure. Also runnable via `dbx-nwp-helper guided`.
