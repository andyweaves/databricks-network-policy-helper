---
name: ingress-helper
description: Suggest and optionally apply Databricks Context-Based Ingress (CBI) network-policy allow-lists from real audit-log traffic, using the dbx-nwp-helper CLI. Use when the user wants to build/suggest a context-based ingress policy, tighten inbound network access, allow-list source IPs, analyse who connects to a workspace and from where, or turn system.access.audit logs into a CBI / account network-policy proposal. Runs `dbx-nwp-helper ingress` (or the guided wizard), which analyses public source IPs carrying successful traffic, enriches them with open threat-intelligence and cloud-provider ranges plus RDAP ownership, proposes minimal/optimal/maximum CIDR framings optionally scoped by destination (Apps/Lakebase) and identity (users/SPs), and can write the result into a network policy's dry-run (log-only) or enforced ingress block via the Databricks SDK.
---

# Context-Based Ingress (CBI) Helper

Turn real `system.access.audit` traffic into a proposed **Context-Based Ingress (CBI)** allow-list
for a Databricks **account network policy**, with threat-intel + cloud-range enrichment, optional
destination/identity scoping, and a safe dry-run-first apply path.

The engine is the **`dbx-nwp-helper`** CLI (this repo). This skill helps run it with sensible
parameters and review/apply a policy responsibly.

For **egress** (outbound allow-lists) use `egress-helper`. To end up with a combined ingress + egress
policy, run one direction with `--policy-action create_new`, then the other with
`--policy-action add_to_existing --existing-policy-id <id>` pointed at the policy the first created.

## When to use

The user wants to: suggest/build a CBI or ingress allow-list; see which public IPs / identities
connect to a workspace and from where; tighten inbound network access from observed traffic; or
trial an ingress policy in dry-run before enforcing.

## Setup

The CLI is a uv project. From a checkout: `uv sync`, then run via `uv run dbx-nwp-helper …` (or
`uv tool install .` to expose `dbx-nwp-helper` on PATH).

- **Auth** is the Databricks SDK's unified auth — pass `--profile <name>` (a `~/.databrickscfg`
  profile) or set `DATABRICKS_*` env vars. Analysis needs only workspace read on
  `system.access.audit`. **Applying a policy, or identity scoping, needs an account admin** — pass
  `--account-id` and have account-admin credentials resolvable (recommended: an account-admin
  service principal via OAuth M2M in the same profile). See `docs/account-admin-setup.md`.
- **SQL warehouse**: the CLI queries the system tables through a SQL warehouse. Pass
  `--warehouse-http-path` to use a specific one; otherwise it reuses (or creates) a small serverless
  warehouse named `dbx-nwp-helper`.

## Safety model — read first

- The default `--policy-mode` is **`dry_run`** — writes the log-only `ingress_dry_run` block and
  **blocks nothing**. Always propose and validate here first.
- **`enforce` mode writes the enforced `ingress` block and CAN lock users (and the operator) out**
  if the allow-list is incomplete. Keep `--policy-mode dry_run` until the logs look right.
- Nothing is written unless **`--create-policy`** is passed, and an interactive review gate
  confirms before any write (bypass only with `--yes` for scripting). Show the JSON preview first.
- By default the CLI **steps through** each section — pausing after the analysis results and after
  the proposed-policy preview to ask whether to continue (answering *no* aborts cleanly). **`--yes`
  runs non-interactively**, skipping the step-through pauses *and* every review/write gate.
- The CBI policy schema is **IPv4-only**; IPv6 is analysed but never put in a policy.
- Never pass `--create-policy` (let alone `--policy-mode enforce`) on the user's behalf without
  explicit, current confirmation of the mode and the exact CIDRs.

## Workflow

1. **Propose-only first** (no `--create-policy`):
   ```bash
   uv run dbx-nwp-helper ingress --profile <profile> --lookback-days 30
   ```
   This runs the analysis, prints the candidate IPs, ranked CIDR suggestions, the ⚠️ threat-match
   table, and the JSON policy preview — writing nothing.
2. **Review** the proposal with the user: framing, scoping, mode, and the exact CIDRs.
3. **Apply (gated)** — only with explicit go-ahead, add `--create-policy` (defaults to `dry_run`)
   and, when ready, `--policy-mode enforce`. Add `--auto-assign` to bind the workspace(s).
4. Or run **`uv run dbx-nwp-helper guided --profile <profile>`** for a structured Q&A wizard that
   walks the user through the same choices interactively.

## CIDR framings (`--policy-framing`)

- `minimal` (default) — one `/32` per observed IP (tightest).
- `optimal` — collapse adjacent addresses.
- `maximum` — the full RDAP-assigned range (needs `--enable-rdap`).

## Scoping modes (`--scoping-mode`)

- `ip_only` (default) — one rule: these CIDRs, all destinations, all identities.
- `ip_and_destination` — scope groups whose traffic maps cleanly to Apps or Lakebase.
- `ip_and_identity` — scope to the specific users/SPs seen (resolves emails→numeric ids via account
  SCIM; account admin required). Groups are **not** supported — only users and service principals.
- `ip_identity_and_destination` — both.

## Policy scope (`--policy-scope`) & limits

- `current_workspace` (default) — one policy built from **this** workspace's traffic, named
  `<name_prefix>-<profile>`, bound to this workspace on `--auto-assign`.
- `per_workspace` — a tailored policy per workspace seen, named `<name_prefix>-ws-<id>`.
- `all_workspaces` — a single policy built from **all** workspaces' traffic, named `<name_prefix>`.

Audit `workspace_id = 0` is account-level, excluded unless `--include-account-level`.

Names are derived from `--name-prefix` as above. To set the policy id yourself instead, pass
`--policy-name <id>` (single-policy scopes only — not `per_workspace`, and not `add_to_existing`,
which uses `--existing-policy-id`). It's normalised to an id-safe slug (lowercased, non-alphanumerics
→ `-`, length-capped) and the CLI prints the resulting id.

Before any analysis or write, the CLI shows the **target workspace** (profile / URL / id) and asks
you to confirm it — so a mis-set `--profile` can't act on the wrong workspace (skip with `--yes`).

Applying: **`--create-policy`** is the master switch; **`--policy-action`** chooses `create_new`
(a fresh policy from `--name-prefix`) or `add_to_existing` (update `--existing-policy-id`, replacing
only its ingress block and leaving egress intact — needs a single-policy scope, i.e.
`current_workspace` or `all_workspaces`, not `per_workspace`);
**`--auto-assign`** binds the workspace(s). `add_to_existing` is how you layer ingress onto a policy
the egress helper already created (and vice-versa) for a combined policy.

The CLI knows the Databricks network-policy limits and **warns + auto-caps** to keep proposals
valid: **50 ingress rules, 2000 CIDR blocks, 100 identities per policy; 1000 policies per account.**

## Existing IP access list & denied requests

`--ip-acl-handling`: `migrate_and_enrich` (default — recreate the ACL as CBI rules **and** add
traffic-derived rules), `migrate` (recreate the ACL exactly), or `ignore` (traffic-derived only).
The CLI also surfaces requests **currently being denied** (403 / IpAccessDenied); pass
`--deny-denied-ips` to turn those source IPs into explicit deny rules.

Once the CBI policy replaces the old IP access list, pass `--disable-existing-ip-acls` (off by
default) to turn the workspace's IP access lists off (`enableIpAccessLists=false`) so both controls
don't apply at once. It only runs **after** the policy is created and assigned, and the CLI refuses
the flag unless the run also does both (`--create-policy` **and** `--auto-assign`) — so it can't
leave the workspace with no ingress control. The lists are preserved, so it's reversible.

## Flagged groups & threat-intel deny rules

Threat-intel and cloud-provider-owned groups are **always excluded** from proposed allow rules.
Threat matches still appear in the ⚠️ threat-match table for investigation. **Databricks-owned** IPs
are the exception and take **precedence**: an observed Databricks-owned group is always kept in the
allow-list (in its own unscoped rule, and never dropped even when a threat feed also matches). Note
this only covers Databricks ranges **seen in your audit traffic** — the tool does not inject the full
published range set, so confirm the platform's own ranges are covered before enforcing.

`--threat-deny-rules` adds **deny rules** from the threat-intel table: `off`, `matched_only` (only
threat CIDRs that matched observed traffic), or `all` (whole feeds). Over the cap it prioritises
(confidence-1, attacker_subnet first) rather than skipping. If a policy would have deny rules but no
allow rules, a catch-all allow is added so non-denied traffic is still permitted.

## Feeds

Enrichment feeds are cached locally with a TTL. `dbx-nwp-helper feeds list` shows the cache;
`feeds refresh` forces a re-download; the analysis commands accept `--refresh-feeds`.

## References

- `docs/threat-intel-feeds.md` — the enrichment feeds, what each represents, licensing.
- `docs/cbi-sdk-schema.md` — the verified `AccountNetworkPolicy` SDK object model.
- `docs/account-admin-setup.md` — account-admin SP + credential setup.
