# Databricks Network Policy Helper

Tools to **build** and **review** Databricks **account network policies** from real observed traffic.
Each tool is a self-contained notebook (+ a Databricks Genie Code skill) sharing a common home, a
common safety model, and the same deploy path.

Two kinds of tool:

- **Helpers** turn observed traffic (or an existing IP ACL) into a proposed policy and, when you
  explicitly opt in, apply it — dry-run first, enforce with intent.
- **Checkers** are strictly read-only: they review a policy that's *already running* and recommend
  rules to add.

Both directions of an account network policy are covered — **ingress** (context-based ingress / CBI,
inbound source IPs) and **egress** (serverless egress / SEG, outbound destinations) — plus a
combined ingress+egress path and a straight IP-ACL migration.

## The tools

Each tool's full detail — what it does, every widget, its safety notes — lives in its skill
(`.assistant/skills/<name>/SKILL.md`) and in the notebook's own header cells. This table is the map.

| Direction | Build (helper) | Review (checker) |
|---|---|---|
| **Ingress** (CBI, inbound) | [`ingress_policy_helper.py`](notebooks/ingress_policy_helper.py) · [skill](.assistant/skills/ingress-helper/SKILL.md) | [`ingress_policy_checker.py`](notebooks/ingress_policy_checker.py) · [skill](.assistant/skills/ingress-checker/SKILL.md) |
| **Egress** (SEG, outbound) | [`egress_policy_helper.py`](notebooks/egress_policy_helper.py) · [skill](.assistant/skills/egress-helper/SKILL.md) | [`egress_policy_checker.py`](notebooks/egress_policy_checker.py) · [skill](.assistant/skills/egress-checker/SKILL.md) |
| **Both** (ingress + egress) | [`full_policy_helper.py`](notebooks/full_policy_helper.py) · [skill](.assistant/skills/full-policy-helper/SKILL.md) | [`full_policy_checker.py`](notebooks/full_policy_checker.py) · [skill](.assistant/skills/full-policy-checker/SKILL.md) |
| **IP ACL → CBI** (migrate) | [`ip_acl_migration.py`](notebooks/ip_acl_migration.py) · [skill](.assistant/skills/ip-acl-migration/SKILL.md) | — |

At a glance:

- **Ingress Helper** — proposes a CBI allow-list from `system.access.audit` source IPs, enriched with
  open threat-intel, cloud-provider and Databricks-owned IP ranges + RDAP, optionally scoped by
  destination/identity. The most feature-rich tool.
- **Egress Helper** — proposes a SEG allow-list from `system.access.outbound_network` destinations
  (S3 / GCS / Azure storage + internet FQDNs), with optional threat-intel domain blocking.
- **Full Policy Helper** — runs both helpers, merges their rules per workspace target, creates one
  policy each.
- **IP ACL Migration** — recreates this workspace's existing IP access list as a CBI policy, verbatim
  (no traffic analysis, no enrichment).
- **Checkers** — read the network system tables over a lookback window and recommend rules to add
  (see [Reviewing a running policy](#reviewing-a-running-policy) for what they can and can't tell you).

## Quick start

1. **Deploy a notebook** into a workspace with the Databricks CLI:
   ```bash
   # one notebook (default: ingress_policy_helper)
   python scripts/deploy_notebook.py --profile <cli-profile> --notebook egress_policy_helper --overwrite
   # or all of them
   python scripts/deploy_notebook.py --profile <cli-profile> --notebook all --overwrite
   ```
   Imports to `/Users/<you>/<notebook>`; pass `--path` to change. (You can also clone/attach the repo
   as a Git folder and open the notebooks directly.)
2. **Open the notebook** and set the widgets at the top — every decision lives there.
3. **Run top to bottom** and review the proposed rules / JSON preview (helpers) or the review tables
   (checkers).
4. **Apply with intent** (helpers only) — start in `dry_run`, review the logged denials with the
   matching checker, then re-run in `enforce`.

## Safety model (helpers)

The helpers share one safety model:

- **Nothing is written unless you opt in** — set `create_policy=true` (helpers) / `apply_policy` is
  never implicit. Analysis and proposal are always side-effect-free.
- **Dry-run first.** Default `policy_mode` is `dry_run`, which writes the log-only block and **blocks
  nothing**. It makes the policy *log* what it would deny so a checker can review it.
- **Enforce with intent.** `enforce` writes the blocking block and **can lock users or workloads out**
  if the allow-list is incomplete. Stay in `dry_run` until the logged denials are only bad actors.
- **The platform stays reachable.** The ingress helper auto-allows Databricks' own control-plane /
  serverless IP ranges, so an enforced ingress policy won't lock the platform out.
- **IPv4 only.** The CBI policy schema is IPv4-only; IPv6 is analysed but never placed in a policy.

Checkers are **read-only** and have no apply path at all.

## Reviewing a running policy

Once a policy has been assigned and running for a while, the **checkers** review how it's performing.
They read the network system tables — `system.access.inbound_network` (ingress) and
`system.access.outbound_network` (egress) — over a lookback window and recommend rules to add.

Important: those tables record **only denied traffic** — both hard denials (enforced mode) and
**dry-run would-be-denials** (`DENY_DRY_RUN` / `DRY_RUN_DENIAL`). So the checkers are strongest at
finding **rules to ADD** (legitimate traffic the policy is/would-be blocking) and at confirming the
policy is catching threat-intel / flagged sources. They **cannot** see which existing allow rules are
unused (allowed traffic isn't logged here), so allow-rule pruning is necessarily limited — the
checkers say so rather than guess.

## Permissions

- **Analysis / enrichment (helpers) and review (checkers):** workspace read on the relevant system
  tables (`system.access.audit`, `system.access.inbound_network`, `system.access.outbound_network`).
- **Applying a policy, or identity scoping (helpers only): account admin** — recommended as an
  account-admin service principal via OAuth M2M with its secret in a secret scope. See
  [`docs/account-admin-setup.md`](docs/account-admin-setup.md). Checkers need no account admin.

## Databricks Genie Code skills

The repo ships [Databricks Genie Code skills](https://docs.databricks.com/aws/en/genie-code/skills)
under `.assistant/skills/` — one per tool (linked in the table above). Each skill's `SKILL.md` is
also the tool's reference doc. Genie Code discovers per-user skills under
`/Users/<you>/.assistant/skills/`.

**Easiest install:** run [`notebooks/install_skill.py`](notebooks/install_skill.py) from the repo /
Git-folder checkout — its `skills` widget lists every skill in the repo (`ALL` by default) and copies
the selected ones into your user skills directory (a `workspace` scope option exists for an
account-wide install). Or copy the `.assistant/skills/<skill>` folder(s) there by hand.

Once installed, Genie Code picks them up next time you use it; invoke one with `@<skill-name>`
(e.g. `@ingress-helper`, `@egress-checker`) in chat.

## Repo layout

| Path | What |
|---|---|
| `notebooks/*_policy_helper.py` | The three build engines (ingress / egress / full). |
| `notebooks/*_policy_checker.py` | The three read-only review engines (ingress / egress / full). |
| `notebooks/ip_acl_migration.py` | Migrate this workspace's IP access list into a CBI policy. |
| `notebooks/install_skill.py` | Install the Genie Code skill(s) into your user skills directory. |
| `.assistant/skills/<tool>/SKILL.md` | Per-tool reference doc + Genie Code skill (one per tool). |
| `scripts/deploy_notebook.py` | Import/update a notebook (`--notebook <name>`/`all`) into a workspace. |
| `requirements.txt` | Python deps (`databricks-sdk`); the notebooks `%pip install -r` it. |
| `docs/account-admin-setup.md` | Account-admin service-principal + secret-scope setup (applying a policy). |
| `docs/cbi-sdk-schema.md` | The verified `AccountNetworkPolicy` SDK object model. |
| `docs/threat-intel-feeds.md` | The enrichment feeds, what each represents, licensing. |

## Notes & caveats

- Requires `databricks-sdk>=0.113.0` for the network-policy dataclasses — the helper notebooks pin it
  in `requirements.txt` and restart Python to ensure it on serverless / older runtimes. Checkers use
  no SDK.
