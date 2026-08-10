# 🛡️ Databricks Network Policy Helper

> Build Databricks **account network policies** from *real observed traffic* — not guesswork.

`dbx-netpolicy` is a visually engaging CLI that turns the Databricks system tables into proposed
**account network policies**, with a dry-run-first, review-gated apply path. Both directions are
covered:

- 📥 **Ingress** — context-based ingress (CBI): who may connect *in*, by source IP.
- 📤 **Egress** — serverless egress (SEG): where workloads may connect *out*, by destination.
- 🔁 **IP ACL migration** — recreate an existing IP access list as a CBI policy, verbatim.

🔗 Each direction can either **create a new policy** *or* **add its rules to an existing** one — so
run them one after the other, pointed at the same policy, for a combined ingress + egress policy.

## 🚀 Quick start

Requires [uv](https://docs.astral.sh/uv/) and a Databricks workspace you can authenticate to.

```bash
uv sync                                    # set up the environment
uv run dbx-netpolicy --help                # see all commands

# Propose-only (writes nothing): analyse audit traffic and preview a CBI policy
uv run dbx-netpolicy ingress --profile <profile> --lookback-days 30

# Or let it walk you through it interactively
uv run dbx-netpolicy guided --profile <profile>
```

`uv tool install .` exposes `dbx-netpolicy` on your PATH so you can drop the `uv run` prefix.

**Auth** is the Databricks SDK's [unified auth](https://docs.databricks.com/dev-tools/auth) — a
`--profile` from `~/.databrickscfg`, `DATABRICKS_*` env vars, or OAuth. Analysis needs only workspace
read on the system tables plus a **SQL warehouse** (pass `--warehouse-http-path`, or the CLI reuses /
creates a small serverless one named `dbx-netpolicy`). **Applying a policy or identity-scoping needs
an account admin** — pass `--account-id` with account-admin credentials (see
[`docs/account-admin-setup.md`](docs/account-admin-setup.md)).

## 🧰 The commands

| Command | What it does |
|---|---|
| 📥 `dbx-netpolicy ingress` | Propose & apply a CBI allow-list from `system.access.audit` source IPs — enriched with open threat-intel, cloud-provider and Databricks-owned IP ranges + RDAP, optionally scoped by destination/identity. |
| 📤 `dbx-netpolicy egress` | Propose & apply a SEG allow-list from `system.access.outbound_network` destinations (S3 / GCS / Azure storage + internet FQDNs), with optional threat-intel domain blocking. |
| 🔁 `dbx-netpolicy migrate-acl` | Recreate this workspace's existing IP access list as a CBI policy, verbatim — no traffic analysis, no enrichment. |
| 🧭 `dbx-netpolicy guided` | Interactive Q&A wizard — point it at a workspace and it walks you through building any of the above. |
| 📦 `dbx-netpolicy feeds` | Manage the local threat-intel / cloud-range feed cache (`list` / `refresh` / `clear`). |

Every option is discoverable with `--help` on any command. The full detail for each tool lives in its
Claude skill under [`.claude/skills/`](.claude/skills/).

## 🔒 Safety model

- 🛑 **Nothing is written unless you opt in** — `--create-policy`. Analysis and proposal are always
  side-effect-free, and an interactive **review gate** confirms before any write (bypass with `--yes`
  for scripting).
- 🧪 **Dry-run first.** Default `--policy-mode` is `dry_run` — writes the log-only block and **blocks
  nothing**, so you can review would-be denials in the network system tables first.
- ⛔ **Enforce with intent.** `--policy-mode enforce` writes the blocking block and **can lock users
  or workloads out** if the allow-list is incomplete. Stay in `dry_run` until the logged denials are
  only bad actors.
- 🧬 **The platform stays reachable.** The ingress helper auto-allows Databricks' own control-plane /
  serverless IP ranges, so an enforced ingress policy won't lock the platform out.
- #️⃣ **IPv4 only.** The CBI policy schema is IPv4-only; IPv6 is analysed but never placed in a policy.
- 🧱 **`add_to_existing` never clobbers the other direction** — it replaces only the block for its own
  direction and requires the target policy to already exist.

## 🔗 Combining ingress + egress

Each helper can add its rules to an existing policy, so you compose one yourself in two runs:

1. 🥇 Run the first direction with `--create-policy --policy-action create_new`. It creates the policy
   (named from `--name-prefix`, e.g. `np-helper`) and prints its **policy id**. Use `--policy-scope
   single`.
2. 🥈 Run the second direction with `--create-policy --policy-action add_to_existing
   --existing-policy-id <id>`. It updates **only its own direction**, leaving the first intact.

🎉 The result is one account network policy carrying both blocks. (Order doesn't matter.)

## 🤖 Claude skills

The repo ships [Claude Code skills](https://docs.claude.com/en/docs/claude-code) under
[`.claude/skills/`](.claude/skills/) — one per tool (`ingress-helper`, `egress-helper`,
`ip-acl-migration`) — so you can drive the CLI conversationally. Each skill's `SKILL.md` is also the
tool's reference doc.

## 🗂️ Repo layout

| Path | What |
|---|---|
| `src/dbx_netpolicy/cli.py` | 🎛️ The Typer CLI (all commands + flags). |
| `src/dbx_netpolicy/guided.py` | 🧭 The interactive Q&A wizard. |
| `src/dbx_netpolicy/core/` | 🧠 Engines: ingress, egress, ACL, policy builders, limits. |
| `src/dbx_netpolicy/feeds/` | 🕵️ Threat-intel / cloud / Databricks range loaders + local cache + RDAP. |
| `src/dbx_netpolicy/{auth,sql,queries}.py` | 🔌 Unified auth, SQL-warehouse connection, system-table queries. |
| `src/dbx_netpolicy/{console,render}.py` | 🎨 Rich theming + result rendering. |
| `.claude/skills/<tool>/SKILL.md` | 📚 Per-tool reference doc + Claude skill. |
| `docs/account-admin-setup.md` | 👑 Account-admin credential setup (applying a policy). |
| `docs/cbi-sdk-schema.md` | 🧩 The verified `AccountNetworkPolicy` SDK object model. |
| `docs/threat-intel-feeds.md` | 🕵️ The enrichment feeds, what each represents, licensing. |
| `tests/` | ✅ Offline engine tests (fixtures; no Databricks/network). |

## 🧪 Development & tests

The test suite is **fully offline** — it uses fixtures and fakes, so it needs no Databricks
workspace, no warehouse, and no network access. Run it with `uv`:

```bash
uv sync                 # once, to set up the dev environment (installs pytest, ruff)
uv run pytest           # run all tests
uv run pytest -q        # quieter output
uv run pytest tests/test_ingress_rules.py       # a single file
uv run pytest -k threat_deny                     # tests matching a keyword
```

Coverage (optional, prints per-module line coverage):

```bash
uv run --with pytest-cov pytest --cov=dbx_netpolicy --cov-report=term-missing
```

Lint with ruff (the CI standard for this repo):

```bash
uv run ruff check src/ tests/     # report issues
uv run ruff check --fix src/ tests/   # auto-fix what it can
```

Please keep `pytest` and `ruff` green before opening a PR. When you change behaviour, add or update a
test — the engines (`core/`), feed parsers (`feeds/`), and query builders (`queries.py`) are all
covered by fast, network-free unit tests, and CLI flows are exercised via Typer's `CliRunner`.

## 📝 Notes & caveats

- Requires `databricks-sdk>=0.113.0` for the network-policy dataclasses (pinned in `pyproject.toml`).
- **Applying a policy needs account-level auth**, which is separate from workspace auth — a workspace
  OAuth session can't call the account API. Use `--account-profile <name>` pointing at an account
  login (`databricks auth login --host <account-console-host> --account-id <id>`), or set account
  creds via env. `--profile` is for the workspace (analysis/warehouse) only.
- **Behind a TLS-inspecting proxy?** The CLI uses [`truststore`](https://pypi.org/project/truststore/)
  to verify TLS against your **OS trust store**, so a corporate root CA is honoured automatically by
  the SDK, the SQL connector, and feed downloads — no configuration needed. If you still hit
  `CERTIFICATE_VERIFY_FAILED` on an unsupported platform, fall back to
  `export SSL_CERT_FILE=/path/to/ca-bundle.pem` (and `REQUESTS_CA_BUNDLE` likewise).
- The egress table (`system.access.outbound_network`) only logs **denied** egress, including
  dry-run would-be-denials — so stand up an egress policy in `dry_run` first, let it observe, then
  run `dbx-netpolicy egress` to turn the observed destinations into an allow-list.
- **Ingress shows no candidate IPs?** The CLI prints a diagnostic funnel explaining where the audit
  rows dropped out. The usual causes: the workspace uses **PrivateLink/NAT** (the audit log records
  the relay's private IP, not the user's public IP — a source-IP allow-list can't be built from
  that), or the public IPs only appear on **account-level** rows (`workspace_id=0`, e.g. account
  console / SCIM) — pass `--include-account-level` to use them.
