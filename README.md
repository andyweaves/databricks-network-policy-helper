# 🛡️ Databricks Network Policy Helper

> Build Databricks **account network policies** from *real observed traffic* — not guesswork.

Each tool is a self-contained notebook (+ a 🤖 Databricks Genie Code skill) sharing a common home, a
common safety model, and the same deploy path.

Both directions of an account network policy are covered:

- 📥 **Ingress** — context-based ingress (CBI): who may connect *in*, by source IP.
- 📤 **Egress** — serverless egress (SEG): where workloads may connect *out*, by destination.

🔗 Each helper can either **create a new policy** *or* **add its rules to an existing one** — so you
run them one after the other, pointed at the same policy, to end up with a single combined
ingress + egress policy (see [Combining ingress + egress](#-combining-ingress--egress)).

## 🧰 The tools

Each tool's full detail — what it does, every widget, its safety notes — lives in its skill
(`.assistant/skills/<name>/SKILL.md`) and in the notebook's own header cells. This table is the map.

| Tool | Notebook | Skill / reference | What it does |
|---|---|---|---|
| 📥 **Ingress Helper** (CBI) | [`ingress_helper.py`](notebooks/ingress_helper.py) | [ingress-helper](.assistant/skills/ingress-helper/SKILL.md) | Proposes & applies a CBI allow-list from `system.access.audit` source IPs — enriched with open threat-intel, cloud-provider and Databricks-owned IP ranges + RDAP, optionally scoped by destination/identity. |
| 📤 **Egress Helper** (SEG) | [`egress_helper.py`](notebooks/egress_helper.py) | [egress-helper](.assistant/skills/egress-helper/SKILL.md) | Proposes & applies a SEG allow-list from `system.access.outbound_network` destinations (S3 / GCS / Azure storage + internet FQDNs), with optional threat-intel domain blocking. |
| 🔁 **IP ACL Migration** | [`ip_acl_migration.py`](notebooks/ip_acl_migration.py) | [ip-acl-migration](.assistant/skills/ip-acl-migration/SKILL.md) | Recreates this workspace's existing IP access list as a CBI policy, verbatim — no traffic analysis, no enrichment. |

## 🚀 Quick start

1. 📦 **Deploy a notebook** into a workspace with the Databricks CLI:
   ```bash
   # one notebook (default: ingress_helper)
   python scripts/deploy_notebook.py --profile <cli-profile> --notebook egress_helper --overwrite
   # or all of them
   python scripts/deploy_notebook.py --profile <cli-profile> --notebook all --overwrite
   ```
   Imports to `/Users/<you>/<notebook>`; pass `--path` to change. (You can also clone/attach the repo
   as a Git folder and open the notebooks directly.)
2. 🎛️ **Open the notebook** and set the widgets at the top — every decision lives there.
3. 👀 **Run top to bottom** and review the proposed rules / JSON preview.
4. ✅ **Apply with intent** — start in `dry_run`, review the logged denials, then re-run in `enforce`.

## 🔗 Combining ingress + egress

There's no separate combined notebook — instead, each helper can add its rules to an existing
policy, so you compose one yourself in two runs:

1. 🥇 **Run the first helper** (say the ingress helper) with `create_policy=true` and
   `policy_action=create_new`. It creates the policy and prints its **policy id** (from
   `name_prefix`, e.g. `np-helper`). Use `policy_scope=single`.
2. 🥈 **Run the second helper** (the egress helper) with `create_policy=true`,
   `policy_action=add_to_existing`, and `existing_policy_id` set to the id from step 1. It updates
   **only its own direction** on that policy, leaving the first helper's block intact.

🎉 The result is one account network policy carrying both the ingress and egress blocks. (Order
doesn't matter — either helper can go first.) `add_to_existing` requires `policy_scope=single`, since
it targets one specific policy id.

## 🔒 Safety model

Both helpers share one safety model:

- 🛑 **Nothing is written unless you opt in** — `create_policy=true`. Analysis and proposal are always
  side-effect-free, and a review gate (`reviewed_rules`) blocks the create cell until you confirm.
- 🧪 **Dry-run first.** Default `policy_mode` is `dry_run`, which writes the log-only block and **blocks
  nothing** — it makes the policy *log* what it would deny so you can review it in the network system
  tables (`system.access.inbound_network` / `system.access.outbound_network`).
- ⛔ **Enforce with intent.** `enforce` writes the blocking block and **can lock users or workloads
  out** if the allow-list is incomplete. Stay in `dry_run` until the logged denials are only bad actors.
- 🧬 **The platform stays reachable.** The ingress helper auto-allows Databricks' own control-plane /
  serverless IP ranges, so an enforced ingress policy won't lock the platform out.
- #️⃣ **IPv4 only.** The CBI policy schema is IPv4-only; IPv6 is analysed but never placed in a policy.
- 🧱 **`add_to_existing` never clobbers the other direction** — it replaces only the block for its own
  direction and requires the target policy to already exist (it won't silently create one).

## 🔑 Permissions

- 📖 **Analysis / enrichment:** workspace read on the relevant system tables (`system.access.audit`
  for ingress; `system.access.outbound_network` for egress).
- 👑 **Applying a policy, or identity scoping: account admin** — recommended as an account-admin
  service principal via OAuth M2M with its secret in a secret scope. See
  [`docs/account-admin-setup.md`](docs/account-admin-setup.md).

## 🤖 Databricks Genie Code skills

The repo ships [Databricks Genie Code skills](https://docs.databricks.com/aws/en/genie-code/skills)
under `.assistant/skills/` — one per tool (linked in the table above). Each skill's `SKILL.md` is
also the tool's reference doc. Genie Code discovers per-user skills under
`/Users/<you>/.assistant/skills/`.

✨ **Easiest install:** run [`notebooks/install_skills.py`](notebooks/install_skills.py) from the
repo / Git-folder checkout — its `skills` widget lists every skill in the repo (`ALL` by default) and
copies the selected ones into your user skills directory (a `workspace` scope option exists for an
account-wide install). Or copy the `.assistant/skills/<skill>` folder(s) there by hand.

💬 Once installed, Genie Code picks them up next time you use it; invoke one with `@<skill-name>`
(e.g. `@ingress-helper`, `@egress-helper`) in chat.

## 🗂️ Repo layout

| Path | What |
|---|---|
| `notebooks/ingress_helper.py` | 📥 Build/apply an ingress (CBI) policy from audit-log source IPs. |
| `notebooks/egress_helper.py` | 📤 Build/apply an egress (SEG) policy from observed outbound destinations. |
| `notebooks/ip_acl_migration.py` | 🔁 Migrate this workspace's IP access list into a CBI policy. |
| `notebooks/install_skills.py` | 🤖 Install the Genie Code skill(s) into your user skills directory. |
| `.assistant/skills/<tool>/SKILL.md` | 📚 Per-tool reference doc + Genie Code skill (one per tool). |
| `scripts/deploy_notebook.py` | 📦 Import/update a notebook (`--notebook <name>`/`all`) into a workspace. |
| `requirements.txt` | 📌 Python deps (`databricks-sdk`); the notebooks `%pip install -r` it. |
| `docs/account-admin-setup.md` | 👑 Account-admin service-principal + secret-scope setup (applying a policy). |
| `docs/cbi-sdk-schema.md` | 🧩 The verified `AccountNetworkPolicy` SDK object model. |
| `docs/threat-intel-feeds.md` | 🕵️ The enrichment feeds, what each represents, licensing. |

## 📝 Notes & caveats

- Requires `databricks-sdk>=0.113.0` for the network-policy dataclasses — the notebooks pin it in
  `requirements.txt` and restart Python to ensure it on serverless / older runtimes.
