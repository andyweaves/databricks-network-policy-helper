"""Configuration dataclasses mirroring the notebook widget option sets.

Each command builds one of these from its CLI flags (or the guided wizard), and the core logic reads
only the dataclass — so the flag surface, the wizard, and the engine never drift apart. The literal
choice sets here are the single source of truth for both Typer's validation and questionary's menus.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- Enumerated choice sets (shared by CLI flags + guided prompts) ---
THREAT_FEEDS = ["spamhaus_drop", "tor_exit", "firehol_level1", "ipsum", "dshield", "cins_ci_army"]
POLICY_FRAMINGS = ["minimal", "optimal", "maximum"]
SCOPING_MODES = ["ip_only", "ip_and_destination", "ip_and_identity", "ip_identity_and_destination"]
POLICY_SCOPES = ["single", "per_workspace"]
POLICY_MODES = ["dry_run", "enforce"]
THREAT_DENY_RULES = ["off", "matched_only", "all"]
IP_ACL_HANDLING = ["migrate_and_enrich", "migrate", "ignore"]
POLICY_ACTIONS = ["create_new", "add_to_existing"]
BLOCK_THREAT_DOMAINS = ["off", "matched_only", "all"]
EGRESS_THREAT_FEEDS = ["threatfox"]
ACL_EGRESS_POLICIES = ["allow_all", "dry_run", "restricted"]

DEFAULT_ACCOUNT_HOST = "https://accounts.cloud.databricks.com"
DEFAULT_NAME_PREFIX = "np-helper"

# Databricks account network-policy limits (warn + auto-cap so proposals stay valid).
MAX_INGRESS_RULES_PER_POLICY = 50
MAX_CIDRS_PER_POLICY = 2000
MAX_IDENTITIES_PER_POLICY = 100
MAX_POLICIES_PER_ACCOUNT = 1000
MAX_DENY_CIDRS = 5000
# Egress limits.
MAX_INTERNET_DESTINATIONS = 100
MAX_STORAGE_DESTINATIONS = 100
# Generated policy ids have an empirical ~30-char limit.
MAX_POLICY_ID_LEN = 30


@dataclass
class Connection:
    """How the CLI reaches the workspace + account. Auth itself is resolved by the SDK's unified
    auth (profile / env / OAuth); this only carries the selectors and the warehouse target."""
    profile: str | None = None
    warehouse_http_path: str | None = None
    # When no warehouse path is given, the CLI reuses/creates a serverless warehouse; store its name.
    warehouse_name: str = "dbx-netpolicy"
    account_id: str = ""
    account_host: str = DEFAULT_ACCOUNT_HOST
    # A workspace OAuth session can't call the account API, so the account client uses its own
    # profile when given. If unset, unified auth resolves account creds from env / matching profile.
    account_profile: str | None = None


@dataclass
class ApplyOptions:
    """The gated write path — shared shape across all three commands."""
    create_policy: bool = False
    policy_action: str = "create_new"   # create_new | add_to_existing
    existing_policy_id: str = ""
    auto_assign: bool = False
    reviewed: bool = False              # the review gate; --yes/--reviewed sets it non-interactively


@dataclass
class IngressConfig:
    # Analysis window & candidate selection
    lookback_days: int = 30
    min_events: int = 1
    treat_null_status_as_success: bool = False
    include_ipv6: bool = False
    include_account_level: bool = False
    # Enrichment
    threat_feeds: list[str] = field(default_factory=lambda: list(THREAT_FEEDS))
    enable_rdap: bool = True
    refresh_feeds: bool = False
    # Policy shape
    policy_framing: str = "minimal"
    scoping_mode: str = "ip_only"
    policy_scope: str = "single"
    policy_mode: str = "dry_run"
    threat_deny_rules: str = "off"
    name_prefix: str = DEFAULT_NAME_PREFIX
    ip_acl_handling: str = "migrate_and_enrich"
    deny_denied_ips: bool = False
    apply: ApplyOptions = field(default_factory=ApplyOptions)

    @property
    def scope_destination(self) -> bool:
        return self.scoping_mode in ("ip_and_destination", "ip_identity_and_destination")

    @property
    def scope_identity(self) -> bool:
        return self.scoping_mode in ("ip_and_identity", "ip_identity_and_destination")

    @property
    def policy_mode_target(self) -> str:
        return {"dry_run": "ingress_dry_run", "enforce": "ingress"}[self.policy_mode]


@dataclass
class EgressConfig:
    lookback_days: int = 30
    min_events: int = 1
    source_type_filter: str = ""
    enable_rdap: bool = True
    refresh_feeds: bool = False
    name_prefix: str = DEFAULT_NAME_PREFIX
    policy_mode: str = "dry_run"
    policy_scope: str = "single"
    block_threat_domains: str = "off"
    threat_feed: str = "threatfox"
    apply: ApplyOptions = field(default_factory=ApplyOptions)


@dataclass
class AclConfig:
    policy_mode: str = "enforce"
    name_prefix: str = DEFAULT_NAME_PREFIX
    egress_policy: str = "allow_all"   # allow_all | dry_run | restricted
    auto_assign: bool = True
    create_policy: bool = False
    reviewed: bool = False

    @property
    def policy_mode_target(self) -> str:
        return {"dry_run": "ingress_dry_run", "enforce": "ingress"}[self.policy_mode]


def validate_apply(apply: ApplyOptions, policy_scope: str, other_direction: str) -> None:
    """Validate the add_to_existing invariants early with an actionable message (mirrors the
    notebooks' upfront checks). `other_direction` names the helper that created the target policy."""
    if not (apply.create_policy and apply.policy_action == "add_to_existing"):
        return
    if not apply.existing_policy_id:
        raise ValueError(
            "policy_action=add_to_existing requires --existing-policy-id "
            f"(e.g. the id the {other_direction} helper created). Set it and re-run."
        )
    if policy_scope != "single":
        raise ValueError(
            "policy_action=add_to_existing updates one supplied policy id, so it needs "
            "policy_scope=single. Switch --policy-scope to single, or use create_new for per_workspace."
        )
