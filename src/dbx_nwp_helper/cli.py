"""dbx-nwp-helper — the Typer CLI.

Commands:
  ingress       Build/apply a context-based ingress (CBI) allow-list from audit-log source IPs.
  egress        Build/apply a serverless egress (SEG) allow-list from observed outbound traffic.
  migrate-acl   Recreate this workspace's IP access list as a CBI policy, verbatim.
  guided        Interactive Q&A wizard — point it at a workspace and it walks you through a policy.
  feeds         Manage the local threat-intel / cloud-range feed cache.

Every notebook widget maps to a flag here; the guided command exposes the same choices as prompts.
Nothing is written unless --create-policy is set, and an interactive review gate (or --yes) guards
the write. Auth is the SDK's unified auth (a --profile, DATABRICKS_* env, or OAuth).
"""

from __future__ import annotations

from enum import Enum

import typer

from . import console, render
from .config import (
    MAX_POLICY_ID_LEN,
    AclConfig,
    ApplyOptions,
    Connection,
    EgressConfig,
    IngressConfig,
    validate_apply,
    validate_disable_ip_acls,
    validate_policy_name,
)

app = typer.Typer(
    add_completion=False, no_args_is_help=True, rich_markup_mode="rich",
    help="Build Databricks account network policies from real observed traffic.",
)
feeds_app = typer.Typer(no_args_is_help=True, help="Manage the local feed cache.")
app.add_typer(feeds_app, name="feeds")


@app.callback()
def _main() -> None:
    """Runs before every command — make TLS verification use the OS trust store so corporate
    proxy CAs are honoured by the SDK, the SQL connector, and feed downloads alike."""
    from . import tls
    tls.enable()


# --- Enums so Typer validates + shows choices (mirroring config.py) ---
class Framing(str, Enum):
    minimal = "minimal"; optimal = "optimal"; maximum = "maximum"  # noqa: E702


class Scoping(str, Enum):
    ip_only = "ip_only"; ip_and_destination = "ip_and_destination"  # noqa: E702
    ip_and_identity = "ip_and_identity"; ip_identity_and_destination = "ip_identity_and_destination"  # noqa: E702


class Scope(str, Enum):
    current_workspace = "current_workspace"  # noqa: E702
    per_workspace = "per_workspace"; all_workspaces = "all_workspaces"  # noqa: E702


class Mode(str, Enum):
    dry_run = "dry_run"; enforce = "enforce"  # noqa: E702


class ThreatDeny(str, Enum):
    off = "off"; matched_only = "matched_only"; all = "all"  # noqa: E702


class AclHandling(str, Enum):
    migrate_and_enrich = "migrate_and_enrich"; migrate = "migrate"; ignore = "ignore"  # noqa: E702


class Action(str, Enum):
    create_new = "create_new"; add_to_existing = "add_to_existing"  # noqa: E702


class AclEgress(str, Enum):
    allow_all = "allow_all"; dry_run = "dry_run"; restricted = "restricted"  # noqa: E702


def _available_profiles() -> list[str]:
    """Profile names configured in ~/.databrickscfg (or $DATABRICKS_CONFIG_FILE)."""
    import configparser
    import os

    path = os.path.expanduser(os.environ.get("DATABRICKS_CONFIG_FILE") or "~/.databrickscfg")
    if not os.path.exists(path):
        return []
    cp = configparser.ConfigParser()
    try:
        cp.read(path)
    except configparser.Error:
        return []
    # DEFAULT is a real, selectable profile in .databrickscfg; ConfigParser hides it in sections().
    names = list(cp.sections())
    if cp.defaults():
        names = ["DEFAULT", *names]
    return names


def _resolve_profile(profile: str | None) -> str | None:
    """Require an explicit profile choice rather than silently falling back to the first-configured
    one. If --profile is given, use it. If env-based auth is configured (DATABRICKS_HOST), allow it
    through. Otherwise prompt the user to pick from ~/.databrickscfg; error if none / non-interactive."""
    import os
    import sys

    if profile:
        return profile
    if os.environ.get("DATABRICKS_HOST"):
        return None  # explicit env auth — respect it

    profiles = _available_profiles()
    if not profiles:
        raise typer.BadParameter(
            "No --profile given and no profiles found in ~/.databrickscfg. Pass --profile <name> "
            "or run `databricks auth login` first.")
    if not sys.stdin.isatty():
        raise typer.BadParameter(
            "No --profile given (non-interactive). Pass --profile <name> explicitly — the CLI won't "
            f"guess. Available: {', '.join(profiles)}")

    import questionary
    choice = questionary.select(
        "Which Databricks profile? (pass --profile to skip this prompt)", choices=profiles).ask()
    if not choice:
        raise typer.Abort()
    return choice


# Shared connection options (used by every command that hits the workspace).
def _conn(profile, warehouse_http_path, account_id, account_host, account_profile=None) -> Connection:
    profile = _resolve_profile(profile)
    return Connection(profile=profile, warehouse_http_path=warehouse_http_path,
                      account_id=account_id or "", account_host=account_host,
                      account_profile=account_profile)


def _step(message: str) -> None:
    console.console.print(f"[muted]· {message}[/muted]")


def _ensure_account_id(conn: Connection, reason: str) -> None:
    """Ensure conn.account_id is set before account-level work begins, prompting for it up front
    rather than failing deep in the apply/SCIM step. `reason` explains why it's needed. Mutates conn.
    Prompts interactively; errors clearly when non-interactive."""
    import sys

    if conn.account_id:
        return
    msg = (f"{reason} needs a Databricks account_id (numeric). Find it in the Account console "
           "top-right user menu, or in the account-console URL after '/account/'.")
    if not sys.stdin.isatty():
        raise typer.BadParameter(
            f"{msg}\nPass --account-id <id> (non-interactive, so the CLI can't prompt).")
    import questionary
    console.banner("info", msg)
    entered = (questionary.text("Databricks account_id:").ask() or "").strip()
    if not entered:
        raise typer.Abort()
    conn.account_id = entered


def _confirm_workspace(conn: Connection, yes: bool):
    """Resolve the workspace client and surface exactly which workspace this run reads from and (on
    apply) modifies — profile, URL, id — then gate on Y/N so the target can't be mistaken. Always
    displays; the confirmation is skipped with --yes and is a no-op non-interactively (like
    _confirm_params). Returns the WorkspaceClient (reused by the caller)."""
    import sys

    from . import auth
    wc = auth.workspace_client(conn)
    try:
        host = (wc.config.host or "").rstrip("/") or "unknown"
    except Exception:  # noqa: BLE001 - display best-effort; real auth errors surface later in use
        host = "unknown"
    try:
        ws_id = wc.get_workspace_id()
    except Exception:  # noqa: BLE001
        ws_id = "unknown"
    console.workspace_panel(conn.profile or "env / OAuth", host, ws_id)
    if yes or not sys.stdin.isatty():
        return wc
    if not typer.confirm(
            typer.style("Is this the correct workspace to analyse / modify?", fg="yellow"),
            default=True):
        console.banner("info", "Aborted — re-run with the intended --profile.")
        raise typer.Exit(code=0)
    return wc


def _resolve_acl_policy_name(cfg: AclConfig, conn: Connection, wc, yes: bool) -> None:
    """migrate-acl names the new policy from --policy-name; if that wasn't given, prompt for one
    (blank = use the profile name, falling back to the workspace id). Mutates cfg.policy_name."""
    import sys
    if cfg.policy_name:
        return
    try:
        ws_id = wc.get_workspace_id()
    except Exception:  # noqa: BLE001
        ws_id = None
    default = conn.profile or (str(ws_id) if ws_id is not None else "migrated-policy")
    if yes or not sys.stdin.isatty():
        cfg.policy_name = default
        return
    import questionary
    entered = (questionary.text(
        f"Policy name for the new network policy? (blank = use '{default}')").ask() or "").strip()
    cfg.policy_name = entered or default


def _acl_preflight(account, workspace_id, yes: bool) -> None:
    """migrate-acl account-level pre-checks (run before any migration). Aborts when migration isn't
    supported or possible yet:
      * a PAS (PrivateLink) is attached -> unsupported for now;
      * the workspace already has an ENFORCED CBI ingress policy -> unsupported for now (a correct
        migration would need to intersect with it);
      * the workspace has a DRY-RUN CBI ingress policy -> offer to promote it to enforced, then stop
        (a migration needs an enforced baseline first)."""
    import sys

    from .core import acl as acl_core

    pas = acl_core.workspace_pas_attached(account, workspace_id)
    if pas is True:
        console.banner("danger", "This workspace has a Private Access Settings (PAS) object attached "
                                 "(PrivateLink). Migrating a PAS/PrivateLink workspace to CBI isn't "
                                 "supported yet — aborting.")
        raise typer.Exit(code=1)
    if pas is None:
        console.banner("warn", "Couldn't verify whether a PAS/PrivateLink is attached (account read "
                               "failed). If this workspace uses PrivateLink, migration isn't "
                               "supported yet.")

    assigned_id, state = acl_core.assigned_ingress_state(account, workspace_id)
    if state == "enforced":
        console.banner("danger", f"This workspace already has an ENFORCED CBI ingress policy "
                                 f"('{assigned_id}'). Migrating on top of an existing enforced policy "
                                 "isn't supported yet (it would need to intersect with it) — aborting.")
        raise typer.Exit(code=1)
    if state == "dry_run":
        console.banner("warn", f"This workspace has a DRY-RUN CBI ingress policy ('{assigned_id}') "
                               "with no enforced ingress. A migration needs an enforced baseline first.")
        if not yes and sys.stdin.isatty() and typer.confirm(
                typer.style(f"Promote '{assigned_id}' from dry-run to enforced now?", fg="yellow"),
                default=False):
            with console.status("Promoting policy to enforced…"):
                acl_core.promote_dry_run_to_enforced(
                    account, assigned_id, note=lambda m: console.banner("info", m))
            console.banner("info", "Promoted to enforced. Re-run `migrate-acl` to continue the "
                                   "migration now that an enforced baseline exists.")
        console.banner("info", "Migration cancelled.")
        raise typer.Exit(code=0)


def _note_policy_name(name_prefix: str, policy_name: str) -> None:
    """When an explicit --policy-name is given, show the id it normalises to (so the user sees the
    real id when case/characters/length were adjusted)."""
    if not policy_name:
        return
    from .core import policy
    normalized = policy.policy_name(name_prefix, explicit=policy_name)
    if normalized != policy_name:
        console.banner("info", f"Using policy id '{normalized}' (names are normalised: lowercased, "
                               f"non-alphanumerics become '-', capped at {MAX_POLICY_ID_LEN} chars).")


def _confirm_params(yes: bool) -> None:
    """After showing the config, ask the user to confirm before doing any work. --yes skips it, and
    it's a no-op non-interactively so scripted runs aren't blocked. Aborting exits cleanly (0)."""
    import sys
    if yes or not sys.stdin.isatty():
        return
    if not typer.confirm("Proceed with these parameters? (No to abort and adjust flags)",
                         default=True):
        console.banner("info", "Aborted — adjust the flags and re-run (see --help).")
        raise typer.Exit(code=0)


def _has_rules(policies: dict) -> bool:
    """True if any policy target carries at least one allow or deny rule. Guards the apply path so an
    empty analysis (e.g. no candidate IPs) fails with a clear message instead of a KeyError."""
    return any(p.get("allow") or p.get("deny") for p in (policies or {}).values())


def _confirm_write(cfg_mode: str, yes: bool) -> bool:
    """The write gate. Returns True if the user has confirmed (or --yes given)."""
    if yes:
        return True
    console.mode_banner(cfg_mode)
    return typer.confirm(
        typer.style("Review the proposed rules above. Create/apply the policy now?", fg="yellow"),
        default=False)


def _maybe_disable_ip_acls(disable: bool, results: list[dict], workspace_client) -> None:
    """After a successful create+assign, optionally turn off the workspace's IP access lists. Only
    fires when at least one policy was actually assigned — if the apply errored and assigned nothing,
    we must NOT disable the ACLs (that would strip the workspace's protection). The create+assign
    flag combination itself is validated up front by validate_disable_ip_acls."""
    if not disable:
        return
    if not any(r.get("assigned") is not None for r in results):
        console.banner("warn", "Skipped disabling IP access lists — no policy was assigned (the "
                               "apply may have failed), so the workspace keeps its current "
                               "protection.")
        return
    from .core import acl as acl_core
    try:
        with console.status("Disabling workspace IP access lists…"):
            acl_core.disable_ip_access_lists(
                workspace_client, note=lambda m: console.banner("info", m))
    except Exception as e:  # noqa: BLE001 - the policy is already applied; cleanup failure shouldn't crash
        console.banner("warn",
                       f"Couldn't disable the workspace IP access lists automatically: {e}. The new "
                       "policy is created and assigned (the workspace stays protected — both "
                       "controls just apply for now); disable the IP access lists manually in Admin "
                       "settings if you want them off.")


@app.command()
def ingress(
    profile: str | None = typer.Option(None, help="Databricks CLI/config profile."),
    warehouse_http_path: str | None = typer.Option(
        None, help="SQL warehouse http_path. If omitted, a serverless warehouse is reused/created."),
    lookback_days: int = typer.Option(30, help="Days of system.access.audit history."),
    min_events: int = typer.Option(1, help="Min successful events per IP."),
    treat_null_status_as_success: bool = typer.Option(False, help="Count NULL status as success."),
    include_ipv6: bool = typer.Option(False, help="Analyse IPv6 (policy stays IPv4-only)."),
    include_account_level: bool = typer.Option(
        False, help="Include account-level (workspace_id=0) audit rows (default off; these are "
                    "account console / SCIM traffic, not workspace-scoped)."),
    threat_feeds: str | None = typer.Option(
        None, help="Comma-separated feeds (default: all). See `feeds list`."),
    enable_rdap: bool = typer.Option(True, help="RDAP owner lookup (needed for 'maximum')."),
    refresh_feeds: bool = typer.Option(False, help="Force re-download of cached feeds."),
    policy_framing: Framing = typer.Option(Framing.minimal, help="CIDR framing."),
    scoping_mode: Scoping = typer.Option(Scoping.ip_only, help="Destination/identity scoping."),
    policy_scope: Scope = typer.Option(
        Scope.current_workspace,
        help="current_workspace (default): one policy for the profile's workspace; per_workspace: "
             "one per workspace seen; all_workspaces: a single policy from all workspaces' traffic."),
    policy_mode: Mode = typer.Option(Mode.dry_run, help="dry_run=log-only; enforce=blocking."),
    threat_deny_rules: ThreatDeny = typer.Option(ThreatDeny.off, help="Threat-intel deny rules."),
    name_prefix: str = typer.Option("dbx-nwp", help="Prefix for policy names/labels."),
    policy_name: str = typer.Option(
        "", help="Explicit policy id (single-policy scopes only). Blank = derive from --name-prefix. "
                 "Normalised: lowercased, non-alphanumerics → '-', length-capped."),
    ip_acl_handling: AclHandling = typer.Option(
        AclHandling.migrate_and_enrich, help="How to treat an existing IP ACL."),
    deny_denied_ips: bool = typer.Option(False, help="Deny currently-denied (403) source IPs."),
    disable_existing_ip_acls: bool = typer.Option(
        False, help="After creating AND assigning the policy, disable this workspace's existing IP "
                    "access lists (enableIpAccessLists=false). Requires --create-policy and "
                    "--auto-assign."),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply/identity)."),
    account_host: str = typer.Option("https://accounts.cloud.databricks.com", help="Account host."),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."),
    create_policy: bool = typer.Option(False, help="Master switch: write the policy."),
    policy_action: Action = typer.Option(Action.create_new, help="Create new or add to existing."),
    existing_policy_id: str = typer.Option("", help="Target id for add_to_existing."),
    auto_assign: bool = typer.Option(False, help="Bind the workspace(s) to the policy."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the interactive review gate."),
):
    """Build (and optionally apply) a context-based ingress (CBI) allow-list."""
    from .config import THREAT_FEEDS as ALL_FEEDS

    feeds = ([f.strip() for f in threat_feeds.split(",") if f.strip()] if threat_feeds
             else list(ALL_FEEDS))
    cfg = IngressConfig(
        lookback_days=lookback_days, min_events=min_events,
        treat_null_status_as_success=treat_null_status_as_success, include_ipv6=include_ipv6,
        include_account_level=include_account_level, threat_feeds=feeds, enable_rdap=enable_rdap,
        refresh_feeds=refresh_feeds, policy_framing=policy_framing.value,
        scoping_mode=scoping_mode.value, policy_scope=policy_scope.value,
        policy_mode=policy_mode.value, threat_deny_rules=threat_deny_rules.value,
        name_prefix=name_prefix, policy_name=policy_name, ip_acl_handling=ip_acl_handling.value,
        deny_denied_ips=deny_denied_ips, disable_existing_ip_acls=disable_existing_ip_acls,
        apply=ApplyOptions(create_policy=create_policy, policy_action=policy_action.value,
                           existing_policy_id=existing_policy_id, auto_assign=auto_assign),
    )
    conn = _conn(profile, warehouse_http_path, account_id, account_host, account_profile)
    _run_ingress(cfg, conn, yes)


@app.command()
def egress(
    profile: str | None = typer.Option(None, help="Databricks CLI/config profile."),
    warehouse_http_path: str | None = typer.Option(
        None, help="SQL warehouse http_path. If omitted, a serverless warehouse is reused/created."),
    lookback_days: int = typer.Option(30, help="Days of outbound_network history."),
    min_events: int = typer.Option(1, help="Min events per destination."),
    source_type_filter: str = typer.Option("", help="network_source_type filter (blank=all)."),
    enable_rdap: bool = typer.Option(True, help="Cloud-owner lookup for internet FQDNs."),
    refresh_feeds: bool = typer.Option(False, help="Force re-download of cached feeds."),
    policy_scope: Scope = typer.Option(
        Scope.current_workspace,
        help="current_workspace (default): one policy for the profile's workspace; per_workspace: "
             "one per workspace seen; all_workspaces: a single policy from all workspaces' traffic."),
    policy_mode: Mode = typer.Option(Mode.dry_run, help="dry_run=log-only; enforce=blocking."),
    block_threat_domains: ThreatDeny = typer.Option(
        ThreatDeny.off, help="Block known-bad domains: off/matched_only/all."),
    threat_feed: str = typer.Option("threatfox", help="Threat-domain feed."),
    name_prefix: str = typer.Option("dbx-nwp", help="Prefix for policy names/labels."),
    policy_name: str = typer.Option(
        "", help="Explicit policy id (single-policy scopes only). Blank = derive from --name-prefix. "
                 "Normalised: lowercased, non-alphanumerics → '-', length-capped."),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply)."),
    account_host: str = typer.Option("https://accounts.cloud.databricks.com", help="Account host."),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."),
    create_policy: bool = typer.Option(False, help="Master switch: write the policy."),
    policy_action: Action = typer.Option(Action.create_new, help="Create new or add to existing."),
    existing_policy_id: str = typer.Option("", help="Target id for add_to_existing."),
    auto_assign: bool = typer.Option(False, help="Bind the workspace(s) to the policy."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the interactive review gate."),
):
    """Build (and optionally apply) a serverless egress (SEG) allow-list."""
    cfg = EgressConfig(
        lookback_days=lookback_days, min_events=min_events, source_type_filter=source_type_filter,
        enable_rdap=enable_rdap, refresh_feeds=refresh_feeds, name_prefix=name_prefix,
        policy_name=policy_name, policy_mode=policy_mode.value, policy_scope=policy_scope.value,
        block_threat_domains=block_threat_domains.value, threat_feed=threat_feed,
        apply=ApplyOptions(create_policy=create_policy, policy_action=policy_action.value,
                           existing_policy_id=existing_policy_id, auto_assign=auto_assign),
    )
    conn = _conn(profile, warehouse_http_path, account_id, account_host, account_profile)
    _run_egress(cfg, conn, yes)


@app.command("migrate-acl")
def migrate_acl(
    profile: str | None = typer.Option(None, help="Databricks CLI/config profile."),
    policy_mode: Mode = typer.Option(Mode.enforce, help="enforce (default) or dry_run."),
    policy_name: str = typer.Option(
        "", help="Policy id for the new policy. If omitted you'll be prompted (blank there = use the "
                 "profile name). Normalised: lowercased, non-alphanumerics → '-', length-capped."),
    egress_policy: AclEgress = typer.Option(AclEgress.allow_all, help="Egress set on create."),
    auto_assign: bool = typer.Option(True, help="Bind this workspace to the new policy."),
    disable_existing_ip_acls: bool = typer.Option(
        False, help="After creating AND assigning the policy, disable this workspace's IP access "
                    "lists (enableIpAccessLists=false). Requires --create-policy (assign is on by "
                    "default)."),
    export: str = typer.Option(
        "", help="Write the proposed network-policy JSON to this file (for use with curl / the REST "
                 "API). Works in propose-only mode too."),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply)."),
    account_host: str = typer.Option("https://accounts.cloud.databricks.com", help="Account host."),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."),
    create_policy: bool = typer.Option(False, help="Master switch: write the policy."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the interactive review gate."),
):
    """Recreate this workspace's existing IP access list as a CBI policy, verbatim."""
    cfg = AclConfig(
        policy_mode=policy_mode.value, policy_name=policy_name, egress_policy=egress_policy.value,
        auto_assign=auto_assign, create_policy=create_policy,
        disable_existing_ip_acls=disable_existing_ip_acls, export=export,
    )
    conn = _conn(profile, None, account_id, account_host, account_profile)
    _run_acl(cfg, conn, yes)


@app.command()
def guided(
    profile: str | None = typer.Option(None, help="Databricks CLI/config profile."),
    warehouse_http_path: str | None = typer.Option(
        None, help="SQL warehouse http_path. If omitted, a serverless warehouse is reused/created."),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply/identity)."),
    account_host: str = typer.Option("https://accounts.cloud.databricks.com", help="Account host."),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."),
):
    """Interactive Q&A wizard — walks you through building an ingress/egress/ACL policy."""
    from .guided import run_wizard
    conn = _conn(profile, warehouse_http_path, account_id, account_host, account_profile)
    run_wizard(conn)


# --- feeds subcommands ---
@feeds_app.command("list")
def feeds_list():
    """Show the cached feed tables (name, rows, age)."""
    from .feeds import cache
    rows = cache.status_rows()
    if not rows:
        console.banner("info", f"No cached feeds yet ({cache.cache_dir()}). Run an analysis or "
                               "`feeds refresh` to populate.")
        return
    import pandas as pd
    console.dataframe(pd.DataFrame(rows, columns=["feed", "rows", "age"]),
                      f"Cached feeds ({cache.cache_dir()})")


@feeds_app.command("refresh")
def feeds_refresh():
    """Force a re-download of all enrichment feeds into the cache."""
    from .config import THREAT_FEEDS as ALL_FEEDS
    from .feeds import loaders
    with console.status("Refreshing threat-intel feeds…"):
        loaders.threat_intel(list(ALL_FEEDS), refresh=True)
    with console.status("Refreshing cloud-provider ranges…"):
        loaders.cloud_ranges(refresh=True)
    with console.status("Refreshing Databricks ranges…"):
        loaders.databricks_ranges(refresh=True)
    console.banner("success", "Feed cache refreshed.")


@feeds_app.command("clear")
def feeds_clear():
    """Remove all cached feed files."""
    from .feeds import cache
    removed = cache.clear()
    console.banner("success", f"Removed {len(removed)} cached feed file(s).")


# --------------------------------------------------------------------------------- run helpers
# These are importable by the guided wizard too, so a wizard run and a flag run share one flow.
def _run_ingress(cfg: IngressConfig, conn: Connection, yes: bool) -> None:
    from . import auth, sql
    from .core import ingress as ing
    from .core import ingress_rules as rules

    try:
        validate_apply(cfg.apply, cfg.policy_scope, other_direction="egress")
        validate_disable_ip_acls(cfg.disable_existing_ip_acls, cfg.apply.create_policy,
                                 cfg.apply.auto_assign)
        validate_policy_name(cfg.policy_name, cfg.policy_scope, cfg.apply.policy_action)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel("Context-Based Ingress (CBI) Helper",
                        "Propose a CBI allow-list from real audit-log source IPs.")
    wc = _confirm_workspace(conn, yes)
    render.ingress_decisions(cfg)
    _note_policy_name(cfg.name_prefix, cfg.policy_name)
    _confirm_params(yes)

    # Account-level work (apply, or identity scoping via SCIM) needs an account_id — prompt for it up
    # front rather than failing after the analysis + enrichment have already run.
    if cfg.apply.create_policy or cfg.scope_identity:
        reason = "Creating a policy" if cfg.apply.create_policy else "Identity scoping (SCIM)"
        _ensure_account_id(conn, reason)

    http_path = sql.resolve_warehouse(conn)
    with sql.connection(conn, http_path) as sconn:
        analysis = ing.analyze(cfg, sconn, wc, on_step=_step)

    render.ingress_analysis(analysis, cfg)

    identity_resolution = None
    if cfg.scope_identity:
        with console.status("Resolving identities via account SCIM…"):
            account = auth.account_client(conn)
            identity_resolution = rules.resolve_identities(
                analysis, account, note=lambda m: console.banner("info", m))

    policies = rules.build_rules(analysis, cfg, identity_resolution,
                                 note=lambda m: console.banner("warn", m))
    previews = rules.preview_blocks(policies, cfg, note=lambda m: console.banner("info", m))
    render.ingress_preview(previews, cfg, analysis)
    if previews:
        console.responsibility_warning("source IP addresses / CIDRs")

    if not cfg.apply.create_policy:
        console.banner("info", "Propose-only run (no --create-policy). Nothing was written.")
        return
    if not _has_rules(policies):
        console.banner("danger", "Nothing to apply — the analysis produced no ingress rules, so no "
                                 "policy can be created. Review the candidate funnel above (try "
                                 "--lookback-days / --min-events / --include-account-level).")
        raise typer.Exit(code=1)
    if not _confirm_write(cfg.policy_mode, yes):
        console.banner("info", "Aborted — nothing written.")
        return

    account = auth.account_client(conn)
    this_ws = auth.this_workspace_id(conn)
    with console.status("Applying policy…"):
        results = rules.apply(policies, cfg, account, conn.account_id, this_ws,
                              profile=conn.profile, note=lambda m: console.banner("info", m))
    render.apply_results(results, conn.account_host, conn.account_id)
    _maybe_disable_ip_acls(cfg.disable_existing_ip_acls, results, wc)


def _run_egress(cfg: EgressConfig, conn: Connection, yes: bool) -> None:
    from . import auth, sql
    from .core import egress as eg

    try:
        validate_apply(cfg.apply, cfg.policy_scope, other_direction="ingress")
        validate_policy_name(cfg.policy_name, cfg.policy_scope, cfg.apply.policy_action)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel("Egress Policy Helper (serverless egress / SEG)",
                        "Propose an egress allow-list from observed outbound traffic.")
    _confirm_workspace(conn, yes)
    render.egress_decisions(cfg)
    _note_policy_name(cfg.name_prefix, cfg.policy_name)
    _confirm_params(yes)

    if cfg.apply.create_policy:
        _ensure_account_id(conn, "Creating a policy")

    # current_workspace scope needs this workspace's id to both filter analysis and name the policy.
    this_ws = auth.this_workspace_id(conn) if cfg.policy_scope == "current_workspace" else None

    http_path = sql.resolve_warehouse(conn)
    with sql.connection(conn, http_path) as sconn:
        analysis = eg.analyze(cfg, sconn, on_step=_step, this_workspace_id=this_ws)

    render.egress_analysis(analysis)
    previews = eg.preview_blocks(analysis, cfg, note=lambda m: console.banner("warn", m))
    render.egress_preview(previews, cfg)
    if previews:
        console.responsibility_warning("FQDNs and storage destinations")

    if not cfg.apply.create_policy:
        console.banner("info", "Propose-only run (no --create-policy). Nothing was written.")
        return
    if not previews:
        console.banner("danger", "Nothing to apply — no egress destinations were classified, so no "
                                 "policy can be created. Confirm outbound_network has data for this "
                                 "window (stand up a dry_run egress policy first to populate it).")
        raise typer.Exit(code=1)
    if not _confirm_write(cfg.policy_mode, yes):
        console.banner("info", "Aborted — nothing written.")
        return

    account = auth.account_client(conn)
    if this_ws is None:
        this_ws = auth.this_workspace_id(conn)
    with console.status("Applying egress policy…"):
        results = eg.apply(analysis, cfg, account, conn.account_id, this_ws,
                           profile=conn.profile, note=lambda m: console.banner("info", m))
    render.apply_results(results, conn.account_host, conn.account_id)


def _run_acl(cfg: AclConfig, conn: Connection, yes: bool) -> None:
    from . import auth
    from .core import acl as acl_core

    try:
        validate_disable_ip_acls(cfg.disable_existing_ip_acls, cfg.create_policy, cfg.auto_assign)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel("IP Access List → CBI migration",
                        "Recreate this workspace's IP ACL as a CBI policy, verbatim.")
    wc = _confirm_workspace(conn, yes)
    _resolve_acl_policy_name(cfg, conn, wc, yes)
    render.acl_decisions(cfg)
    _note_policy_name("", cfg.policy_name)
    _confirm_params(yes)

    # migrate-acl always needs account access now: the pre-checks below (PAS + existing CBI policy)
    # are account-level, and applying needs it anyway.
    _ensure_account_id(conn, "Migrating an IP ACL (checks the workspace's existing policy + PAS)")
    account = auth.account_client(conn)
    ws_id = auth.this_workspace_id(conn)
    _acl_preflight(account, ws_id, yes)

    analysis = acl_core.analyze(cfg, wc)
    render.acl_analysis(analysis, cfg)
    if not (analysis.allow_specs or analysis.deny_specs):
        msg = ("No enabled IPv4 IP-access-list entries on this workspace — nothing to migrate.")
        if cfg.create_policy:
            console.banner("danger", msg + " No policy can be created.")
            raise typer.Exit(code=1)
        console.banner("info", msg)
        return

    preview = acl_core.preview_block(analysis, cfg, note=lambda m: console.banner("info", m))
    render.acl_preview(preview, cfg)
    console.responsibility_warning("IP access list entries")

    if cfg.export:
        import json
        payload = acl_core.policy_payload(analysis, cfg, conn.account_id)
        with open(cfg.export, "w") as f:
            json.dump(payload, f, indent=2)
        console.banner("success", f"Wrote proposed network-policy JSON to {cfg.export}.")

    if not cfg.create_policy:
        console.banner("info", "Propose-only run (no --create-policy). Nothing was written.")
        return
    if not _confirm_write(cfg.policy_mode, yes):
        console.banner("info", "Aborted — nothing written.")
        return

    with console.status("Applying policy…"):
        result = acl_core.apply(analysis, cfg, account, conn.account_id,
                                note=lambda m: console.banner("info", m))
    render.apply_results([result], conn.account_host, conn.account_id)
    _maybe_disable_ip_acls(cfg.disable_existing_ip_acls, [result], wc)


if __name__ == "__main__":
    app()
