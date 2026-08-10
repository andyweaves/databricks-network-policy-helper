"""dbx-netpolicy — the Typer CLI.

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
    AclConfig,
    ApplyOptions,
    Connection,
    EgressConfig,
    IngressConfig,
    validate_apply,
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
    single = "single"; per_workspace = "per_workspace"  # noqa: E702


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
    """The review gate. Returns True if the user has confirmed (or --yes given)."""
    if yes:
        return True
    console.mode_banner(cfg_mode)
    return typer.confirm(
        typer.style("Review the proposed rules above. Create/apply the policy now?", fg="yellow"),
        default=False)


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
    policy_scope: Scope = typer.Option(Scope.single, help="One policy, or one per workspace."),
    policy_mode: Mode = typer.Option(Mode.dry_run, help="dry_run=log-only; enforce=blocking."),
    threat_deny_rules: ThreatDeny = typer.Option(ThreatDeny.off, help="Threat-intel deny rules."),
    name_prefix: str = typer.Option("np-helper", help="Prefix for policy names/labels."),
    ip_acl_handling: AclHandling = typer.Option(
        AclHandling.migrate_and_enrich, help="How to treat an existing IP ACL."),
    deny_denied_ips: bool = typer.Option(False, help="Deny currently-denied (403) source IPs."),
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
        name_prefix=name_prefix, ip_acl_handling=ip_acl_handling.value,
        deny_denied_ips=deny_denied_ips,
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
    policy_scope: Scope = typer.Option(Scope.single, help="One policy, or one per workspace."),
    policy_mode: Mode = typer.Option(Mode.dry_run, help="dry_run=log-only; enforce=blocking."),
    block_threat_domains: ThreatDeny = typer.Option(
        ThreatDeny.off, help="Block known-bad domains: off/matched_only/all."),
    threat_feed: str = typer.Option("threatfox", help="Threat-domain feed."),
    name_prefix: str = typer.Option("np-helper", help="Prefix for policy names/labels."),
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
        policy_mode=policy_mode.value, policy_scope=policy_scope.value,
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
    name_prefix: str = typer.Option("np-helper", help="Prefix for the policy name/labels."),
    egress_policy: AclEgress = typer.Option(AclEgress.allow_all, help="Egress set on create."),
    auto_assign: bool = typer.Option(True, help="Bind this workspace to the new policy."),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply)."),
    account_host: str = typer.Option("https://accounts.cloud.databricks.com", help="Account host."),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."),
    create_policy: bool = typer.Option(False, help="Master switch: write the policy."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the interactive review gate."),
):
    """Recreate this workspace's existing IP access list as a CBI policy, verbatim."""
    cfg = AclConfig(
        policy_mode=policy_mode.value, name_prefix=name_prefix, egress_policy=egress_policy.value,
        auto_assign=auto_assign, create_policy=create_policy,
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
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel("Context-Based Ingress (CBI) Helper",
                        "Propose a CBI allow-list from real audit-log source IPs.")
    render.ingress_decisions(cfg)
    _confirm_params(yes)

    wc = auth.workspace_client(conn)
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
                              note=lambda m: console.banner("info", m))
    render.apply_results(results, conn.account_host, conn.account_id)


def _run_egress(cfg: EgressConfig, conn: Connection, yes: bool) -> None:
    from . import auth, sql
    from .core import egress as eg

    try:
        validate_apply(cfg.apply, cfg.policy_scope, other_direction="ingress")
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel("Egress Policy Helper (serverless egress / SEG)",
                        "Propose an egress allow-list from observed outbound traffic.")
    render.egress_decisions(cfg)
    _confirm_params(yes)

    http_path = sql.resolve_warehouse(conn)
    with sql.connection(conn, http_path) as sconn:
        analysis = eg.analyze(cfg, sconn, on_step=_step)

    render.egress_analysis(analysis)
    previews = eg.preview_blocks(analysis, cfg)
    render.egress_preview(previews, cfg)

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
    this_ws = auth.this_workspace_id(conn)
    with console.status("Applying egress policy…"):
        results = eg.apply(analysis, cfg, account, conn.account_id, this_ws,
                           note=lambda m: console.banner("info", m))
    render.apply_results(results, conn.account_host, conn.account_id)


def _run_acl(cfg: AclConfig, conn: Connection, yes: bool) -> None:
    from . import auth
    from .core import acl as acl_core

    console.title_panel("IP Access List → CBI migration",
                        "Recreate this workspace's IP ACL as a CBI policy, verbatim.")
    render.acl_decisions(cfg)
    _confirm_params(yes)

    wc = auth.workspace_client(conn)
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

    if not cfg.create_policy:
        console.banner("info", "Propose-only run (no --create-policy). Nothing was written.")
        return
    if not _confirm_write(cfg.policy_mode, yes):
        console.banner("info", "Aborted — nothing written.")
        return

    account = auth.account_client(conn)
    with console.status("Applying policy…"):
        result = acl_core.apply(analysis, cfg, account, conn.account_id,
                                note=lambda m: console.banner("info", m))
    render.apply_results([result], conn.account_host, conn.account_id)


if __name__ == "__main__":
    app()
