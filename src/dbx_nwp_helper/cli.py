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
    DEFAULT_NAME_PREFIX,
    MAX_POLICY_ID_LEN,
    AclConfig,
    ApplyOptions,
    Connection,
    EgressConfig,
    IngressConfig,
    validate_acl_apply,
    validate_apply,
    validate_disable_ip_acls,
    validate_export,
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


def _profile_config_error(e: Exception, profile: str | None, flag: str) -> None:
    """Turn an SDK client-construction ValueError (e.g. a mistyped profile that isn't in
    ~/.databrickscfg) into a clean, actionable message instead of a raw traceback. Always raises."""
    msg = str(e)
    if profile and "profile configured" in msg:
        available = ", ".join(_available_profiles()) or "(none found)"
        console.banner("danger", f"{flag} '{profile}' isn't configured in your Databricks config "
                                 "(~/.databrickscfg or $DATABRICKS_CONFIG_FILE). Available profiles: "
                                 f"{available}. Fix the name or run `databricks auth login`.")
    else:
        console.banner("danger", f"Couldn't initialise the Databricks client: {msg}")
    raise typer.Exit(code=1) from None


def _workspace_client_or_exit(conn: Connection):
    """Build the workspace client, converting a config/profile ValueError into a clean CLI error."""
    from . import auth
    try:
        return auth.workspace_client(conn)
    except ValueError as e:
        _profile_config_error(e, conn.profile, "--profile")


def _account_client_or_exit(conn: Connection):
    """Build the account client, converting a config/profile ValueError into a clean CLI error."""
    from . import auth
    try:
        return auth.account_client(conn)
    except ValueError as e:
        _profile_config_error(e, conn.account_profile or conn.profile,
                              "--account-profile" if conn.account_profile else "--profile")


def _confirm_workspace(conn: Connection, yes: bool):
    """Resolve the workspace client and surface exactly which workspace this run reads from and (on
    apply) modifies — profile, URL, id — then gate on Y/N so the target can't be mistaken. Always
    displays; the confirmation is skipped with --yes and is a no-op non-interactively (like
    _confirm_params). Returns the WorkspaceClient (reused by the caller)."""
    import sys

    wc = _workspace_client_or_exit(conn)
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


def _resolve_policy_name(cfg, conn: Connection, wc, yes: bool) -> None:
    """Resolve the policy name once, centrally (all three commands). An explicit --policy-name is
    kept as-is; otherwise prompt for one (blank = the profile name, falling back to the workspace
    id). Skipped when the run adds to an existing policy (the id comes from --existing-policy-id).
    Mutates cfg.policy_name. For single-policy scopes the name is the policy id; for per_workspace
    it's the prefix (-> <name>-ws-<id>)."""
    import sys
    if cfg.policy_name:
        return
    if getattr(getattr(cfg, "apply", None), "policy_action", "create_new") == "add_to_existing":
        return
    try:
        ws_id = wc.get_workspace_id()
    except Exception:  # noqa: BLE001
        ws_id = None
    default = conn.profile or (str(ws_id) if ws_id is not None else DEFAULT_NAME_PREFIX)
    if yes or not sys.stdin.isatty():
        cfg.policy_name = default
        return
    import questionary
    entered = (questionary.text(
        f"Policy name for the new network policy? (blank = use '{default}')").ask() or "").strip()
    cfg.policy_name = entered or default


def _acl_preflight(account, workspace_id, will_assign: bool, yes: bool) -> None:
    """migrate-acl account-level pre-checks (run before any migration).

    * A PAS (PrivateLink) attached -> always abort (unsupported for now; the produced policy would
      be incomplete).
    * An existing assigned CBI ingress policy only matters when this run will **assign** the new
      policy (assigning would replace the existing one). When assigning:
        - enforced existing policy -> abort (migrating on top of it isn't supported yet);
        - dry-run existing policy   -> flag, offer to promote it to enforced, then stop (a migration
          needs an enforced baseline first).
      When NOT assigning (propose-only, --export, or --no-auto-assign) the workspace's binding is
      untouched, so we just warn and let the run create/export the (unbound) policy."""
    import sys

    from .core import acl as acl_core

    pas = acl_core.workspace_pas_attached(account, workspace_id)
    if pas is True:
        console.banner("danger", "This workspace has a Private Access Settings (PAS) object attached "
                                 "(PrivateLink). Migrating a PAS/PrivateLink workspace to CBI is NOT "
                                 "supported yet - aborting.")
        raise typer.Exit(code=1)
    if pas is None:
        console.banner("warn", "Couldn't verify whether a PAS/PrivateLink is attached (account read "
                               "failed). If this workspace uses PrivateLink, migration is NOT "
                               "supported yet.")

    vpce = acl_core.workspace_vpc_endpoint_count(account, workspace_id)
    if vpce:
        console.banner("danger", f"This workspace has {vpce} registered VPC (PrivateLink) "
                                 "endpoint(s). Migrating a PrivateLink workspace to CBI is NOT "
                                 "supported yet - aborting.")
        raise typer.Exit(code=1)
    if vpce is None:
        console.banner("warn", "Couldn't verify the workspace's registered VPC endpoints (account "
                               "read failed). If this workspace uses PrivateLink, migration is NOT "
                               "supported yet.")

    assigned_id, state = acl_core.assigned_ingress_state(account, workspace_id)
    if state is None:
        return

    if not will_assign:
        kind = "an ENFORCED" if state == "enforced" else "a DRY-RUN"
        console.banner("warn", f"This workspace already has {kind} CBI ingress policy "
                               f"('{assigned_id}'). This run isn't assigning the new policy, so that "
                               "one stays in place — the new policy will be created/exported but not "
                               "bound to the workspace.")
        return

    if state == "enforced":
        console.banner("danger", f"This workspace already has an ENFORCED CBI ingress policy "
                                 f"('{assigned_id}'). Migrating on top of an existing enforced policy "
                                 "is NOT supported yet - aborting.")
        raise typer.Exit(code=1)

    # dry-run only, and we're about to assign a replacement
    console.banner("warn", f"This workspace has a DRY-RUN CBI ingress policy ('{assigned_id}') with "
                           "no enforced ingress. A migration needs an enforced baseline first.")
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


def _write_json_export(path: str, payload: dict) -> str:
    """Write `payload` as pretty JSON to `path`, and return the final path written.
    If `path` is a directory (or ends with a separator), write `<network_policy_id>.json` inside it;
    create missing parent dirs; and turn write failures into a clean error instead of a traceback."""
    import json
    import os
    from pathlib import Path

    dest = Path(path).expanduser()
    if dest.is_dir() or path.endswith(("/", os.sep)):
        name = payload.get("network_policy_id") or "network-policy"
        dest = dest / f"{name}.json"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Pin UTF-8 so a non-ASCII rule label writes identically on macOS and Windows (whose default
        # text encoding is cp1252, which would otherwise raise on such characters).
        with dest.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except OSError as e:
        console.banner("danger", f"Couldn't write --export to '{path}': {e}")
        raise typer.Exit(code=1) from None
    return str(dest)


def _write_tf_export(path: str, payload: dict) -> str:
    """Write a best-effort Terraform config for `payload` alongside the JSON, and return the path.
    A directory writes `<network_policy_id>.tf` inside it; a file path takes a `.tf` suffix."""
    import os
    from pathlib import Path

    from .core import terraform

    dest = Path(path).expanduser()
    if dest.is_dir() or path.endswith(("/", os.sep)):
        name = payload.get("network_policy_id") or "network-policy"
        dest = dest / f"{name}.tf"
    else:
        dest = dest.with_suffix(".tf")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(terraform.network_policy_hcl(payload), encoding="utf-8")
    except OSError as e:
        console.banner("danger", f"Couldn't write Terraform export to '{path}': {e}")
        raise typer.Exit(code=1) from None
    return str(dest)


def _export_policy(path: str, payload: dict) -> None:
    """Write the proposed policy as both JSON (curl / REST body) and best-effort Terraform."""
    json_dest = _write_json_export(path, payload)
    tf_dest = _write_tf_export(path, payload)
    console.banner("success",
                   f"Wrote proposed network-policy JSON to {json_dest} and Terraform to {tf_dest}.")


def _ingress_preflight(account, workspace_id, new_policy_id: str, yes: bool) -> None:
    """ingress create-and-assign pre-checks. Aborts when we can't safely stand up a public-IP CBI
    policy for the workspace:
      * PrivateLink (PAS) configured on the workspace;
      * the assigned policy has private-access / cross-workspace rules (which this command doesn't
        build and can't yet preserve);
      * the assigned policy already ENFORCES restrictive public ingress;
      * assigning a *new* policy (a different id) would drop an existing restrictive egress on the
        assigned policy (the new policy carries a FULL_ACCESS egress default).
    A restrictive *dry-run* public ingress (or egress we'd drop) just warns. Called only when the run
    will create AND assign a single policy — never for per_workspace or add_to_existing."""
    from .core import acl as acl_core

    pas = acl_core.workspace_pas_attached(account, workspace_id)
    if pas is True:
        console.banner("danger", "This workspace has PrivateLink (a PAS object) configured. Building "
                                 "a CBI ingress policy for a PrivateLink workspace is NOT supported "
                                 "yet - aborting.")
        raise typer.Exit(code=1)
    if pas is None:
        console.banner("warn", "Couldn't verify whether PrivateLink (PAS) is configured (account "
                               "read failed). If this workspace uses PrivateLink, this is NOT "
                               "supported yet.")

    pid, pol = acl_core.assigned_policy(account, workspace_id)
    if pol is None:
        return
    ing = getattr(pol, "ingress", None)
    dry = getattr(pol, "ingress_dry_run", None)
    if acl_core.private_or_xws_restrictive(ing) or acl_core.private_or_xws_restrictive(dry):
        console.banner("danger", f"The policy assigned to this workspace ('{pid}') has private-access "
                                 "or cross-workspace rules, which this command can't preserve yet - "
                                 "aborting.")
        raise typer.Exit(code=1)
    if acl_core.public_restrictive(ing):
        console.banner("danger", f"This workspace already has an ENFORCED restrictive CBI ingress "
                                 f"policy ('{pid}'). Replacing it is NOT supported yet - aborting.")
        raise typer.Exit(code=1)
    if acl_core.public_restrictive(dry):
        console.banner("warn", f"The policy assigned to this workspace ('{pid}') has a restrictive "
                               "DRY-RUN public ingress (not enforced) — assigning the new policy will "
                               "replace it.")
    # Opposite direction: a new policy id rebinds the workspace, dropping the assigned policy's egress
    # (the new policy defaults to FULL_ACCESS egress). Updating the *same* id preserves it, so skip.
    if new_policy_id and new_policy_id != pid:
        _warn_or_abort_dropped_egress(acl_core, pid, getattr(pol, "egress", None), "ingress")


def _warn_or_abort_dropped_egress(acl_core, pid, egress, this_direction: str) -> None:
    """Shared by both preflights: when create-and-assign of a NEW policy id would rebind the
    workspace away from an assigned policy that has a restrictive egress, abort if that egress is
    ENFORCED (real protection lost) or warn if it's DRY-RUN. `this_direction` is the command running
    ('ingress' / 'egress'), used only for the message."""
    if not acl_core.egress_restrictive(egress):
        return
    if acl_core.egress_enforced(egress):
        console.banner("danger",
                       f"The policy assigned to this workspace ('{pid}') has an ENFORCED restrictive "
                       f"egress; creating a new {this_direction} policy would rebind the workspace "
                       f"and drop it - aborting. Use --policy-action add_to_existing "
                       f"--existing-policy-id {pid} to keep the egress and add {this_direction} to it.")
        raise typer.Exit(code=1)
    console.banner("warn",
                   f"The policy assigned to this workspace ('{pid}') has a restrictive DRY-RUN egress "
                   f"(not enforced) — creating a new {this_direction} policy will drop it.")


def _egress_preflight(account, workspace_id, new_policy_id: str, yes: bool) -> None:
    """egress create-and-assign pre-check — the egress-direction mirror of _ingress_preflight.
    Aborts if the policy already assigned to the workspace has an ENFORCED restrictive egress
    (replacing it isn't supported yet); warns if it's a restrictive DRY-RUN egress (assigning
    replaces it). Also guards the opposite direction: assigning a *new* policy id drops the assigned
    policy's ingress (the new policy defaults to FULL_ACCESS ingress), so abort/warn on a restrictive
    ingress there. Allow-all (FULL_ACCESS) blocks — or no assigned policy — are fine. Called only when
    the run will create AND assign a single policy."""
    from .core import acl as acl_core

    pid, pol = acl_core.assigned_policy(account, workspace_id)
    if pol is None:
        return
    egr = getattr(pol, "egress", None)
    if acl_core.egress_restrictive(egr):
        if acl_core.egress_enforced(egr):
            console.banner("danger", "This workspace already has an ENFORCED restrictive egress "
                                     f"policy ('{pid}'). Replacing it is NOT supported yet - "
                                     "aborting.")
            raise typer.Exit(code=1)
        console.banner("warn", f"The policy assigned to this workspace ('{pid}') has a restrictive "
                               "DRY-RUN egress (not enforced) — assigning the new policy will replace "
                               "it.")
    # Opposite direction: a new policy id rebinds the workspace, dropping the assigned policy's
    # ingress (the new egress policy defaults to FULL_ACCESS ingress). Same-id updates preserve it.
    if new_policy_id and new_policy_id != pid:
        ing = getattr(pol, "ingress", None)
        dry = getattr(pol, "ingress_dry_run", None)

        def _ing_restrictive(blk):
            return (acl_core.public_restrictive(blk)
                    or acl_core.private_or_xws_restrictive(blk))

        if _ing_restrictive(ing):
            console.banner("danger",
                           f"The policy assigned to this workspace ('{pid}') has an ENFORCED "
                           "restrictive ingress; creating a new egress policy would rebind the "
                           "workspace and drop it - aborting. Use --policy-action add_to_existing "
                           f"--existing-policy-id {pid} to keep the ingress and add egress to it.")
            raise typer.Exit(code=1)
        if _ing_restrictive(dry):
            console.banner("warn", f"The policy assigned to this workspace ('{pid}') has a "
                                   "restrictive DRY-RUN ingress (not enforced) — creating a new "
                                   "egress policy will drop it.")


def _note_policy_name(policy_name: str) -> None:
    """Show the id the resolved policy name normalises to (so the user sees the real id when
    case/characters/length were adjusted). For per_workspace the name is a prefix, so callers skip
    this there."""
    if not policy_name:
        return
    from .core import policy
    normalized = policy.policy_name("", explicit=policy_name)
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


def _checkpoint(yes: bool) -> None:
    """Step-through pause after a results/preview section: let the user review it and choose whether
    to continue. Aborts the run cleanly (exit 0) on 'n'. On by default; skipped with --yes and in
    non-interactive/scripted runs (so scripting and the guided flow are unaffected)."""
    import sys
    if yes or not sys.stdin.isatty():
        return
    if not typer.confirm(typer.style("Continue to the next step?", fg="yellow"), default=True):
        console.banner("info", "Stopped — nothing further was done.")
        raise typer.Exit(code=0)


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
    policy_name: str = typer.Option(
        "", help="Policy name. If omitted you'll be prompted (blank there = the profile name). The "
                 "policy id for single-policy scopes; the prefix (→ <name>-ws-<id>) for "
                 "per_workspace. Normalised: lowercased, non-alphanumerics → '-', length-capped."),
    ip_acl_handling: AclHandling = typer.Option(
        AclHandling.migrate_and_enrich, help="How to treat an existing IP ACL."),
    deny_denied_ips: bool = typer.Option(False, help="Deny currently-denied (403) source IPs."),
    export: str = typer.Option(
        "", help="Write the proposed network-policy JSON to this path (for curl / the REST API); a "
                 "directory writes <policy-id>.json inside it. Single-policy scopes only. Works in "
                 "propose-only mode too."),
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
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Non-interactive mode: skip all prompts — the step-through pauses between sections and "
             "the review/write gates. Use for scripted runs."),
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
        policy_name=policy_name, export=export,
        ip_acl_handling=ip_acl_handling.value,
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
    policy_name: str = typer.Option(
        "", help="Policy name. If omitted you'll be prompted (blank there = the profile name). The "
                 "policy id for single-policy scopes; the prefix (→ <name>-ws-<id>) for "
                 "per_workspace. Normalised: lowercased, non-alphanumerics → '-', length-capped."),
    export: str = typer.Option(
        "", help="Write the proposed network-policy JSON to this path (for curl / the REST API); a "
                 "directory writes <policy-id>.json inside it. Single-policy scopes only. Works in "
                 "propose-only mode too."),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply)."),
    account_host: str = typer.Option("https://accounts.cloud.databricks.com", help="Account host."),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."),
    create_policy: bool = typer.Option(False, help="Master switch: write the policy."),
    policy_action: Action = typer.Option(Action.create_new, help="Create new or add to existing."),
    existing_policy_id: str = typer.Option("", help="Target id for add_to_existing."),
    auto_assign: bool = typer.Option(False, help="Bind the workspace(s) to the policy."),
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Non-interactive mode: skip all prompts — the step-through pauses between sections and "
             "the review/write gates. Use for scripted runs."),
):
    """Build (and optionally apply) a serverless egress (SEG) allow-list."""
    cfg = EgressConfig(
        lookback_days=lookback_days, min_events=min_events, source_type_filter=source_type_filter,
        enable_rdap=enable_rdap, refresh_feeds=refresh_feeds,
        policy_name=policy_name, export=export,
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
    policy_name: str = typer.Option(
        "", help="Policy id for the new policy. If omitted you'll be prompted (blank there = use the "
                 "profile name). Normalised: lowercased, non-alphanumerics → '-', length-capped."),
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
    create_policy: bool = typer.Option(
        True, help="Write the policy (default). For a propose-only run pass --no-create-policy "
                   "--no-auto-assign. An interactive review gate still confirms before any write."),
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Non-interactive mode: skip all prompts — the step-through pauses between sections and "
             "the review/write gates. Use for scripted runs."),
):
    """Recreate this workspace's existing IP access list as a CBI policy, verbatim."""
    cfg = AclConfig(
        policy_mode=policy_mode.value, policy_name=policy_name,
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
        validate_export(cfg.export, cfg.policy_scope)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel("Context-Based Ingress (CBI) Helper",
                        "Propose a CBI allow-list from real audit-log source IPs.")
    wc = _confirm_workspace(conn, yes)
    _resolve_policy_name(cfg, conn, wc, yes)
    render.ingress_decisions(cfg)
    if cfg.policy_scope != "per_workspace":
        _note_policy_name(cfg.policy_name)
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
    _checkpoint(yes)

    identity_resolution = None
    if cfg.scope_identity:
        with console.status("Resolving identities via account SCIM…"):
            account = _account_client_or_exit(conn)
            identity_resolution = rules.resolve_identities(
                analysis, account, note=lambda m: console.banner("info", m))

    policies = rules.build_rules(analysis, cfg, identity_resolution,
                                 note=lambda m: console.banner("warn", m))
    previews = rules.preview_blocks(policies, cfg, note=lambda m: console.banner("info", m))
    render.ingress_preview(previews, cfg, analysis)
    if previews:
        console.responsibility_warning("source IP addresses / CIDRs")

    if cfg.export:
        if previews:
            payload = rules.export_payload(policies, cfg, conn.account_id or "",
                                           auth.this_workspace_id(conn), profile=conn.profile)
            _export_policy(cfg.export, payload)
        else:
            console.banner("warn", "Nothing to export — the analysis produced no ingress rules.")
    _checkpoint(yes)

    if not cfg.apply.create_policy:
        console.banner("info", "Propose-only run (no --create-policy). Nothing was written.")
        return
    if not _has_rules(policies):
        console.banner("danger", "Nothing to apply — the analysis produced no ingress rules, so no "
                                 "policy can be created. Review the candidate funnel above (try "
                                 "--lookback-days / --min-events / --include-account-level).")
        raise typer.Exit(code=1)

    account = _account_client_or_exit(conn)
    this_ws = auth.this_workspace_id(conn)
    # Pre-check the workspace we'd bind — but only when creating AND assigning a single new policy
    # (per_workspace fans out; add_to_existing targets a chosen policy on purpose).
    if (cfg.apply.auto_assign and cfg.apply.policy_action == "create_new"
            and cfg.policy_scope in ("current_workspace", "all_workspaces")):
        new_id = rules._single_policy_id(cfg, conn.profile, this_ws)
        _ingress_preflight(account, this_ws, new_id, yes)

    if not _confirm_write(cfg.policy_mode, yes):
        console.banner("info", "Aborted — nothing written.")
        return

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
        validate_export(cfg.export, cfg.policy_scope)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel("Egress Policy Helper (serverless egress / SEG)",
                        "Propose an egress allow-list from observed outbound traffic.")
    wc = _confirm_workspace(conn, yes)
    _resolve_policy_name(cfg, conn, wc, yes)
    render.egress_decisions(cfg)
    if cfg.policy_scope != "per_workspace":
        _note_policy_name(cfg.policy_name)
    _confirm_params(yes)

    if cfg.apply.create_policy:
        _ensure_account_id(conn, "Creating a policy")

    # current_workspace scope needs this workspace's id to both filter analysis and name the policy.
    this_ws = auth.this_workspace_id(conn) if cfg.policy_scope == "current_workspace" else None

    http_path = sql.resolve_warehouse(conn)
    with sql.connection(conn, http_path) as sconn:
        analysis = eg.analyze(cfg, sconn, on_step=_step, this_workspace_id=this_ws)

    render.egress_analysis(analysis)
    _checkpoint(yes)
    previews = eg.preview_blocks(analysis, cfg, note=lambda m: console.banner("warn", m))
    render.egress_preview(previews, cfg)
    if previews:
        console.responsibility_warning("FQDNs and storage destinations")

    if cfg.export:
        if previews:
            # this_ws is set for current_workspace (the only scope whose name uses it); None otherwise.
            payload = eg.export_payload(analysis, cfg, conn.account_id or "", this_ws,
                                        profile=conn.profile)
            _export_policy(cfg.export, payload)
        else:
            console.banner("warn", "Nothing to export — no egress destinations were classified.")
    _checkpoint(yes)

    if not cfg.apply.create_policy:
        console.banner("info", "Propose-only run (no --create-policy). Nothing was written.")
        return
    if not previews:
        console.banner("danger", "Nothing to apply — no egress destinations were classified, so no "
                                 "policy can be created. Confirm outbound_network has data for this "
                                 "window (stand up a dry_run egress policy first to populate it).")
        raise typer.Exit(code=1)

    account = _account_client_or_exit(conn)
    if this_ws is None:
        this_ws = auth.this_workspace_id(conn)
    # Pre-check the workspace we'd bind — but only when creating AND assigning a single new policy
    # (per_workspace fans out; add_to_existing targets a chosen policy on purpose).
    if (cfg.apply.auto_assign and cfg.apply.policy_action == "create_new"
            and cfg.policy_scope in ("current_workspace", "all_workspaces")):
        new_id = eg._single_policy_id(cfg, conn.profile, this_ws)
        _egress_preflight(account, this_ws, new_id, yes)

    if not _confirm_write(cfg.policy_mode, yes):
        console.banner("info", "Aborted — nothing written.")
        return

    with console.status("Applying egress policy…"):
        results = eg.apply(analysis, cfg, account, conn.account_id, this_ws,
                           profile=conn.profile, note=lambda m: console.banner("info", m))
    render.apply_results(results, conn.account_host, conn.account_id)


def _acl_ip_gate(analysis, wc, yes: bool) -> None:
    """Right after the workspace is chosen, decide whether there's anything to migrate, based on the
    workspace-wide `enableIpAccessLists` toggle × the number of IP access lists:
      * disabled + 0 rules  → nothing to migrate (exit);
      * disabled + 1+ rules → print the current config, offer to re-enable (interactively); either
        way exit so the migration re-runs against active rules;
      * enabled  + 0 rules  → nothing to migrate (exit);
      * enabled  + 1+ rules → proceed.
    A read failure on the toggle (None) just warns and proceeds. All exits are clean (code 0)."""
    import sys

    from .core import acl as acl_core

    toggle = acl_core.ip_acl_enforcement_state(wc)
    total = len(analysis.ip_acls) + len(analysis.disabled_acls)

    if toggle is False:
        if total == 0:
            console.banner("info", "This workspace's IP access lists are disabled and have no rules. "
                                   "There is nothing to migrate.")
            raise typer.Exit(code=0)
        console.banner("warn", "This workspace's IP access lists are disabled, so there are no "
                               "enabled rules to migrate.")
        render.acl_current_config(analysis)
        if yes or not sys.stdin.isatty():
            console.banner("info", "Re-run interactively to enable them, or set "
                                   "enableIpAccessLists=true manually, then re-run — aborting.")
            raise typer.Exit(code=0)
        if typer.confirm(
                typer.style("Would you like to first enable your IP access lists?", fg="yellow"),
                default=False):
            acl_core.enable_ip_access_lists(wc, note=lambda m: console.banner("info", m))
            console.banner("info", "Enabled — continuing with the migration of the now-active rules.")
            return  # proceed with the run
        console.banner("info", "Nothing to migrate — the IP access lists are not active. Aborting.")
        raise typer.Exit(code=0)

    # toggle is True or None (unknown).
    if total == 0:
        console.banner("info", "This workspace's IP access lists have no rules. There is nothing to "
                               "migrate.")
        raise typer.Exit(code=0)
    if toggle is None:
        console.banner("warn", "Couldn't read this workspace's IP access list enforcement state — "
                               "proceeding.")


def _ensure_acl_policy_name_unique(cfg: AclConfig, account, workspace_id, yes: bool) -> None:
    """migrate-acl only *creates* new policies, so the chosen name must not already exist. If it does,
    re-prompt for a new one (interactively) or abort (non-interactive). Mutates cfg.policy_name."""
    import sys

    from .core import acl as acl_core

    while acl_core.policy_exists(account, acl_core.resolve_policy_id(cfg, workspace_id)):
        pid = acl_core.resolve_policy_id(cfg, workspace_id)
        if yes or not sys.stdin.isatty():
            console.banner("danger", f"A network policy named '{pid}' already exists. migrate-acl "
                                     "only creates new policies — choose a different --policy-name.")
            raise typer.Exit(code=1)
        console.banner("warn", f"A network policy named '{pid}' already exists — enter a different "
                               "name.")
        import questionary
        entered = (questionary.text("New policy name:").ask() or "").strip()
        if not entered:
            raise typer.Abort()
        cfg.policy_name = entered


def _run_acl(cfg: AclConfig, conn: Connection, yes: bool) -> None:
    from .core import acl as acl_core

    try:
        validate_acl_apply(cfg.create_policy, cfg.auto_assign, cfg.disable_existing_ip_acls,
                           cfg.policy_mode)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel("IP Access List → CBI migration",
                        "Recreate this workspace's IP ACL as a CBI policy, verbatim.")
    wc = _confirm_workspace(conn, yes)

    # Read the workspace's IP access lists + enforcement state up front, and decide whether there's
    # anything to migrate at all (the quadrant gate may exit cleanly).
    analysis = acl_core.analyze(cfg, wc)
    _acl_ip_gate(analysis, wc, yes)
    if not (analysis.allow_specs or analysis.deny_specs):
        console.banner("info", "This workspace's IP access lists are all individually disabled — "
                               "there are no enabled rules to migrate.")
        raise typer.Exit(code=0)

    # migrate-acl always needs account access: the pre-checks (PAS / VPC endpoints / existing policy)
    # and the name-uniqueness check are account-level, and applying needs it anyway.
    _ensure_account_id(conn, "Migrating an IP ACL (checks PrivateLink + the existing assigned policy)")
    account = _account_client_or_exit(conn)
    ws_id = analysis.workspace_id
    # An existing assigned policy is only replaced if we're going to assign the new one.
    _acl_preflight(account, ws_id, will_assign=cfg.create_policy and cfg.auto_assign, yes=yes)

    _resolve_policy_name(cfg, conn, wc, yes)
    _ensure_acl_policy_name_unique(cfg, account, ws_id, yes)
    render.acl_decisions(cfg)
    _note_policy_name(cfg.policy_name)
    _confirm_params(yes)

    render.acl_analysis(analysis, cfg)
    _checkpoint(yes)

    preview = acl_core.preview_block(analysis, cfg, note=lambda m: console.banner("info", m))
    render.acl_preview(preview, cfg)
    render.acl_disabled_notice(analysis)   # below [old]/[new], before create: vet disabled rules
    console.responsibility_warning("IP access list entries")

    if cfg.export:
        _export_policy(cfg.export, acl_core.policy_payload(analysis, cfg, conn.account_id))
    _checkpoint(yes)

    if not cfg.create_policy:
        console.banner("info", "Propose-only run (--no-create-policy). Nothing was written.")
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
