#!/usr/bin/env python3
"""Deploy (import/update) one of the network-policy-helper notebooks into a Databricks workspace.

The engine notebooks live in `notebooks/` next to this script:

    ingress_policy_helper   ingress (CBI) proposal + apply engine
    egress_policy_helper    serverless egress (SEG) proposal + apply engine
    full_policy_helper      combines ingress + egress into one policy
    ingress_policy_checker  review a running ingress policy (read-only)
    egress_policy_checker   review a running egress policy (read-only)
    full_policy_checker     combined ingress + egress review (read-only)
    ip_acl_migration        migrate this workspace's IP ACL into a CBI policy
    install_skill           install the Genie Code skill(s)

This helper imports the chosen notebook via the Databricks CLI so it can be run in the target
workspace. It only imports the notebook; it does not run it or touch any network policy.

Examples
--------
    # Import the ingress helper into your home dir on a given CLI profile
    python deploy_notebook.py --profile my-workspace

    # Import a specific notebook to an explicit path, overwriting any existing copy
    python deploy_notebook.py --profile my-workspace --notebook egress_policy_helper \
        --path /Users/you@example.com/egress_policy_helper --overwrite

    # Import every engine notebook into your home dir
    python deploy_notebook.py --profile my-workspace --notebook all --overwrite

Requires the Databricks CLI, authenticated for the chosen --profile.
"""
import argparse
import subprocess
import sys
from pathlib import Path

NOTEBOOKS_DIR = Path(__file__).resolve().parent.parent / "notebooks"
DEFAULT_NOTEBOOK = "ingress_policy_helper"


def _available():
    return sorted(p.stem for p in NOTEBOOKS_DIR.glob("*.py"))


def _run(cmd):
    print("+ " + " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True)


def _current_user(profile):
    r = _run(["databricks", "current-user", "me", "--profile", profile])
    if r.returncode != 0:
        return None
    import json

    try:
        return json.loads(r.stdout).get("userName")
    except (ValueError, AttributeError):
        return None


def _import(name, profile, path, overwrite, user):
    src = NOTEBOOKS_DIR / f"{name}.py"
    if not src.exists():
        return f"Notebook source not found: {src}"
    target = path or f"/Users/{user}/{name}"
    cmd = [
        "databricks", "workspace", "import", target,
        "--format", "SOURCE", "--language", "PYTHON",
        "--file", str(src), "--profile", profile,
    ]
    if overwrite:
        cmd.append("--overwrite")
    r = _run(cmd)
    if r.returncode != 0:
        return f"Import failed for {name}:\n{r.stderr or r.stdout}"
    print(f"Imported {name} -> {target}")
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True, help="Databricks CLI profile (must be authenticated)")
    ap.add_argument("--notebook", default=DEFAULT_NOTEBOOK,
                    help=f"Notebook to import (stem, no .py), or 'all'. Default: {DEFAULT_NOTEBOOK}. "
                         f"Available: {', '.join(_available())}")
    ap.add_argument("--path", help="Target workspace path (default: /Users/<you>/<notebook>). "
                                    "Ignored when --notebook all.")
    ap.add_argument("--overwrite", action="store_true", help="Overwrite an existing notebook at the path")
    args = ap.parse_args()

    available = _available()
    if args.notebook != "all" and args.notebook not in available:
        sys.exit(f"Unknown notebook '{args.notebook}'. Available: {', '.join(available)} (or 'all').")
    if args.notebook == "all" and args.path:
        sys.exit("--path cannot be combined with --notebook all (each notebook needs its own path).")

    user = None
    if not args.path or args.notebook == "all":
        user = _current_user(args.profile)
        if not user:
            sys.exit("Could not resolve current user; pass --path explicitly.")

    names = available if args.notebook == "all" else [args.notebook]
    errors = [e for n in names if (e := _import(n, args.profile, args.path, args.overwrite, user))]
    if errors:
        sys.exit("\n".join(errors))
    print("Open the notebook(s) in the workspace, set the widgets at the top, and run top to bottom.")


if __name__ == "__main__":
    main()
