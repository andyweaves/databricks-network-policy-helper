#!/usr/bin/env python3
"""Deploy (import/update) the CBI Helper notebook into a Databricks workspace.

The notebook `audit_log_cbi.py` (next to this script) is the analysis + proposal + apply engine.
This helper imports it via the Databricks CLI so it can be run in the target workspace.

Examples
--------
    # Import into your home dir on a given CLI profile
    python deploy_notebook.py --profile my-workspace

    # Import to an explicit path, overwriting any existing copy
    python deploy_notebook.py --profile my-workspace \
        --path /Users/you@example.com/audit_log_cbi --overwrite

Requires the Databricks CLI, authenticated for the chosen --profile. Only imports the notebook;
it does not run it or touch any network policy.
"""
import argparse
import subprocess
import sys
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "notebooks" / "audit_log_cbi.py"


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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True, help="Databricks CLI profile (must be authenticated)")
    ap.add_argument("--path", help="Target workspace path (default: /Users/<you>/audit_log_cbi)")
    ap.add_argument("--overwrite", action="store_true", help="Overwrite an existing notebook at the path")
    args = ap.parse_args()

    if not NOTEBOOK.exists():
        sys.exit(f"Notebook source not found: {NOTEBOOK}")

    path = args.path
    if not path:
        user = _current_user(args.profile)
        if not user:
            sys.exit("Could not resolve current user; pass --path explicitly.")
        path = f"/Users/{user}/audit_log_cbi"

    cmd = [
        "databricks", "workspace", "import", path,
        "--format", "SOURCE", "--language", "PYTHON",
        "--file", str(NOTEBOOK), "--profile", args.profile,
    ]
    if args.overwrite:
        cmd.append("--overwrite")

    r = _run(cmd)
    if r.returncode != 0:
        sys.exit(f"Import failed:\n{r.stderr or r.stdout}")
    print(f"Imported CBI Helper notebook -> {path}")
    print("Open it in the workspace, set the widgets at the top, and run top to bottom.")


if __name__ == "__main__":
    main()
