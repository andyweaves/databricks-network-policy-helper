# Databricks notebook source
# MAGIC %md
# MAGIC # Full Policy Checker (read-only review of a running ingress + egress policy)
# MAGIC
# MAGIC Combines the **ingress** and **egress** checkers into one review of an already-running account
# MAGIC network policy. It `%run`s `ingress_policy_checker` and `egress_policy_checker` (both read-only),
# MAGIC then prints a **combined health summary** across both directions.
# MAGIC
# MAGIC Use the individual checkers if you only care about one direction. Their widgets (lookback,
# MAGIC min_events, filters, threat-intel flags) apply here too — set them in the widget bar.
# MAGIC
# MAGIC > ✋ **Read-only.** Like the checkers it runs, this writes nothing. Take the ADD candidates to
# MAGIC > `full_policy_helper` (or your change process) to actually update the policy.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Run the ingress checker
# MAGIC
# MAGIC `%run` shares this notebook's namespace, so after this cell the ingress checker's `review_df`
# MAGIC and `add_candidates` are available. We capture them under ingress-specific names before running
# MAGIC the egress checker (which reuses the same variable names).

# COMMAND ----------

# MAGIC %run ./ingress_policy_checker

# COMMAND ----------

# DBTITLE 1,Capture ingress results
import pandas as pd

ingress_review = review_df.copy() if isinstance(review_df, pd.DataFrame) else pd.DataFrame()
ingress_add = add_candidates.copy() if isinstance(add_candidates, pd.DataFrame) else pd.DataFrame()
ingress_keep = working_as_intended.copy() if isinstance(working_as_intended, pd.DataFrame) else pd.DataFrame()
print(f"ingress: {len(ingress_review)} denied source(s), {len(ingress_add)} ADD candidate(s), "
      f"{len(ingress_keep)} working-as-intended.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Run the egress checker
# MAGIC
# MAGIC After this, the egress checker's `review_df` / `add_candidates` / `flagged_denials` are current.

# COMMAND ----------

# MAGIC %run ./egress_policy_checker

# COMMAND ----------

# DBTITLE 1,Capture egress results
egress_review = review_df.copy() if isinstance(review_df, pd.DataFrame) else pd.DataFrame()
egress_add = add_candidates.copy() if isinstance(add_candidates, pd.DataFrame) else pd.DataFrame()
egress_keep = flagged_denials.copy() if isinstance(flagged_denials, pd.DataFrame) else pd.DataFrame()
print(f"egress: {len(egress_review)} denied destination(s), {len(egress_add)} ADD candidate(s), "
      f"{len(egress_keep)} flagged-denial(s).")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Combined policy-health summary
# MAGIC
# MAGIC One view across both directions: how much each is denying, what to consider adding, and what's
# MAGIC being blocked as intended. Removals aren't assessed — the network system tables log only denied
# MAGIC traffic, not allowed traffic, so unused allow rules aren't visible from here.

# COMMAND ----------

# DBTITLE 1,Summary
def _sum(df, col):
    return int(df[col].sum()) if (isinstance(df, pd.DataFrame) and col in df) else 0


summary = pd.DataFrame([
    {
        "direction": "ingress (CBI)",
        "denied_entities": len(ingress_review),
        "enforced_denials": _sum(ingress_review, "enforced_denials"),
        "dry_run_denials": _sum(ingress_review, "dry_run_denials"),
        "add_candidates": len(ingress_add),
        "blocked_as_intended": len(ingress_keep),
    },
    {
        "direction": "egress (SEG)",
        "denied_entities": len(egress_review),
        "enforced_denials": _sum(egress_review, "enforced_denials"),
        "dry_run_denials": _sum(egress_review, "dry_run_denials"),
        "add_candidates": len(egress_add),
        "blocked_as_intended": len(egress_keep),
    },
])
display(summary)

_total_add = len(ingress_add) + len(egress_add)
_total_dry = _sum(ingress_review, "dry_run_denials") + _sum(egress_review, "dry_run_denials")
_total_enf = _sum(ingress_review, "enforced_denials") + _sum(egress_review, "enforced_denials")
print(f"\nAcross both directions: {_total_add} ADD candidate(s) to review "
      f"(ingress {len(ingress_add)} + egress {len(egress_add)}).")
if _total_dry and not _total_enf:
    print("All denials are dry-run — the policy is in preview and blocking nothing yet. Work through "
          "the ADD candidates in each checker above, then move to enforce.")
elif _total_enf:
    print("Some denials are enforced (live) — any legitimate traffic among the ADD candidates is "
          "being blocked right now. Prioritise reviewing those.")
print("\nRemovals not assessed (only denials are logged). This notebook made no changes.")
