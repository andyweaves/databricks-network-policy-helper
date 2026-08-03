# Databricks notebook source
# MAGIC %md
# MAGIC # Install the CBI Helper Genie Code skill
# MAGIC
# MAGIC Copies the `cbi-helper` skill from this repo's `.assistant/skills/` into **your user skills
# MAGIC directory** — `/Users/<you>/.assistant/skills/cbi-helper/` — where Databricks Genie Code
# MAGIC discovers per-user skills. Run this notebook from the git folder / repo checkout so it can
# MAGIC read the skill source next to itself.
# MAGIC
# MAGIC After installing, Genie Code picks up the skill the next time you use it; you can also invoke
# MAGIC it explicitly by `@cbi-helper` in chat.
# MAGIC
# MAGIC > We install into the **user** path, not `Workspace/.assistant/skills/` (which is a shared,
# MAGIC > admin-scoped location). Set the `target_scope` widget to `workspace` only if you deliberately
# MAGIC > want the skill available account-wide and have permission to write there.

# COMMAND ----------

# DBTITLE 1,Parameters
dbutils.widgets.dropdown("target_scope", "user", ["user", "workspace"], "Install scope")
dbutils.widgets.dropdown("overwrite", "true", ["true", "false"], "Overwrite existing?")
TARGET_SCOPE = dbutils.widgets.get("target_scope")
OVERWRITE = dbutils.widgets.get("overwrite") == "true"

# COMMAND ----------

# DBTITLE 1,Locate the skill source and target
import os
import shutil

from databricks.sdk import WorkspaceClient

SKILL_NAME = "cbi-helper"


def _fuse(path):
    """Map a workspace object path to its /Workspace FUSE filesystem path."""
    return path if path.startswith("/Workspace/") else f"/Workspace{path}"


# This notebook lives at <repo>/notebooks/install_skill. The skill is at
# <repo>/.assistant/skills/cbi-helper/. Resolve the repo root from this notebook's workspace path,
# then work against the /Workspace FUSE mount as ordinary files (no export/import API needed).
_nb_path = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
_repo_root = os.path.dirname(os.path.dirname(_nb_path))  # up from /notebooks/install_skill
SKILL_SRC = _fuse(f"{_repo_root}/.assistant/skills/{SKILL_NAME}")

_me = WorkspaceClient().current_user.me().user_name
if TARGET_SCOPE == "user":
    TARGET_DIR = _fuse(f"/Users/{_me}/.assistant/skills/{SKILL_NAME}")
else:
    TARGET_DIR = _fuse(f"/Workspace/.assistant/skills/{SKILL_NAME}")

print(f"notebook path : {_nb_path}")
print(f"skill source  : {SKILL_SRC}")
print(f"install target: {TARGET_DIR}  (scope={TARGET_SCOPE}, overwrite={OVERWRITE})")

# COMMAND ----------

# DBTITLE 1,Copy the skill files
if not os.path.isdir(SKILL_SRC):
    raise RuntimeError(
        f"Skill source not found at {SKILL_SRC}. Run this notebook from the repo / git-folder "
        f"checkout so the .assistant/skills/{SKILL_NAME} folder sits alongside it.")

if os.path.exists(TARGET_DIR):
    if not OVERWRITE:
        raise RuntimeError(f"{TARGET_DIR} already exists and overwrite=false. Set overwrite=true.")
    shutil.rmtree(TARGET_DIR)

os.makedirs(os.path.dirname(TARGET_DIR), exist_ok=True)
shutil.copytree(SKILL_SRC, TARGET_DIR)

copied = [os.path.relpath(os.path.join(dp, f), TARGET_DIR)
          for dp, _, fs in os.walk(TARGET_DIR) for f in fs]
print(f"Installed {len(copied)} file(s) to {TARGET_DIR}:")
for rel in sorted(copied):
    print(f"  {rel}")
print("\nGenie Code will pick up the skill next time you use it. Invoke explicitly with @cbi-helper.")
