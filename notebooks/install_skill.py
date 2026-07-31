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
import base64
import os

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.workspace import ImportFormat

SKILL_NAME = "cbi-helper"

# This notebook lives at <repo>/notebooks/install_skill.py. The skill is at
# <repo>/.assistant/skills/cbi-helper/. Resolve the repo root from this notebook's workspace path.
_nb_path = (
    dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
)
_repo_root = os.path.dirname(os.path.dirname(_nb_path))  # up from /notebooks/install_skill
SKILL_SRC = f"{_repo_root}/.assistant/skills/{SKILL_NAME}"

w = WorkspaceClient()
_me = w.current_user.me().user_name

if TARGET_SCOPE == "user":
    TARGET_DIR = f"/Users/{_me}/.assistant/skills/{SKILL_NAME}"
else:
    TARGET_DIR = f"/Workspace/.assistant/skills/{SKILL_NAME}"

print(f"notebook path : {_nb_path}")
print(f"skill source  : {SKILL_SRC}")
print(f"install target: {TARGET_DIR}  (scope={TARGET_SCOPE}, overwrite={OVERWRITE})")

# COMMAND ----------

# DBTITLE 1,Copy the skill files
def _iter_files(root):
    """Yield workspace object paths under `root` recursively (files only)."""
    for obj in w.workspace.list(root):
        if str(obj.object_type) in ("ObjectType.DIRECTORY", "DIRECTORY"):
            yield from _iter_files(obj.path)
        else:
            yield obj.path


try:
    src_files = list(_iter_files(SKILL_SRC))
except Exception as e:  # noqa: BLE001
    raise RuntimeError(
        f"Could not list the skill source at {SKILL_SRC}. Run this notebook from the repo/git "
        f"folder checkout so the .assistant/skills/{SKILL_NAME} folder sits alongside it."
    ) from e

if not src_files:
    raise RuntimeError(f"No files found under {SKILL_SRC}.")

w.workspace.mkdirs(TARGET_DIR)
copied = 0
for src in src_files:
    rel = src[len(SKILL_SRC):].lstrip("/")
    dst = f"{TARGET_DIR}/{rel}"
    # Read source bytes (export RAW) and write to the target (import RAW).
    content_b64 = w.workspace.export(path=src, format="RAW").content  # base64 string
    parent = os.path.dirname(dst)
    if parent:
        w.workspace.mkdirs(parent)
    w.workspace.import_(path=dst, content=content_b64, format=ImportFormat.RAW, overwrite=OVERWRITE)
    print(f"  copied {rel}")
    copied += 1

print(f"\nInstalled {copied} file(s) to {TARGET_DIR}")
print("Genie Code will pick up the skill next time you use it. Invoke explicitly with @cbi-helper.")
