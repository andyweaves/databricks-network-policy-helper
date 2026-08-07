# Databricks notebook source
# MAGIC %md
# MAGIC # Install Genie Code skill(s)
# MAGIC
# MAGIC Copies skill(s) from this repo's `.assistant/skills/` into **your user skills directory**
# MAGIC (`/Users/<you>/.assistant/skills/<skill>/`), where Databricks Genie Code discovers per-user
# MAGIC skills. Run this notebook from the git-folder / repo checkout so it can read the skill sources.
# MAGIC
# MAGIC Choose which skills to install with the `skills` widget (`ALL` = every skill in the repo). After
# MAGIC installing, Genie Code picks them up next time you use it; invoke one explicitly with
# MAGIC `@<skill-name>` in chat.
# MAGIC
# MAGIC > Installs into the **user** path by default, not `Workspace/.assistant/skills/` (a shared,
# MAGIC > admin-scoped location). Use `target_scope=workspace` only for a deliberate account-wide install.

# COMMAND ----------

# DBTITLE 1,Discover available skills + parameters
import os
import shutil

from databricks.sdk import WorkspaceClient


def _fuse(path):
    """Map a workspace object path to its /Workspace FUSE filesystem path."""
    return path if path.startswith("/Workspace/") else f"/Workspace{path}"


# This notebook lives at <repo>/notebooks/install_skills; skills are at <repo>/.assistant/skills/*.
_nb_path = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
_repo_root = os.path.dirname(os.path.dirname(_nb_path))
SKILLS_ROOT = _fuse(f"{_repo_root}/.assistant/skills")

# A skill is any subdir of .assistant/skills containing a SKILL.md.
AVAILABLE_SKILLS = sorted(
    d for d in (os.listdir(SKILLS_ROOT) if os.path.isdir(SKILLS_ROOT) else [])
    if os.path.isfile(os.path.join(SKILLS_ROOT, d, "SKILL.md"))
)

# Recreate the skills widget each run so its choices track what's actually in the repo.
try:
    dbutils.widgets.remove("skills")
except Exception:  # noqa: BLE001
    pass
dbutils.widgets.multiselect(
    "skills", "ALL", ["ALL"] + AVAILABLE_SKILLS, "Skills to install (ALL = every skill)"
)
dbutils.widgets.dropdown("target_scope", "user", ["user", "workspace"], "Install scope")
dbutils.widgets.dropdown("overwrite", "true", ["true", "false"], "Overwrite existing?")

_sel = [s.strip() for s in dbutils.widgets.get("skills").split(",") if s.strip()]
SELECTED_SKILLS = list(AVAILABLE_SKILLS) if (not _sel or "ALL" in _sel) else [s for s in _sel if s in AVAILABLE_SKILLS]
TARGET_SCOPE = dbutils.widgets.get("target_scope")
OVERWRITE = dbutils.widgets.get("overwrite") == "true"

_me = WorkspaceClient().current_user.me().user_name
TARGET_ROOT = _fuse(f"/Users/{_me}/.assistant/skills") if TARGET_SCOPE == "user" else _fuse("/Workspace/.assistant/skills")

print(f"repo skills root : {SKILLS_ROOT}")
print(f"available skills : {AVAILABLE_SKILLS or '(none found)'}")
print(f"selected         : {SELECTED_SKILLS or '(none)'}")
print(f"install target   : {TARGET_ROOT}  (scope={TARGET_SCOPE}, overwrite={OVERWRITE})")

# COMMAND ----------

# DBTITLE 1,Install the selected skill(s)
if not AVAILABLE_SKILLS:
    raise RuntimeError(
        f"No skills found under {SKILLS_ROOT}. Run this notebook from the repo / git-folder checkout "
        f"so the .assistant/skills folder sits alongside it.")
if not SELECTED_SKILLS:
    raise RuntimeError("No skills selected — pick at least one (or ALL) in the skills widget.")

os.makedirs(TARGET_ROOT, exist_ok=True)
for skill in SELECTED_SKILLS:
    src = os.path.join(SKILLS_ROOT, skill)
    dst = os.path.join(TARGET_ROOT, skill)
    if os.path.exists(dst):
        if not OVERWRITE:
            print(f"  ⏭️  {skill}: already exists and overwrite=false — skipped")
            continue
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    n = sum(len(fs) for _, _, fs in os.walk(dst))
    print(f"  ✅ {skill}: installed {n} file(s) -> {dst}")

print("\nGenie Code will pick up the skill(s) next time you use it. Invoke one with @<skill-name>.")
