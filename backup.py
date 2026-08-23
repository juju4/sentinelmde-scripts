"""
Backup script for Sentinel DefenderXDR environment

Inspired from https://github.com/juju4/ansible-openobserve/blob/main/templates/backup.py.j2

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

from pprint import pprint
import os
import sys

try:
    from git.repo import Repo  # type: ignore

    HAVE_MODULE_GIT = True
except ImportError:
    HAVE_MODULE_GIT = False

from dotenv import load_dotenv  # type: ignore
from sentinelmde import SentinelMDE

load_dotenv()

GIT_COMMIT_ENABLE = False
tenant_id = os.getenv("tenant_id", "")
client_id = os.getenv("client_id", "")
client_secret = os.getenv("client_secret", "")
resource_uri = os.getenv("resource_uri", "")
oauth_uri = os.getenv("oauth_uri", "")
sub = os.getenv("target_subscription_id", "")
rg = os.getenv("target_resourcegroup_name", "")
ws = os.getenv("target_workspace_name", "")
backup_git_repo = os.getenv("backup_git_repo", "/path/to/repo")


conn = SentinelMDE()
conn.config_export(
    sub,
    rg,
    ws,
    ".",
    outformat="json",
    split=True,
    flat=False,
)

# Commit
if GIT_COMMIT_ENABLE is not True:
    sys.exit(0)
if not HAVE_MODULE_GIT:
    print("Fatal! missing Gitpython.")
    sys.exit(1)
repo = Repo(backup_git_repo)
changed = [item.a_path for item in repo.index.diff(None)]
untracked = repo.untracked_files
if not changed and not untracked:
    pprint("no change to commit")
    sys.exit(0)
files_list = [k for k in changed + untracked if k.endswith(".json")]
excluded_list: list[str] = []
pprint(files_list)
git_cmd = repo.git
for f in files_list:
    if "pytest" not in f and f not in excluded_list:
        git_cmd.add(f)
    else:
        pprint(f"  => Excluded file {f}")
git_cmd.commit(message="feat: backup commit from python", no_verify=True)
git_cmd.push()
