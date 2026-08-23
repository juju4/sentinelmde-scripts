"""
Healthcheck for Sentinel DefenderXDR environment

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=R0801

from pprint import pprint
import os

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


conn = SentinelMDE()
pprint(conn.healthcheck(sub))
