"""
Pytest file for sentinelmde healthcheck - online

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-FileCopyrightText: 2025 The python_openobserve authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=unused-argument,redefined-outer-name,missing-function-docstring,too-few-public-methods,no-else-return,duplicate-code,too-many-lines,line-too-long
from pprint import pprint
import os

# import pytest  # type: ignore

from dotenv import load_dotenv  # type: ignore
from sentinelmde import SentinelMDE

load_dotenv()

tenant_id = os.getenv("tenant_id", None)
client_id = os.getenv("client_id", None)
client_secret = os.getenv("client_secret", None)
resource_uri = os.getenv("resource_uri", None)
oauth_uri = os.getenv("oauth_uri", None)
sub = os.getenv("target_subscription_id", None)
rg = os.getenv("target_resourcegroup_name", None)
ws = os.getenv("target_workspace_name", None)


def test_connection_settings():
    """Ensure have connection settings from environment"""
    assert tenant_id
    assert client_id
    assert client_secret
    assert resource_uri
    assert oauth_uri


def test_get_availabilitystatuses():
    """Ensure can get availabilitystatuses"""
    conn = SentinelMDE()

    results = conn.get_availabilitystatuses(sub)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["location"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["reasonType"]
    assert results["value"][0]["properties"]["reportedTime"]
    assert results["value"][0]["properties"]["summary"]
    assert results["value"][0]["properties"]["title"]
    assert results["value"][0]["type"]


def test_get_healthevents():
    """Ensure can get healthevents"""
    conn = SentinelMDE()

    results = conn.get_healthevents(
        sub,
    )
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["article"]
    assert results["value"][0]["properties"]["faqs"]
    assert results["value"][0]["properties"]["impact"]
    assert results["value"][0]["properties"]["status"]
    assert results["value"][0]["properties"]["summary"]
    assert results["value"][0]["properties"]["title"]


def test_get_impactedresource():
    """Ensure can get impactedresource"""
    conn = SentinelMDE()

    results = conn.get_impactedresource(
        sub,
        "MOCK_EVENT_TRACKING_ID",
        "MOCK_RESOURCE",
    )

    pprint(results)
    assert results
    assert results["id"]
    assert results["name"]
    assert results["properties"]
    assert results["properties"]["targetResourceId"]


def test_healthcheck():
    """Ensure can get impactedresource"""
    conn = SentinelMDE()

    results = conn.healthcheck(
        sub,
    )

    pprint(results)
    assert "## Healthcheck report for subscription" in results
    assert "Availability status count: " in results
    assert "Health events count: " in results
    assert "Failed LogicApp workflows run" in results
