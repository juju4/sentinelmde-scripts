"""
Pytest file for sentinelmde-backup.py - offline

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-FileCopyrightText: 2025 The python_openobserve authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=unused-argument,redefined-outer-name,missing-function-docstring,too-few-public-methods,no-else-return,duplicate-code,too-many-lines,line-too-long
import os
from pprint import pprint
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


def test_getalerts():
    """Ensure can export alerts"""
    conn = SentinelMDE()

    results = conn.get_alerts(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["kind"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["description"]
    assert results["value"][0]["properties"]["enabled"]
    assert results["value"][0]["properties"]["displayName"]
    assert results["value"][0]["properties"]["severity"]
    assert results["value"][0]["properties"]["lastModifiedUtc"]
    assert results["value"][0]["properties"]["tactics"]
    assert results["value"][0]["type"]
    assert results["value"][0]["name"]


def test_getalerts_csv(tmp_path):
    """Ensure can export alerts as csv"""
    conn = SentinelMDE()

    conn.export_objects(
        sub,
        rg,
        ws,
        "alerts",
        f"{tmp_path}/test-",
        outformat="csv",
        split=False,
        flat=False,
    )

    p = f"{tmp_path}/test-alerts.csv"
    with open(p, "r", encoding="utf-8") as file:
        content = file.read()
        assert (
            "id,name,type,kind,etag,properties.alertRuleTemplateName,properties.displayName,properties.description,properties.severity,"
            in content
        )
        assert "/alertRules/" in content
    assert len(list(tmp_path.iterdir())) == 1


def test_get_automationrules():
    """Ensure can export automation rules"""
    conn = SentinelMDE()

    results = conn.get_automationrules(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["actions"]
    assert results["value"][0]["properties"]["createdBy"]
    assert results["value"][0]["properties"]["displayName"]
    assert results["value"][0]["properties"]["order"]
    assert results["value"][0]["properties"]["lastModifiedTimeUtc"]
    assert results["value"][0]["properties"]["triggeringLogic"]
    assert results["value"][0]["type"]


def test_get_bookmarks():
    """Ensure can export bookmarks"""
    conn = SentinelMDE()

    results = conn.get_bookmarks(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["created"]
    assert results["value"][0]["properties"]["createdBy"]
    assert results["value"][0]["properties"]["displayName"]
    assert results["value"][0]["properties"]["incidentInfo"]
    assert results["value"][0]["properties"]["labels"]
    assert results["value"][0]["properties"]["notes"]
    assert results["value"][0]["type"]


def test_get_contentpackages():
    """Ensure can export contentpackages"""
    conn = SentinelMDE()

    results = conn.get_contentpackages(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["contentId"]
    assert results["value"][0]["properties"]["contentKind"]
    assert results["value"][0]["properties"]["contentProductId"]
    assert results["value"][0]["properties"]["displayName"]
    assert results["value"][0]["properties"]["version"]
    assert results["value"][0]["type"]


def test_get_watchlists():
    """Ensure can export watchlists"""
    conn = SentinelMDE()

    results = conn.get_watchlists(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["created"]
    assert results["value"][0]["properties"]["createdBy"]
    assert results["value"][0]["properties"]["description"]
    assert results["value"][0]["properties"]["displayName"]
    assert results["value"][0]["properties"]["source"]
    assert results["value"][0]["type"]


def test_get_sourcecontrols():
    """Ensure can export sourcecontrols"""
    conn = SentinelMDE()

    results = conn.get_sourcecontrols(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["contentTypes"]
    assert results["value"][0]["properties"]["id"]
    assert results["value"][0]["properties"]["description"]
    assert results["value"][0]["properties"]["displayName"]
    assert results["value"][0]["properties"]["pullRequest"]
    assert results["value"][0]["properties"]["servicePrincipal"]
    assert results["value"][0]["type"]


def test_get_productpackages():
    """Ensure can export productpackages"""
    conn = SentinelMDE()

    results = conn.get_productpackages(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["author"]
    assert results["value"][0]["properties"]["contentId"]
    assert results["value"][0]["properties"]["dependencies"]
    assert results["value"][0]["properties"]["displayName"]
    assert results["value"][0]["properties"]["source"]
    assert results["value"][0]["properties"]["support"]
    assert results["value"][0]["properties"]["installedVersion"]
    assert results["value"][0]["type"]


def test_get_loganalytics_datasources():
    """Ensure can export loganalytics datasources"""
    conn = SentinelMDE()

    results = conn.get_loganalytics_datasources(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["eventLogName"]
    assert results["value"][0]["properties"]["eventTypes"]
    assert results["value"][0]["type"]


def test_get_loganalytics_tables():
    """Ensure can export loganalytics tables"""
    conn = SentinelMDE()

    results = conn.get_loganalytics_tables(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["name"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["archiveRetentionInDays"]
    assert results["value"][0]["properties"]["plan"]
    assert results["value"][0]["properties"]["schema"]
    assert results["value"][0]["properties"]["totalRetentionInDays"]


def test_get_loganalytics_savedsearches():
    """Ensure can export loganalytics saved searches"""
    conn = SentinelMDE()

    results = conn.get_loganalytics_savedsearches(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["category"]
    assert results["value"][0]["properties"]["displayName"]
    assert results["value"][0]["properties"]["query"]


def test_get_loganalytics_usage():
    """Ensure can export loganalytics usage"""
    conn = SentinelMDE()

    results = conn.get_loganalytics_usage(sub, rg, ws)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["currentValue"] == 0
    assert results["value"][0]["limit"]
    assert results["value"][0]["name"]["value"]
    assert results["value"][0]["quotaPeriod"]
    assert results["value"][0]["unit"]


def test_get_workflows():
    """Ensure can export workflows"""
    conn = SentinelMDE()

    results = conn.get_workflows_byrg(sub, rg)
    pprint(results)
    assert results
    assert results["value"]
    assert results["value"][0]
    assert results["value"][0]["id"]
    assert results["value"][0]["type"]
    assert results["value"][0]["properties"]
    assert results["value"][0]["properties"]["accessEndpoint"]
    assert results["value"][0]["properties"]["definition"]
    assert results["value"][0]["properties"]["provisioningState"]
    assert results["value"][0]["properties"]["state"]
    assert results["value"][0]["properties"]["version"]
