"""
Pytest file for sentinelmde-backup.py - offline

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-FileCopyrightText: 2025 The python_openobserve authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=unused-argument,redefined-outer-name,missing-function-docstring,too-few-public-methods,no-else-return,duplicate-code,too-many-lines,line-too-long
from pprint import pprint
import os
import json
import glob
from unittest.mock import patch

# import pytest  # type: ignore

import jmespath
from sentinelmde import SentinelMDE, get_rg_from_id

# pylint: disable=C0103
tenant_id = client_id = client_secret = "MOCK_INPUT"  # nosec B105
resource_uri = oauth_uri = "https://mockurl.example.internal"
sub = rg = ws = "MOCK_INPUT"


# pylint: disable=R0911,R0912
def mock_get(*args, **kwargs):
    """MockResponse function for openobserve calls of httpx.get"""
    url = args[0]

    class MockResponse:
        """MockResponse class for openobserve calls of httpx.get"""

        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    if "/Microsoft.SecurityInsights/alertRules?api-version=2025-09-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "id": (
                            "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
                            "resourceGroups/myRg/providers/Microsoft.OperationalInsights/"
                            "workspaces/myWorkspace/providers/Microsoft.SecurityInsights/"
                            "alertRules/73e01a99-5cd7-4139-a149-9f2736ff2ab5"
                        ),
                        "name": "73e01a99-5cd7-4139-a149-9f2736ff2ab5",
                        "type": "Microsoft.SecurityInsights/alertRules",
                        "kind": "Scheduled",
                        "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
                        "properties": {
                            "alertRuleTemplateName": None,
                            "displayName": "My scheduled rule",
                            "description": "An example for a scheduled rule",
                            "severity": "High",
                            "enabled": True,
                            "tactics": ["Persistence", "LateralMovement"],
                            "query": "Heartbeat",
                            "queryFrequency": "PT1H",
                            "queryPeriod": "P2DT1H30M",
                            "triggerOperator": "GreaterThan",
                            "triggerThreshold": 0,
                            "suppressionDuration": "PT1H",
                            "suppressionEnabled": False,
                            "lastModifiedUtc": "2021-03-01T13:17:30Z",
                            "eventGroupingSettings": {
                                "aggregationKind": "AlertPerResult"
                            },
                            "customDetails": {
                                "OperatingSystemName": "OSName",
                                "OperatingSystemType": "OSType",
                            },
                            "entityMappings": [
                                {
                                    "entityType": "Host",
                                    "fieldMappings": [
                                        {
                                            "identifier": "FullName",
                                            "columnName": "Computer",
                                        }
                                    ],
                                },
                                {
                                    "entityType": "IP",
                                    "fieldMappings": [
                                        {
                                            "identifier": "Address",
                                            "columnName": "ComputerIP",
                                        }
                                    ],
                                },
                            ],
                            "alertDetailsOverride": {
                                "alertDisplayNameFormat": "Alert from {{Computer}}",
                                "alertDescriptionFormat": (
                                    "Suspicious activity was made by {{ComputerIP}}"
                                ),
                                "alertTacticsColumnName": None,
                                "alertSeverityColumnName": None,
                            },
                            "incidentConfiguration": {
                                "createIncident": True,
                                "groupingConfiguration": {
                                    "enabled": True,
                                    "reopenClosedIncident": False,
                                    "lookbackDuration": "PT5H",
                                    "matchingMethod": "Selected",
                                    "groupByEntities": ["Host"],
                                    "groupByAlertDetails": ["DisplayName"],
                                    "groupByCustomDetails": [
                                        "OperatingSystemType",
                                        "OperatingSystemName",
                                    ],
                                },
                            },
                        },
                    },
                    {
                        "id": (
                            "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
                            "resourceGroups/myRg/providers/Microsoft.OperationalInsights/"
                            "workspaces/myWorkspace/providers/Microsoft.SecurityInsights/"
                            "alertRules/microsoftSecurityIncidentCreationRuleExample"
                        ),
                        "name": "microsoftSecurityIncidentCreationRuleExample",
                        "etag": '"260097e0-0000-0d00-0000-5d6fa88f0000"',
                        "type": "Microsoft.SecurityInsights/alertRules",
                        "kind": "MicrosoftSecurityIncidentCreation",
                        "properties": {
                            "productFilter": "Microsoft Cloud App Security",
                            "severitiesFilter": None,
                            "displayNamesFilter": None,
                            "displayName": "testing displayname",
                            "enabled": True,
                            "description": None,
                            "alertRuleTemplateName": None,
                            "lastModifiedUtc": "2019-09-04T12:05:35.7296311Z",
                        },
                    },
                    {
                        "id": (
                            "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
                            "resourceGroups/myRg/providers/Microsoft.OperationalInsights/"
                            "workspaces/myWorkspace/providers/Microsoft.SecurityInsights/"
                            "alertRules/myFirstFusionRule"
                        ),
                        "name": "myFirstFusionRule",
                        "etag": '"25005c11-0000-0d00-0000-5d6cc0e20000"',
                        "type": "Microsoft.SecurityInsights/alertRules",
                        "kind": "Fusion",
                        "properties": {
                            "displayName": "Advanced Multi-Stage Attack Detection",
                            "description": (
                                "In this mode, Sentinel combines low fidelity alerts, "
                                "which themselves may not be actionable, and events across "
                                "multiple products, into high fidelity security interesting "
                                "incidents. The system looks at multiple products to produce "
                                "actionable incidents. Custom tailored to each tenant, Fusion "
                                "not only reduces False positive rates but also can detect "
                                "attacks with limited or missing information. \nIncidents "
                                "generated by Fusion system will encase two or more alerts. "
                                "By design, Fusion incidents are low volume, high fidelity and "
                                "will be high severity, which is why Fusion is turned ON by "
                                "default in Azure Sentinel.\n\nFor Fusion to work, please "
                                "configure the following data sources in Data Connectors tab:\n"
                                "Required - Azure Active Directory Identity Protection\nRequired "
                                "- Microsoft Cloud App Security\nIf Available - Palo Alto "
                                "Network\n\nFor full list of scenarios covered by Fusion, and "
                                "detail instructions on how to configure the required data "
                                "sources, go to aka.ms/SentinelFusion"
                            ),
                            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
                            "tactics": [
                                "Persistence",
                                "LateralMovement",
                                "Exfiltration",
                                "CommandAndControl",
                            ],
                            "severity": "High",
                            "enabled": False,
                            "lastModifiedUtc": "2019-09-02T07:12:34.9065092Z",
                        },
                    },
                ]
            },
            200,
        )

    if "/Microsoft.SecurityInsights/automationRules?api-version=2025-09-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "id": (
                            "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
                            "resourceGroups/myRg/providers/Microsoft.OperationalInsights/"
                            "workspaces/myWorkspace/providers/Microsoft.SecurityInsights/"
                            "automationRules/73e01a99-5cd7-4139-a149-9f2736ff2ab5"
                        ),
                        "name": "73e01a99-5cd7-4139-a149-9f2736ff2ab5",
                        "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
                        "type": "Microsoft.SecurityInsights/automationRules",
                        "properties": {
                            "displayName": "Suspicious user sign-in events",
                            "order": 1,
                            "triggeringLogic": {
                                "isEnabled": True,
                                "triggersOn": "Incidents",
                                "triggersWhen": "Created",
                                "conditions": [
                                    {
                                        "conditionType": "Property",
                                        "conditionProperties": {
                                            "propertyName": "IncidentRelatedAnalyticRuleIds",
                                            "operator": "Contains",
                                            "propertyValues": [
                                                (
                                                    "/subscriptions/"
                                                    "d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
                                                    "resourceGroups/myRg/providers/"
                                                    "Microsoft.OperationalInsights/workspaces/"
                                                    "myWorkspace/providers/"
                                                    "Microsoft.SecurityInsights/"
                                                    "alertRules/"
                                                    "fab3d2d4-747f-46a7-8ef0-9c0be8112bf7"
                                                ),
                                                (
                                                    "/subscriptions/"
                                                    "d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
                                                    "resourceGroups/myRg/providers/"
                                                    "Microsoft.OperationalInsights/workspaces/"
                                                    "myWorkspace/providers/"
                                                    "Microsoft.SecurityInsights/"
                                                    "alertRules/"
                                                    "8deb8303-e94d-46ff-96e0-5fd94b33df1a"
                                                ),
                                            ],
                                        },
                                    }
                                ],
                            },
                            "actions": [
                                {
                                    "order": 1,
                                    "actionType": "AddIncidentTask",
                                    "actionConfiguration": {
                                        "title": "Reset user passwords",
                                        "description": "Reset passwords for compromised users.",
                                    },
                                }
                            ],
                            "lastModifiedTimeUtc": "2019-01-01T13:00:30Z",
                            "createdTimeUtc": "2019-01-01T13:00:00Z",
                            "lastModifiedBy": {
                                "objectId": "2046feea-040d-4a46-9e2b-91c2941bfa70",
                                "email": "john.doe@contoso.com",
                                "name": "john doe",
                                "userPrincipalName": "john@contoso.com",
                            },
                            "createdBy": {
                                "objectId": "2046feea-040d-4a46-9e2b-91c2941bfa70",
                                "email": "john.doe@contoso.com",
                                "name": "john doe",
                                "userPrincipalName": "john@contoso.com",
                            },
                        },
                    }
                ]
            },
            200,
        )

    if "/Microsoft.SecurityInsights/bookmarks?api-version=2025-09-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "id": (
                            "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
                            "resourceGroups/myRg/providers/Microsoft.OperationalInsights/"
                            "workspaces/myWorkspace/providers/Microsoft.SecurityInsights/"
                            "bookmarks/73e01a99-5cd7-4139-a149-9f2736ff2ab5"
                        ),
                        "name": "73e01a99-5cd7-4139-a149-9f2736ff2ab5",
                        "type": "Microsoft.SecurityInsights/bookmarks",
                        "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
                        "properties": {
                            "displayName": "My bookmark",
                            "createdBy": {
                                "objectId": "2046feea-040d-4a46-9e2b-91c2941bfa70",
                                "email": "john@contoso.com",
                                "name": "john doe",
                            },
                            "updatedBy": {
                                "objectId": "2046feea-040d-4a46-9e2b-91c2941bfa70",
                                "email": "john@contoso.com",
                                "name": "john doe",
                            },
                            "updated": "2019-01-01T13:15:30Z",
                            "created": "2019-01-01T13:15:30Z",
                            "notes": "Found a suspicious activity",
                            "labels": ["Tag1", "Tag2"],
                            "query": (
                                "SecurityEvent | where TimeGenerated > ago(1d)"
                                " and TimeGenerated < ago(2d)"
                            ),
                            "queryResult": "Security Event query result",
                            "incidentInfo": {
                                "incidentId": "DDA55F97-170B-40B9-B8ED-CBFD05481E7D",
                                "severity": "Low",
                                "title": "New case 1",
                                "relationName": "4bb36b7b-26ff-4d1c-9cbe-0d8ab3da0018",
                            },
                        },
                    }
                ]
            },
            200,
        )

    if "/contentPackages?api-version=2025-09-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "id": (
                            "/subscriptions/d0cfeab2-9ae0-4464-9919-dccaee2e48f0/"
                            "resourceGroups/myRg/providers/Microsoft.OperationalIinsights/"
                            "workspaces/myWorkspace/providers/Microsoft.SecurityInsights/"
                            "contentPackages/str.azure-sentinel-solution-str"
                        ),
                        "name": "str.azure-sentinel-solution-str",
                        "type": "Microsoft.SecurityInsights/contentpackages",
                        "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
                        "properties": {
                            "contentId": "str.azure-sentinel-solution-str",
                            "contentProductId": "str.azure-sentinel-solution-str-sl-igl6jawr4gwmu",
                            "contentKind": "Solution",
                            "contentSchemaVersion": "3.0.0",
                            "version": "2.0.0",
                            "displayName": "str",
                        },
                        "systemData": {
                            "createdBy": "string",
                            "createdByType": "User",
                            "createdAt": "2020-04-27T21:53:29.0928001Z",
                            "lastModifiedBy": "string",
                            "lastModifiedByType": "User",
                            "lastModifiedAt": "2020-04-27T21:53:29.0928001Z",
                        },
                    }
                ]
            },
            200,
        )

    if "/Microsoft.SecurityInsights/watchlists?api-version=2025-09-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "id": (
                            "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
                            "resourceGroups/myRg/providers/Microsoft.OperationalIinsights/"
                            "workspaces/myWorkspace/providers/"
                            "Microsoft.SecurityInsights/watchlists/highValueAsset"
                        ),
                        "name": "highValueAsset",
                        "type": "Microsoft.SecurityInsights/Watchlists",
                        "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
                        "properties": {
                            "watchlistId": "76d5a51f-ba1f-4038-9d22-59fda38dc017",
                            "displayName": "High Value Assets Watchlist",
                            "provider": "Microsoft",
                            "source": "watchlist.csv",
                            "sourceType": "Local",
                            "created": "2020-09-28T00:26:54.7746089+00:00",
                            "updated": "2020-09-28T00:26:57+00:00",
                            "createdBy": {
                                "objectId": "2046feea-040d-4a46-9e2b-91c2941bfa70",
                                "email": "john@contoso.com",
                                "name": "john doe",
                            },
                            "updatedBy": {
                                "objectId": "2046feea-040d-4a46-9e2b-91c2941bfa70",
                                "email": "john@contoso.com",
                                "name": "john doe",
                            },
                            "description": "Watchlist from CSV content",
                            "watchlistType": "watchlist",
                            "watchlistAlias": "highValueAsset",
                            "itemsSearchKey": "header1",
                            "isDeleted": False,
                            "labels": ["Tag1", "Tag2"],
                            "defaultDuration": "P1279DT12H30M5S",
                            "tenantId": "f686d426-8d16-42db-81b7-ab578e110ccd",
                        },
                    }
                ]
            },
            200,
        )

    if "/Microsoft.SecurityInsights/sourcecontrols?api-version=2025-09-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "id": "/subscriptions/b28fbe4a-0bb1-4593-960b-061c8655a550/resourceGroups/myRg/providers/Microsoft.OperationalIinsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/sourcecontrols/789e0c1f-4a3d-43ad-809c-e713b677b04a",
                        "version": "V2",
                        "name": "789e0c1f-4a3d-43ad-809c-e713b677b04a",
                        "type": "Microsoft.SecurityInsights/SourceControls",
                        "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
                        "properties": {
                            "id": "789e0c1f-4a3d-43ad-809c-e713b677b04a",
                            "displayName": "My Source Control",
                            "description": "this is a source control",
                            "repoType": "Github",
                            "contentTypes": ["AnalyticsRule", "Workbook"],
                            "repository": {
                                "url": "https://github.com/user/repo",
                                "branch": "master",
                                "displayUrl": "https://github.com/user/repo",
                                "deploymentLogsUrl": "https://github.com/user/repo/actions",
                            },
                            "servicePrincipal": {
                                "id": "6a5f9fbd-6ce5-45a5-a729-79f8943472f3",
                                "tenantId": "336ffe99-ff10-48fa-8c21-6da2a653dcce",
                                "appId": "307ef030-13ed-4342-8cc2-c11760649f4d",
                            },
                            "workloadIdentityFederation": {
                                "id": "c2c12197-fc2c-4880-9b18-0996ffe7aeca",
                                "tenantId": "336ffe99-ff10-48fa-8c21-6da2a653dcce",
                                "appId": "307ef030-13ed-4342-8cc2-c11760649f4d",
                                "subject": "repo:user/repo:ref:refs/heads/branch",
                                "issuer": "https://token.actions.githubusercontent.com",
                            },
                            "repositoryResourceInfo": {
                                "webhook": {
                                    "webhookId": "342768323",
                                    "webhookUrl": "https://cac.sentinel.azure.com/workspaces/eeca17ff-d744-4a8b-9f5e-1edcc3346a1d/webhooks/ado/sourceControl/789e0c1f-4a3d-43ad-809c-e713b677b04a",
                                    "webhookSecretUpdateTime": "2021-01-01T17:18:19.1234567Z",
                                },
                                "gitHubResourceInfo": {"appInstallationId": "123"},
                                "azureDevOpsResourceInfo": None,
                            },
                            "lastDeploymentInfo": {
                                "deploymentFetchStatus": "Success",
                                "deployment": {
                                    "deploymentId": "4985046420",
                                    "deploymentState": "Completed",
                                    "deploymentResult": "Success",
                                    "deploymentTime": "2021-01-01T17:18:19.1234567Z",
                                    "deploymentLogsUrl": "https://github.com/user/repo/actions",
                                },
                                "message": "Successful deployment",
                            },
                            "pullRequest": {
                                "url": "https://github.com/user/repo/pull/123",
                                "state": "Open",
                            },
                        },
                        "systemData": {
                            "createdBy": "user1",
                            "createdByType": "User",
                            "createdAt": "2021-01-01T17:18:19.1234567Z",
                            "lastModifiedBy": "user2",
                            "lastModifiedByType": "User",
                            "lastModifiedAt": "2021-01-02T17:18:19.1234567Z",
                        },
                    }
                ]
            },
            200,
        )

    if (
        "/Microsoft.SecurityInsights/contentProductPackages?api-version=2025-09-01"
        in url
    ):
        return MockResponse(
            {
                "value": [
                    {
                        "id": "/subscriptions/d0cfeab2-9ae0-4464-9919-dccaee2e48f0/resourceGroups/myRg/providers/Microsoft.OperationalIinsights/workspaces/myWorkspace/providers/Microsoft.SecurityInsights/contentProductPackages/str.azure-sentinel-solution-str",
                        "name": "str.azure-sentinel-solution-str",
                        "type": "Microsoft.SecurityInsights/contentproductpackages",
                        "etag": '"0300bf09-0000-0000-0000-5c37296e0000"',
                        "properties": {
                            "contentId": "str.azure-sentinel-solution-str",
                            "contentProductId": "str.azure-sentinel-solution-str-sl-igl6jawr4gwmu",
                            "contentKind": "Solution",
                            "installedVersion": "2.0.0",
                            "version": "2.0.0",
                            "displayName": "str",
                            "source": {
                                "kind": "Solution",
                                "name": "str",
                                "sourceId": "str.azure-sentinel-solution-str",
                            },
                            "author": {
                                "name": "Microsoft",
                                "email": "support@microsoft.com",
                            },
                            "support": {
                                "tier": "Microsoft",
                                "name": "Microsoft Corporation",
                                "email": "support@microsoft.com",
                                "link": "https://support.microsoft.com/",
                            },
                            "dependencies": {
                                "criteria": [
                                    {
                                        "contentId": "strDataConnector",
                                        "kind": "DataConnector",
                                        "version": "2.0.0",
                                    },
                                    {
                                        "contentId": "str-Parser",
                                        "kind": "Parser",
                                        "version": "2.0.0",
                                    },
                                ],
                                "operator": "AND",
                            },
                            "providers": ["Microsoft"],
                            "categories": {
                                "domains": ["Security - Cloud Security"],
                                "verticals": None,
                            },
                            "firstPublishDate": "2022-04-01",
                        },
                        "systemData": {
                            "createdBy": "string",
                            "createdByType": "User",
                            "createdAt": "2020-04-27T21:53:29.0928001Z",
                            "lastModifiedBy": "string",
                            "lastModifiedByType": "User",
                            "lastModifiedAt": "2020-04-27T21:53:29.0928001Z",
                        },
                    }
                ]
            },
            200,
        )

    if "/tables?api-version=2026-03-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "name": "AzureNetworkFlow",
                        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/oiautorest6685/providers/Microsoft.OperationalInsights/workspaces/oiautorest6685/tables/AzureNetworkFlow",
                        "properties": {
                            "schema": {
                                "name": "AzureNetworkFlow",
                                "description": None,
                                "categories": None,
                                "columns": None,
                                "displayName": None,
                                "labels": None,
                                "solutions": ["LogManagement"],
                                "source": None,
                                "standardColumns": [
                                    {
                                        "name": "TenantId",
                                        "type": "guid",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": True,
                                    },
                                    {
                                        "name": "SourceSystem",
                                        "type": "string",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "TimeGenerated",
                                        "type": "dateTime",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "AgentID",
                                        "type": "string",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "SourceIP",
                                        "type": "string",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "Protocol",
                                        "type": "string",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "SourcePort",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "DestinationPort",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "TcpFlags",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "Packets",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "Bytes",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "BytesOut",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "DurationInMs",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "RstCount",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "MaxSampleRtt",
                                        "type": "int",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                ],
                                "tableSubType": "Any",
                                "tableType": "Microsoft",
                            },
                            "archiveRetentionInDays": 25,
                            "plan": "Analytics",
                            "provisioningState": "Succeeded",
                            "retentionInDays": 45,
                            "retentionInDaysAsDefault": False,
                            "totalRetentionInDays": 70,
                            "totalRetentionInDaysAsDefault": False,
                        },
                    },
                    {
                        "name": "SurfaceHubDns",
                        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/oiautorest6685/providers/Microsoft.OperationalInsights/workspaces/oiautorest6685/tables/SurfaceHubDns",
                        "properties": {
                            "schema": {
                                "name": "SurfaceHubDns",
                                "description": None,
                                "categories": None,
                                "columns": None,
                                "displayName": None,
                                "labels": None,
                                "solutions": ["LogManagement"],
                                "source": None,
                                "standardColumns": [
                                    {
                                        "name": "TenantId",
                                        "type": "guid",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": True,
                                    },
                                    {
                                        "name": "SourceSystem",
                                        "type": "string",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "TimeGenerated",
                                        "type": "dateTime",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "QueryName",
                                        "type": "string",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                    {
                                        "name": "ComputerName",
                                        "type": "string",
                                        "description": None,
                                        "dataTypeHint": None,
                                        "displayName": None,
                                        "isDefaultDisplay": False,
                                        "isHidden": False,
                                    },
                                ],
                                "tableSubType": "Any",
                                "tableType": "Microsoft",
                            },
                            "archiveRetentionInDays": 0,
                            "plan": "Analytics",
                            "provisioningState": "Succeeded",
                            "retentionInDays": 30,
                            "retentionInDaysAsDefault": False,
                            "totalRetentionInDays": 30,
                            "totalRetentionInDaysAsDefault": True,
                        },
                    },
                ]
            },
            200,
        )

    if "/savedSearches?api-version=2026-03-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "etag": "W/\"datetime'2017-10-02T23%3A15%3A41.0709875Z'\"",
                        "id": (
                            "/subscriptions/00000000-0000-0000-0000-000000000005/"
                            "resourceGroups/mms-eus/providers/Microsoft.OperationalInsights/"
                            "workspaces/AtlantisDemo/savedSearches/test-new-saved-search-id-2015"
                        ),
                        "properties": {
                            "category": " Saved Search Test Category",
                            "displayName": "Create or Update Saved Search Test",
                            "query": "* | measure Count() by Computer",
                            "tags": [{"name": "Group", "value": "Computer"}],
                            "version": 1,
                        },
                    }
                ]
            },
            200,
        )

    if "/dataSources?api-version=2026-03-01" in url:
        return MockResponse(
            {
                "nextLink": (
                    "https://management.azure.com/subscriptions/"
                    "00000000-0000-0000-0000-000000000005/"
                    "resourcegroups/OIAutoRest7887/providers/"
                    "Microsoft.OperationalInsights/workspaces/"
                    "AzTest218/dataSources?$filter=kind+eq+'WindowsEvent'&"
                    "api-version=2026-03-01&$skiptoken=AzTestDSWE7191"
                ),
                "value": [
                    {
                        "name": "AzTestDSWE1011",
                        "type": "Microsoft.OperationalInsights/workspaces/datasources",
                        "etag": "W/\"datetime'2017-10-02T23%3A20%3A08.5629323Z'\"",
                        "id": (
                            "/subscriptions/00000000-0000-0000-0000-000000000005/resourceGroups/"
                            "OIAutoRest7887/providers/Microsoft.OperationalInsights/workspaces/"
                            "AzTest218/datasources/AzTestDSWE1011"
                        ),
                        "kind": "WindowsEvent",
                        "properties": {
                            "eventLogName": "windowsEvent14",
                            "eventTypes": [{"eventType": "Error"}],
                        },
                    },
                    {
                        "name": "AzTestDSWE1013",
                        "type": "Microsoft.OperationalInsights/workspaces/datasources",
                        "etag": "W/\"datetime'2017-10-02T23%3A20%3A22.2533211Z'\"",
                        "id": (
                            "/subscriptions/00000000-0000-0000-0000-000000000005/resourceGroups/"
                            "OIAutoRest7887/providers/Microsoft.OperationalInsights/workspaces/"
                            "AzTest218/datasources/AzTestDSWE1013"
                        ),
                        "kind": "WindowsEvent",
                        "properties": {
                            "eventLogName": "windowsEvent64",
                            "eventTypes": [{"eventType": "Error"}],
                        },
                    },
                    {
                        "name": "AzTestDSWE1020",
                        "type": "Microsoft.OperationalInsights/workspaces/datasources",
                        "etag": "W/\"datetime'2017-10-02T23%3A21%3A04.4645698Z'\"",
                        "id": (
                            "/subscriptions/00000000-0000-0000-0000-000000000005/resourceGroups/"
                            "OIAutoRest7887/providers/Microsoft.OperationalInsights/workspaces/"
                            "AzTest218/datasources/AzTestDSWE1020"
                        ),
                        "kind": "WindowsEvent",
                        "properties": {
                            "eventLogName": "windowsEvent202",
                            "eventTypes": [{"eventType": "Error"}],
                        },
                    },
                    {
                        "name": "AzTestDSWE1074",
                        "type": "Microsoft.OperationalInsights/workspaces/datasources",
                        "etag": "W/\"datetime'2017-10-02T23%3A21%3A12.5871672Z'\"",
                        "id": (
                            "/subscriptions/00000000-0000-0000-0000-000000000005/resourceGroups/"
                            "OIAutoRest7887/providers/Microsoft.OperationalInsights/workspaces/"
                            "AzTest218/datasources/AzTestDSWE1074"
                        ),
                        "kind": "WindowsEvent",
                        "properties": {
                            "eventLogName": "windowsEvent231",
                            "eventTypes": [{"eventType": "Error"}],
                        },
                    },
                ],
            },
            200,
        )

    if "/usages?api-version=2026-03-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "name": {
                            "localizedValue": "Data Analyzed",
                            "value": "DataAnalyzed",
                        },
                        "currentValue": 0,
                        "limit": 524288000,
                        "nextResetTime": "2017-10-03T00:00:00Z",
                        "quotaPeriod": "P1D",
                        "unit": "Bytes",
                    }
                ]
            },
            200,
        )

    if (
        "/subscriptions/MOCK_INPUT/providers/Microsoft.Logic/workflows?api-version=2019-05-01"
        in url
    ):
        return MockResponse(
            {
                "value": [
                    {
                        "properties": {
                            "provisioningState": "Succeeded",
                            "createdTime": "2018-04-25T01:39:21.4365247Z",
                            "changedTime": "2018-08-09T22:54:54.3533634Z",
                            "state": "Enabled",
                            "version": "08586677515911718341",
                            "accessEndpoint": "http://tempuri.org",
                            "integrationAccount": {
                                "name": "test-integration-account",
                                "id": "/subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/integrationAccounts/test-integration-account",
                                "type": "Microsoft.Logic/integrationAccounts",
                            },
                            "definition": {
                                "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                                "contentVersion": "1.0.0.0",
                                "parameters": {},
                                "triggers": {},
                                "actions": {},
                                "outputs": {},
                            },
                            "parameters": {},
                            "accessControl": {},
                            "endpointsConfiguration": {
                                "workflow": {
                                    "outgoingIpAddresses": [
                                        {"address": "13.84.159.168"},
                                        {"address": "13.65.86.56"},
                                        {"address": "13.65.82.190"},
                                    ],
                                    "accessEndpointIpAddresses": [
                                        {"address": "104.210.153.89"},
                                        {"address": "13.85.79.155"},
                                        {"address": "13.65.39.247"},
                                    ],
                                },
                                "connector": {
                                    "outgoingIpAddresses": [{"address": "40.84.145.61"}]
                                },
                            },
                        },
                        "id": "/subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/workflows/test-workflow",
                        "name": "test-workflow",
                        "type": "Microsoft.Logic/workflows",
                        "location": "brazilsouth",
                        "tags": {},
                    }
                ]
            },
            200,
        )

    if (
        "/resourceGroups/MOCK_INPUT/providers/Microsoft.Logic/workflows?api-version=2019-05-01"
        in url
    ):
        return MockResponse(
            {
                "value": [
                    {
                        "properties": {
                            "provisioningState": "Succeeded",
                            "createdTime": "2018-04-25T01:39:21.4365247Z",
                            "changedTime": "2018-08-09T22:54:54.3533634Z",
                            "state": "Enabled",
                            "version": "08586677515911718341",
                            "accessEndpoint": "http://tempuri.org",
                            "integrationAccount": {
                                "name": "test-integration-account",
                                "id": "/subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/integrationAccounts/test-integration-account",
                                "type": "Microsoft.Logic/integrationAccounts",
                            },
                            "definition": {
                                "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
                                "contentVersion": "1.0.0.0",
                                "parameters": {},
                                "triggers": {},
                                "actions": {},
                                "outputs": {},
                            },
                            "parameters": {},
                            "accessControl": {},
                            "endpointsConfiguration": {
                                "workflow": {
                                    "outgoingIpAddresses": [
                                        {"address": "13.84.159.168"},
                                        {"address": "13.65.86.56"},
                                        {"address": "13.65.82.190"},
                                    ],
                                    "accessEndpointIpAddresses": [
                                        {"address": "104.210.153.89"},
                                        {"address": "13.85.79.155"},
                                        {"address": "13.65.39.247"},
                                    ],
                                },
                                "connector": {
                                    "outgoingIpAddresses": [{"address": "40.84.145.61"}]
                                },
                            },
                        },
                        "id": "/subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/workflows/test-workflow",
                        "name": "test-workflow",
                        "type": "Microsoft.Logic/workflows",
                        "location": "brazilsouth",
                        "tags": {},
                    }
                ]
            },
            200,
        )

    return MockResponse({"id": 1, "name": "John Doe"}, 200)


def mock_post(*args, **kwargs):
    """MockResponse function for httpx.post calls"""
    url = args[0]

    class MockResponse:
        """MockResponse class for httpx.post calls"""

        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    if "/oauth2/token" in url:
        return MockResponse(
            {
                "access_token": "MOCK_TOKEN",
            },
            200,
        )


def test_connection_settings():
    """Ensure have connection settings from environment"""
    assert tenant_id
    assert client_id
    assert client_secret
    assert resource_uri
    assert oauth_uri


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_getalerts(mock_get, mock_post):
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

    search1 = jmespath.search(
        "value[?name=='microsoftSecurityIncidentCreationRuleExample']",
        results,
    )
    assert search1
    assert search1[0]["properties"]["displayName"] == "testing displayname"


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_getalerts_json(mock_get, mock_post, tmp_path):
    """Ensure can export alerts as csv"""
    conn = SentinelMDE()

    conn.export_objects(
        sub,
        rg,
        ws,
        "alerts",
        f"{tmp_path}/",
        outformat="json",
        split=True,
        flat=False,
    )

    assert os.path.exists(f"{tmp_path}/alerts")
    listfiles = glob.glob(f"{tmp_path}/alerts/*.json")
    assert listfiles
    assert len(listfiles) == 3

    a1 = f"{tmp_path}/alerts/myFirstFusionRule.json"
    with open(a1, "r", encoding="utf-8") as file:
        alert1 = json.load(file)
    assert alert1
    assert alert1["etag"] == '"25005c11-0000-0d00-0000-5d6cc0e20000"'
    assert (
        alert1["properties"]["alertRuleTemplateName"]
        == "f71aba3d-28fb-450b-b192-4e76a83015c8"
    )
    a2 = f"{tmp_path}/alerts/microsoftSecurityIncidentCreationRuleExample.json"
    with open(a2, "r", encoding="utf-8") as file:
        alert2 = json.load(file)
    assert alert2
    assert alert2["properties"]["lastModifiedUtc"] == "2019-09-04T12:05:35.7296311Z"
    a3 = f"{tmp_path}/alerts/73e01a995cd74139a1499f2736ff2ab5.json"
    with open(a3, "r", encoding="utf-8") as file:
        alert3 = json.load(file)
    assert alert3
    assert alert3["properties"]["lastModifiedUtc"] == "2021-03-01T13:17:30Z"


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_getalerts_csv(mock_get, mock_post, tmp_path):
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
        assert "/alertRules/myFirstFusionRule," in content
        assert "/alertRules/microsoftSecurityIncidentCreationRuleExample," in content
    assert len(list(tmp_path.iterdir())) == 1


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_automationrules(mock_get, mock_post):
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

    search1 = jmespath.search(
        "value[?name=='73e01a99-5cd7-4139-a149-9f2736ff2ab5']",
        results,
    )
    assert search1
    assert search1[0]["properties"]["displayName"] == "Suspicious user sign-in events"


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_bookmarks(mock_get, mock_post):
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

    search1 = jmespath.search(
        "value[?name=='73e01a99-5cd7-4139-a149-9f2736ff2ab5']",
        results,
    )
    assert search1
    assert search1[0]["properties"]["displayName"] == "My bookmark"


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_contentpackages(mock_get, mock_post):
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

    search1 = jmespath.search(
        "value[?name=='str.azure-sentinel-solution-str']",
        results,
    )
    assert search1
    assert (
        search1[0]["properties"]["contentProductId"]
        == "str.azure-sentinel-solution-str-sl-igl6jawr4gwmu"
    )


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_watchlists(mock_get, mock_post):
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

    search1 = jmespath.search(
        "value[?name=='highValueAsset']",
        results,
    )
    assert search1
    assert search1[0]["properties"]["description"] == "Watchlist from CSV content"


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_sourcecontrols(mock_get, mock_post):
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

    search1 = jmespath.search(
        "value[?name=='789e0c1f-4a3d-43ad-809c-e713b677b04a']",
        results,
    )
    assert search1
    assert search1[0]["properties"]["description"] == "this is a source control"


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_productpackages(mock_get, mock_post):
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

    search1 = jmespath.search(
        "value[?name=='str.azure-sentinel-solution-str']",
        results,
    )
    assert search1
    assert search1[0]["properties"]["firstPublishDate"] == "2022-04-01"


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_loganalytics_datasources(mock_get, mock_post):
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
    assert len(results["value"]) == 4

    search1 = jmespath.search(
        "value[?name=='AzTestDSWE1011']",
        results,
    )
    assert search1
    assert "/workspaces/AzTest218/datasources/AzTestDSWE1011" in search1[0]["id"]


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_loganalytics_tables(mock_get, mock_post):
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
    assert len(results["value"]) == 2

    search1 = jmespath.search(
        "value[?name=='AzureNetworkFlow']",
        results,
    )
    assert search1
    assert "/workspaces/oiautorest6685/tables/AzureNetworkFlow" in search1[0]["id"]


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_loganalytics_savedsearches(mock_get, mock_post):
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
    assert len(results["value"]) == 1


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_loganalytics_usage(mock_get, mock_post):
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
    assert len(results["value"]) == 1


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_workflows_bysub(mock_get, mock_post):
    """Ensure can export workflows"""
    conn = SentinelMDE()

    results = conn.get_workflows_bysub(sub)
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
    assert len(results["value"]) == 1


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_workflows_byrg(mock_get, mock_post):
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
    assert len(results["value"]) == 1


def test_get_rg_from_id():
    """Ensure get_rg_from_id() works"""
    resourceid = (
        "/subscriptions/d0cfe6b2-9ac0-4464-9919-dccaee2e48c0/"
        "resourceGroups/myRg/providers/Microsoft.OperationalInsights/"
        "workspaces/myWorkspace/providers/Microsoft.SecurityInsights/"
        "alertRules/73e01a99-5cd7-4139-a149-9f2736ff2ab5"
    )
    result = get_rg_from_id(resourceid)

    assert result == "myRg"
