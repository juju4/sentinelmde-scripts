"""
Pytest file for sentinelmde healthcheck - offline

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-FileCopyrightText: 2025 The python_openobserve authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=unused-argument,redefined-outer-name,missing-function-docstring,too-few-public-methods,no-else-return,duplicate-code,too-many-lines,line-too-long
from pprint import pprint
from unittest.mock import patch

# import pytest  # type: ignore

from sentinelmde import SentinelMDE

# pylint: disable=C0103
tenant_id = client_id = client_secret = "MOCK_INPUT"  # nosec B105
resource_uri = oauth_uri = "https://mockurl.example.internal"
sub = rg = ws = "MOCK_INPUT"


# pylint: disable=R0911
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

    if "/Microsoft.ResourceHealth/availabilityStatuses?api-version=2025-05-01" in url:
        return MockResponse(
            {
                "nextLink": "https://management.azure.com/subscriptions/subscriptionId/providers/Microsoft.ResourceHealth/availabilityStatuses?api-version=2025-05-01&$skipToken=OpaquePageNumber",
                "value": [
                    {
                        "name": "current",
                        "type": "Microsoft.ResourceHealth/AvailabilityStatuses",
                        "id": "/subscriptions/227b734f-e14f-4de6-b7fc-3190c21e69f6/resourceGroups/resourceGroupName/providers/Microsoft.Compute/virtualMachines/virtualMachineName/providers/Microsoft.ResourceHealth/availabilityStatuses/current",
                        "location": "eastus",
                        "properties": {
                            "availabilityState": "Available",
                            "category": "Unplanned",
                            "context": "Platform Initiated",
                            "detailedStatus": "We have not seen any issues with your virtual machine",
                            "occuredTime": "2016-03-29T09:12:00Z",
                            "reasonChronicity": "Persistent",
                            "reasonType": "Unplanned",
                            "recentlyResolved": {
                                "resolvedTime": "2017-02-28T00:49:00Z",
                                "unavailableOccuredTime": "2017-02-28T00:48:00Z",
                                "unavailableSummary": "We are sorry your SQL database is unavailable",
                            },
                            "recommendedActions": [
                                {
                                    "action": "To start this virtualmachine, open the resource blade and click Start",
                                    "actionUrl": "<#ResourceBlade>",
                                    "actionUrlText": "resourceblade",
                                }
                            ],
                            "reportedTime": "2016-05-04T14:11:29.7598931Z",
                            "summary": "Vm is available",
                            "title": "Available",
                        },
                    },
                    {
                        "name": "current",
                        "type": "Microsoft.ResourceHealth/AvailabilityStatuses",
                        "id": "/subscriptions/227b734f-e14f-4de6-b7fc-3190c21e69f6/resourceGroups/resourceGroupName/providers/Microsoft.Compute/virtualMachines/virtualMachineName/providers/Microsoft.ResourceHealth/availabilityStatuses/current",
                        "location": "eastus",
                        "properties": {
                            "availabilityState": "Unavailable",
                            "detailedStatus": "Diskproblemsarepreventingusfromautomaticallyrecoveringyourvirtualmachine",
                            "occuredTime": "2016-03-29T09:12:00Z",
                            "reasonChronicity": "Persistent",
                            "reasonType": "Unplanned",
                            "recommendedActions": [
                                {
                                    "action": "To start this virtualmachine, open the resource blade",
                                    "actionUrl": "<#ResourceBlade>",
                                    "actionUrlText": "resourceblade",
                                },
                                {
                                    "action": "If you are experiencing problems you believe are caused by Azure, contact support",
                                    "actionUrl": "<#SupportCase>",
                                    "actionUrlText": "contactsupport",
                                },
                            ],
                            "reportedTime": "2016-05-04T14:11:29.7598931Z",
                            "resolutionETA": "2016-03-29T09:37:00Z",
                            "rootCauseAttributionTime": "2016-03-29T09:13:00Z",
                            "summary": "We are sorry, we couldn't automatically recovery our virtualmachine",
                            "title": "Unavailable",
                        },
                    },
                ],
            },
            200,
        )

    if "/Microsoft.ResourceHealth/events?api-version=2025-05-01" in url:
        return MockResponse(
            {
                "nextLink": "https://management.azure.com/subscriptions/subscriptionId/providers/Microsoft.ResourceHealth/events?api-version=2025-05-01&$skipToken=OpaquePageNumber",
                "value": [
                    {
                        "name": "BC_1-FXZ",
                        "type": "/providers/Microsoft.ResourceHealth/events",
                        "id": "/providers/Microsoft.ResourceHealth/events/BC_1-FXZ",
                        "properties": {
                            "article": {
                                "articleContent": "<html>An outage alert is being investigated. More information will be provided as it is known</html>"
                            },
                            "enableChatWithUs": False,
                            "enableMicrosoftSupport": True,
                            "eventLevel": "Warning",
                            "eventSource": "ResourceHealth",
                            "eventTags": [
                                "Action Recommended",
                                "False Positive",
                                "Preliminary PIR",
                                "Final PIR",
                            ],
                            "eventType": "ServiceIssue",
                            "faqs": [
                                {
                                    "answer": "This is an answer",
                                    "localeCode": "en",
                                    "question": "This is a question",
                                }
                            ],
                            "header": "Your service might have been impacted by an Azure service issue",
                            "hirStage": "resolved",
                            "impact": [
                                {
                                    "impactedRegions": [
                                        {
                                            "impactedRegion": "West US",
                                            "impactedSubscriptions": [
                                                "{subscriptionId}"
                                            ],
                                            "impactedTenants": [],
                                            "lastUpdateTime": "2025-05-13T15:43:48.1203530Z",
                                            "status": "Active",
                                            "updates": [
                                                {
                                                    "eventTags": ["Final PIR"],
                                                    "summary": "Update 3 - An outage alert is being investigated. More information will be provided as it is known.",
                                                    "updateDateTime": "2025-05-13T15:43:48.1203530Z",
                                                },
                                                {
                                                    "eventTags": [
                                                        "False Positive",
                                                        "Preliminary PIR",
                                                    ],
                                                    "summary": "Update 2 - An outage alert is being investigated. More information will be provided as it is known.",
                                                    "updateDateTime": "2025-05-13T10:32:48.1203530Z",
                                                },
                                                {
                                                    "eventTags": ["Action Recommended"],
                                                    "summary": "Update 1 - An outage alert is being investigated. More information will be provided as it is known.",
                                                    "updateDateTime": "2025-05-12T15:00:48.1203530Z",
                                                },
                                            ],
                                        }
                                    ],
                                    "impactedService": "Virtual Machines",
                                    "impactedServiceGuid": "fd8065f5-ffd0-4756-8788-e6a11bf36257",
                                }
                            ],
                            "impactMitigationTime": "2025-05-14T15:43:48.1203530Z",
                            "impactStartTime": "2025-05-12T14:45:48.1203530Z",
                            "isEventSensitive": False,
                            "isHIR": False,
                            "lastUpdateTime": "2025-05-13T15:43:48.1203530Z",
                            "level": "Warning",
                            "links": [
                                {
                                    "type": "Hyperlink",
                                    "bladeName": "RequestRCABlade",
                                    "displayText": {
                                        "localizedValue": "Request RCA",
                                        "value": "Request RCA",
                                    },
                                    "extensionName": "Microsoft_Azure_Health",
                                    "parameters": {
                                        "rcaRequested": "False",
                                        "trackingId": "BC_1-FXZ",
                                    },
                                },
                                {
                                    "type": "Button",
                                    "bladeName": "AzureHealthBrowseBlade",
                                    "displayText": {
                                        "localizedValue": "Sign up for updates",
                                        "value": "Sign up for updates",
                                    },
                                    "extensionName": "Microsoft_Azure_Health",
                                    "parameters": {"trackingId": "BC_1-FXZ"},
                                },
                            ],
                            "priority": 2,
                            "recommendedActions": {
                                "actions": [
                                    {"actionText": "action 1", "groupId": 23243},
                                    {"actionText": "action 2", "groupId": 23432},
                                ],
                                "localeCode": "en",
                                "message": "Recommended actions title",
                            },
                            "status": "Active",
                            "summary": "An outage alert is being investigated. More information will be provided as it is known.",
                            "title": "ACTIVE: Virtual machines in West US",
                        },
                    }
                ],
            },
            200,
        )

    if "/impactedResources/MOCK_RESOURCE?api-version=2025-05-01" in url:
        return MockResponse(
            {
                "name": "abc-123-ghj-456",
                "type": "Microsoft.ResourceHealth/events/impactedResources",
                "id": "/subscriptions/{subscripitionId}/providers/Microsoft.ResourceHealth/events/BC_1-FXZ/impactedResources/abc-123-ghj-456",
                "properties": {
                    "targetRegion": "westus",
                    "targetResourceId": "/subscriptions/4970d23e-ed41-4670-9c19-02a1d2808dd9/resourceGroups/TEST/providers/Microsoft.Compute/virtualMachines/testvm",
                    "targetResourceType": "Microsoft.Compute/VirtualMachines",
                },
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

    if "/Microsoft.Logic/workflows/test-workflow/runs?api-version=2019-05-01" in url:
        return MockResponse(
            {
                "value": [
                    {
                        "properties": {
                            "waitEndTime": "2018-08-10T20:16:32.044238Z",
                            "startTime": "2018-08-10T20:16:32.044238Z",
                            "endTime": "2018-08-10T20:16:32.5779999Z",
                            "status": "Succeeded",
                            "correlation": {
                                "clientTrackingId": "08586676746934337772206998657CU22"
                            },
                            "workflow": {
                                "id": "/subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/workflows/test-workflow/versions/08586676754160363885",
                                "name": "08586676754160363885",
                                "type": "Microsoft.Logic/workflows/versions",
                            },
                            "trigger": {
                                "name": "Recurrence",
                                "startTime": "2018-08-10T20:16:32.0387927Z",
                                "endTime": "2018-08-10T20:16:32.0387927Z",
                                "scheduledTime": "2018-08-10T20:16:31.6344174Z",
                                "correlation": {
                                    "clientTrackingId": "08586676746934337772206998657CU22"
                                },
                                "code": "OK",
                                "status": "Succeeded",
                            },
                            "outputs": {},
                        },
                        "id": "/subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/workflows/test-workflow/runs/08586676746934337772206998657CU22",
                        "name": "08586676746934337772206998657CU22",
                        "type": "Microsoft.Logic/workflows/runs",
                    },
                    {
                        "properties": {
                            "waitEndTime": "2018-08-10T20:16:32.044238Z",
                            "startTime": "2018-08-10T20:16:32.044238Z",
                            "endTime": "2018-08-10T20:16:32.5779999Z",
                            "status": "FailedTest",
                            "correlation": {
                                "clientTrackingId": "08586676746934337772206998657CU22"
                            },
                            "workflow": {
                                "id": "/subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/workflows/test-workflow/versions/08586676754160363885",
                                "name": "08586676754160363885",
                                "type": "Microsoft.Logic/workflows/versions",
                            },
                            "trigger": {
                                "name": "Recurrence",
                                "startTime": "2018-08-10T20:16:32.0387927Z",
                                "endTime": "2018-08-10T20:16:32.0387927Z",
                                "scheduledTime": "2018-08-10T20:16:31.6344174Z",
                                "correlation": {
                                    "clientTrackingId": "08586676746934337772206998657CU22"
                                },
                                "code": "OK",
                                "status": "Succeeded",
                            },
                            "outputs": {},
                        },
                        "id": "/subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/workflows/test-workflow/runs/08586676746934337772206998657CU22",
                        "name": "08586676746934337772206998657CU22",
                        "type": "Microsoft.Logic/workflows/runs",
                    },
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
def test_get_availabilitystatuses(mock_get, mock_post):
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


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_healthevents(mock_get, mock_post):
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


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_get_impactedresource(mock_get, mock_post):
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


@patch("httpx.get", side_effect=mock_get)
@patch("httpx.post", side_effect=mock_post)
def test_healthcheck(mock_get, mock_post):
    """Ensure can get impactedresource"""
    conn = SentinelMDE()

    results = conn.healthcheck(
        sub,
    )

    pprint(results)
    assert results == """## Healthcheck report for subscription MOCK_INPUT

Availability status count: 2
Affected resources
* title Available detailedStatus We have not seen any issues with your virtual machine
* title Unavailable detailedStatus Diskproblemsarepreventingusfromautomaticallyrecoveringyourvirtualmachine

Health events count: 1
Events quick view
* name BC_1-FXZ status Active title ACTIVE: Virtual machines in West US eventType ServiceIssue impactedService Virtual Machines

Failed LogicApp workflows run
* 2018-08-10T20:16:32.044238Z FailedTest 08586676746934337772206998657CU22 /subscriptions/34adfa4f-cedf-4dc0-ba29-b6d1a69ab345/resourceGroups/test-resource-group/providers/Microsoft.Logic/workflows/test-workflow/versions/08586676754160363885
"""
