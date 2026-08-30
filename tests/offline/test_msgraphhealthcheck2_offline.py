"""
msgraphhealthcheck tests - offline

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=R0801
# import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import msgraphhealthcheck

# Response taken from the Microsoft Graph documentation:
# https://learn.microsoft.com/en-us/graph/api/security-identitycontainer-list-healthissues
MICROSOFT_GRAPH_HEALTH_ISSUES_RESPONSE = {
    "value": [
        {
            "@odata.type": "#microsoft.graph.security.healthIssue",
            "additionalInformation": [
                "Descendant User Objects "
                "(Schema-Id-Guid: bf967aba-0de6-11d0-a285-00aa003049e2)"
            ],
            "createdDateTime": "2022-07-15T12:19:27.7211305Z",
            "description": (
                "Directory Services Object Auditing isn't configured "
                "as required on domain1.contoso.com"
            ),
            "displayName": (
                "Directory Services Object Auditing isn't configured as required"
            ),
            "domainNames": [
                "domain1.contoso.com",
                "domain2.contoso.com",
            ],
            "healthIssueType": "Global",
            "id": "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c",
            "issueTypeId": "1031",
            "lastModifiedDateTime": "2022-07-15T12:19:27.7211305Z",
            "recommendations": [
                (
                    "Please configure the Directory Services Object "
                    "Auditing events according to the guidance as "
                    "described in https://aka.ms/mdi/objectauditing"
                )
            ],
            "recommendedActionCommands": ["Import-Module DefenderForIdentity"],
            "sensorDNSNames": [
                "DC1.domain1.contoso.com",
                "DC2.domain2.contoso.com",
            ],
            "severity": "medium",
            "status": "open",
        }
    ]
}


def create_health_issue_response():
    """
    Convert the documented JSON example into the minimal SDK-like
    response object required by get_all_health_issues().
    """
    health_issue_data = MICROSOFT_GRAPH_HEALTH_ISSUES_RESPONSE["value"][0]

    health_issue = SimpleNamespace(
        id=health_issue_data["id"],
        display_name=health_issue_data["displayName"],
        severity=health_issue_data["severity"],
        status=health_issue_data["status"],
        description=health_issue_data["description"],
        domain_names=health_issue_data["domainNames"],
        health_issue_type=health_issue_data["healthIssueType"],
        issue_type_id=health_issue_data["issueTypeId"],
        sensor_dns_names=health_issue_data["sensorDNSNames"],
        recommendations=health_issue_data["recommendations"],
        recommended_action_commands=health_issue_data["recommendedActionCommands"],
        additional_information=health_issue_data["additionalInformation"],
    )

    return SimpleNamespace(
        value=[health_issue],
        odata_next_link=None,
    )


@pytest.mark.asyncio
async def test_get_all_health_issues_with_microsoft_documentation_response():
    """
    Test get_all_health_issues using the healthIssue example from
    the official Microsoft Graph documentation.
    """
    response = create_health_issue_response()

    request_builder = MagicMock()
    request_builder.get = AsyncMock(return_value=response)

    client = MagicMock()
    client.security.identities.health_issues = request_builder

    result = await msgraphhealthcheck.get_all_health_issues(client)

    # One health issue was returned.
    assert len(result) == 1

    issue = result[0]

    # Values from Microsoft's documented response.
    assert issue.id == ("b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c")

    assert issue.display_name == (
        "Directory Services Object Auditing isn't configured as required"
    )

    assert issue.description == (
        "Directory Services Object Auditing isn't configured "
        "as required on domain1.contoso.com"
    )

    assert issue.severity == "medium"
    assert issue.status == "open"

    assert issue.domain_names == [
        "domain1.contoso.com",
        "domain2.contoso.com",
    ]

    assert issue.health_issue_type == "Global"
    assert issue.issue_type_id == "1031"

    assert issue.sensor_dns_names == [
        "DC1.domain1.contoso.com",
        "DC2.domain2.contoso.com",
    ]

    assert issue.recommendations == [
        (
            "Please configure the Directory Services Object Auditing "
            "events according to the guidance as described in "
            "https://aka.ms/mdi/objectauditing"
        )
    ]

    assert issue.recommended_action_commands == ["Import-Module DefenderForIdentity"]

    # Verify that Graph was called exactly once.
    request_builder.get.assert_awaited_once()

    # The example response has no @odata.nextLink,
    # so pagination should not be attempted.
    request_builder.with_url.assert_not_called()


@pytest.mark.asyncio
async def test_browse_health_issues_with_microsoft_documentation_response(
    caplog,
):
    """
    Test browse_health_issues using Microsoft's documented healthIssue.
    """
    response = create_health_issue_response()
    issue = response.value[0]

    client = MagicMock()

    original_function = msgraphhealthcheck.get_all_health_issues

    try:
        msgraphhealthcheck.get_all_health_issues = AsyncMock(return_value=[issue])

        with caplog.at_level(
            "INFO",
            logger=msgraphhealthcheck.LOGGER.name,
        ):
            await msgraphhealthcheck.browse_health_issues(client)

        msgraphhealthcheck.get_all_health_issues.assert_awaited_once_with(client)

        assert (
            "Health issue: "
            f"id={issue.id}, "
            f"name={issue.display_name}, "
            f"severity={issue.severity}, "
            f"status={issue.status}"
        ) in caplog.text

    finally:
        msgraphhealthcheck.get_all_health_issues = original_function
