"""
msgraphhealthcheck tests - offline

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=R0801
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import msgraphhealthcheck


@pytest.mark.asyncio
async def test_get_user_returns_user_and_prints_display_name(capsys):
    """get_user should retrieve the user and print the display name."""
    user = SimpleNamespace(display_name="John Doe")

    client = MagicMock()
    client.users.by_user_id.return_value.get = AsyncMock(return_value=user)

    result = await msgraphhealthcheck.get_user(client)

    assert result is user
    client.users.by_user_id.assert_called_once_with("userPrincipalName")
    client.users.by_user_id.return_value.get.assert_awaited_once()

    captured = capsys.readouterr()
    assert captured.out == "John Doe\n"


@pytest.mark.asyncio
async def test_get_user_when_user_is_none(capsys):
    """get_user should return None without printing when Graph returns None."""
    client = MagicMock()
    client.users.by_user_id.return_value.get = AsyncMock(return_value=None)

    result = await msgraphhealthcheck.get_user(client)

    assert result is None

    captured = capsys.readouterr()
    assert captured.out == ""


@pytest.mark.asyncio
async def test_get_applications_returns_applications_and_prints_ids(capsys):
    """get_applications should return the Graph response and print app IDs."""
    applications = SimpleNamespace(
        value=[
            SimpleNamespace(id="app-1"),
            SimpleNamespace(id="app-2"),
        ]
    )

    client = MagicMock()
    client.applications.get = AsyncMock(return_value=applications)

    result = await msgraphhealthcheck.get_applications(client)

    assert result is applications
    client.applications.get.assert_awaited_once()

    captured = capsys.readouterr()
    assert captured.out == "app-1\napp-2\n"


@pytest.mark.asyncio
async def test_get_applications_when_response_is_none(capsys):
    """get_applications should handle a None response."""
    client = MagicMock()
    client.applications.get = AsyncMock(return_value=None)

    result = await msgraphhealthcheck.get_applications(client)

    assert result is None

    captured = capsys.readouterr()
    assert captured.out == ""


@pytest.mark.asyncio
async def test_get_applications_when_value_is_none(capsys):
    """get_applications should handle a response with no value."""
    applications = SimpleNamespace(value=None)

    client = MagicMock()
    client.applications.get = AsyncMock(return_value=applications)

    result = await msgraphhealthcheck.get_applications(client)

    assert result is applications

    captured = capsys.readouterr()
    assert captured.out == ""


@pytest.mark.asyncio
async def test_get_all_health_issues_single_page():
    """get_all_health_issues should return all issues from one page."""
    issue_1 = SimpleNamespace(
        id="issue-1",
        display_name="Issue One",
    )
    issue_2 = SimpleNamespace(
        id="issue-2",
        display_name="Issue Two",
    )

    response = SimpleNamespace(
        value=[issue_1, issue_2],
        odata_next_link=None,
    )

    request_builder = MagicMock()
    request_builder.get = AsyncMock(return_value=response)

    client = MagicMock()
    client.security.identities.health_issues = request_builder

    result = await msgraphhealthcheck.get_all_health_issues(client)

    assert result == [issue_1, issue_2]

    request_builder.get.assert_awaited_once()
    request_builder.with_url.assert_not_called()


@pytest.mark.asyncio
async def test_get_all_health_issues_multiple_pages():
    """get_all_health_issues should follow @odata.nextLink pagination."""
    issue_1 = SimpleNamespace(id="issue-1")
    issue_2 = SimpleNamespace(id="issue-2")
    issue_3 = SimpleNamespace(id="issue-3")

    first_response = SimpleNamespace(
        value=[issue_1, issue_2],
        odata_next_link="https://graph.microsoft.com/next-page",
    )

    second_response = SimpleNamespace(
        value=[issue_3],
        odata_next_link=None,
    )

    request_builder = MagicMock()

    request_builder.get = AsyncMock(return_value=first_response)

    next_request_builder = MagicMock()
    next_request_builder.get = AsyncMock(return_value=second_response)

    request_builder.with_url.return_value = next_request_builder

    client = MagicMock()
    client.security.identities.health_issues = request_builder

    result = await msgraphhealthcheck.get_all_health_issues(client)

    assert result == [issue_1, issue_2, issue_3]

    request_builder.get.assert_awaited_once()
    request_builder.with_url.assert_called_once_with(
        "https://graph.microsoft.com/next-page"
    )
    next_request_builder.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_all_health_issues_empty_value():
    """get_all_health_issues should return an empty list for an empty page."""
    response = SimpleNamespace(
        value=None,
        odata_next_link=None,
    )

    request_builder = MagicMock()
    request_builder.get = AsyncMock(return_value=response)

    client = MagicMock()
    client.security.identities.health_issues = request_builder

    result = await msgraphhealthcheck.get_all_health_issues(client)

    assert result == []


@pytest.mark.asyncio
async def test_get_all_health_issues_none_response():
    """get_all_health_issues should return an empty list for None."""
    request_builder = MagicMock()
    request_builder.get = AsyncMock(return_value=None)

    client = MagicMock()
    client.security.identities.health_issues = request_builder

    result = await msgraphhealthcheck.get_all_health_issues(client)

    assert result == []


@pytest.mark.asyncio
async def test_get_all_health_issues_empty_page_with_next_link():
    """Pagination should continue when a page has no values but has nextLink."""
    issue = SimpleNamespace(id="issue-2")

    first_response = SimpleNamespace(
        value=None,
        odata_next_link="https://graph.microsoft.com/page-2",
    )

    second_response = SimpleNamespace(
        value=[issue],
        odata_next_link=None,
    )

    request_builder = MagicMock()
    request_builder.get = AsyncMock(return_value=first_response)

    next_request_builder = MagicMock()
    next_request_builder.get = AsyncMock(return_value=second_response)

    request_builder.with_url.return_value = next_request_builder

    client = MagicMock()
    client.security.identities.health_issues = request_builder

    result = await msgraphhealthcheck.get_all_health_issues(client)

    assert result == [issue]

    request_builder.with_url.assert_called_once_with(
        "https://graph.microsoft.com/page-2"
    )


@pytest.mark.asyncio
async def test_browse_health_issues_logs_all_issues(caplog):
    """browse_health_issues should log every health issue."""
    issue_1 = SimpleNamespace(
        id="issue-1",
        display_name="Issue One",
        severity="high",
        status="active",
    )

    issue_2 = SimpleNamespace(
        id="issue-2",
        display_name="Issue Two",
        severity="low",
        status="resolved",
    )

    client = MagicMock()

    # Mock get_all_health_issues rather than Graph itself.
    original_function = msgraphhealthcheck.get_all_health_issues

    try:
        msgraphhealthcheck.get_all_health_issues = AsyncMock(
            return_value=[issue_1, issue_2]
        )

        with caplog.at_level("INFO", logger=msgraphhealthcheck.LOGGER.name):
            await msgraphhealthcheck.browse_health_issues(client)

        msgraphhealthcheck.get_all_health_issues.assert_awaited_once_with(client)

        assert "Health issue: id=issue-1" in caplog.text
        assert "name=Issue One" in caplog.text
        assert "severity=high" in caplog.text
        assert "status=active" in caplog.text

        assert "Health issue: id=issue-2" in caplog.text
        assert "name=Issue Two" in caplog.text
        assert "severity=low" in caplog.text
        assert "status=resolved" in caplog.text

    finally:
        msgraphhealthcheck.get_all_health_issues = original_function


@pytest.mark.asyncio
async def test_browse_health_issues_when_no_issues(caplog):
    """browse_health_issues should not log issues when the list is empty."""
    client = MagicMock()

    original_function = msgraphhealthcheck.get_all_health_issues

    try:
        msgraphhealthcheck.get_all_health_issues = AsyncMock(return_value=[])

        with caplog.at_level("INFO", logger=msgraphhealthcheck.LOGGER.name):
            await msgraphhealthcheck.browse_health_issues(client)

        msgraphhealthcheck.get_all_health_issues.assert_awaited_once_with(client)

        assert "Health issue:" not in caplog.text

    finally:
        msgraphhealthcheck.get_all_health_issues = original_function
