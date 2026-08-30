"""
Healthcheck from Microsoft Graph API

https://learn.microsoft.com/en-us/graph/api/resources/security-healthissue?view=graph-rest-beta
https://learn.microsoft.com/en-us/graph/api/security-identitycontainer-list-healthissues?view=graph-rest-beta&tabs=http
https://learn.microsoft.com/en-us/graph/api/security-identitycontainer-list-sensors?view=graph-rest-beta&tabs=http
https://learn.microsoft.com/en-us/graph/api/security-list-securescores?view=graph-rest-beta&tabs=http
https://github.com/microsoftgraph/msgraph-sdk-python

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

import os
import logging
import asyncio

# from collections.abc import Awaitable, Callable
# from typing import TypeAlias
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphServiceClient  # type: ignore
from msgraph.generated.models.security.health_issue import HealthIssue
from msgraph.generated.models.user import User
from msgraph.generated.models.application_collection_response import (
    ApplicationCollectionResponse,
)
import dotenv

# tenantid, appid, appsecret
dotenv.load_dotenv()

LOGGER = logging.getLogger(__name__)


scopes = ["https://graph.microsoft.com/.default"]


def create_credentials() -> ClientSecretCredential:
    """
    Initialize access with env credentials
    """
    return ClientSecretCredential(
        os.getenv("tenant_id", ""),
        os.getenv("msgraph_client_id", ""),
        os.getenv("msgraph_client_secret", ""),
    )


# GET /users/{id | userPrincipalName}
async def get_user(client: GraphServiceClient) -> User | None:
    """
    Get user information

    Args:
        client: An authenticated Microsoft Graph client.

    Returns:
        User information.
    """
    user = await client.users.by_user_id("userPrincipalName").get()
    if user:
        print(user.display_name)

    return user


async def get_applications(
    client: GraphServiceClient,
) -> ApplicationCollectionResponse | None:
    """
    Get applications list

    Args:
        client: An authenticated Microsoft Graph client.

    Returns:
        A list of applications.
    """
    apps = await client.applications.get()
    if apps and apps.value:
        for app in apps.value:
            print(app.id)

    return apps


async def get_all_health_issues(
    client: GraphServiceClient,
) -> list[HealthIssue]:
    """
    Retrieve all Microsoft Graph health issues

    Args:
        client: An authenticated Microsoft Graph client.

    Returns:
        A list containing every health issue returned by Microsoft Graph.

    Raises:
        RuntimeError: If Microsoft Graph returns an unexpected empty response
            while pagination is still expected.
    """
    request_builder = client.security.identities.health_issues

    response = await request_builder.get()
    health_issues: list[HealthIssue] = []

    while response is not None:
        if response.value is not None:
            health_issues.extend(response.value)

        next_link = response.odata_next_link
        if not next_link:
            break

        response = await request_builder.with_url(next_link).get()

    return health_issues


async def browse_health_issues(client: GraphServiceClient) -> None:
    """Retrieve and log all Microsoft Graph health issues."""
    health_issues = await get_all_health_issues(client)

    for issue in health_issues:
        LOGGER.info(
            "Health issue: id=%s, name=%s, severity=%s, status=%s",
            issue.id,
            issue.display_name,
            issue.severity,
            issue.status,
        )


if __name__ == "__main__":
    credentials = create_credentials()
    graphclient = GraphServiceClient(credentials=credentials, scopes=scopes)
    asyncio.run(get_user(graphclient))
    asyncio.run(get_applications(graphclient))
    asyncio.run(browse_health_issues(graphclient))
