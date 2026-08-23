"""
Module for Sentinel / Defender XDR

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=fixme

import os
import json
import re
import logging

# import datetime

import httpx
import pandas
import jmespath
import dotenv

# tenantid, appid, appsecret
dotenv.load_dotenv()


def create_safe_filename(filename: str) -> str:
    """generate filename from string"""
    return "".join(c for c in filename if c.isalnum() or c in (" ", ".", "_")).rstrip()


def get_rg_from_id(resourceid: str) -> str:
    """Get Azure resource group from Azure resource id"""
    match = re.sub(r".*\/resourceGroups\/(.*?)\/providers\/.*", r"\1", resourceid)
    if match:
        return match
    return ""


# pylint: disable=R0904
class SentinelMDE:
    """
    SentinelMDE class
    mostly wrapper around Microsoft API
    """

    def __init__(self):
        self.tenant_id = os.getenv("tenant_id", None)
        self.client_id = os.getenv("client_id", None)
        self.client_secret = os.getenv("client_secret", None)
        self.resource_uri = os.getenv("resource_uri", None)
        self.oauth_uri = os.getenv("oauth_uri", None)

        url = f"{self.oauth_uri}/{self.tenant_id}/oauth2/token"
        body = {
            "resource": self.resource_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }

        try:
            response = httpx.post(url, json=body)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        json_response = response.json()
        token = json_response["access_token"]

        self.headers = {"Authorization": f"Bearer {token}"}

    def get_alerts(self, subscription_id: str, rg_name: str, ws_name: str) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/securityinsights/alert-rules/list?view=rest-securityinsights-2025-09-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers"
            f"/Microsoft.OperationalInsights/workspaces/{ws_name}"
            "/providers/Microsoft.SecurityInsights/alertRules?api-version=2025-09-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_automationrules(
        self, subscription_id: str, rg_name: str, ws_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/securityinsights/automation-rules/list?view=rest-securityinsights-2025-09-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers"
            f"/Microsoft.OperationalInsights/workspaces/{ws_name}"
            "/providers/Microsoft.SecurityInsights/automationRules?api-version=2025-09-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_bookmarks(self, subscription_id: str, rg_name: str, ws_name: str) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/securityinsights/bookmarks/list?view=rest-securityinsights-2025-09-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers"
            f"/Microsoft.OperationalInsights/workspaces/{ws_name}"
            "/providers/Microsoft.SecurityInsights/bookmarks?api-version=2025-09-01"
        )

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_contentpackages(
        self, subscription_id: str, rg_name: str, ws_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers"
            f"/Microsoft.OperationalInsights/workspaces/{ws_name}"
            "/providers/Microsoft.SecurityInsights/contentPackages?api-version=2025-09-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_watchlists(self, subscription_id: str, rg_name: str, ws_name: str) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/securityinsights/watchlists/list?view=rest-securityinsights-2025-09-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers"
            f"/Microsoft.OperationalInsights/workspaces/{ws_name}"
            "/providers/Microsoft.SecurityInsights/watchlists?api-version=2025-09-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_sourcecontrols(
        self, subscription_id: str, rg_name: str, ws_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/securityinsights/source-controls/list?view=rest-securityinsights-2025-09-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers"
            f"/Microsoft.OperationalInsights/workspaces/{ws_name}"
            "/providers/Microsoft.SecurityInsights/sourcecontrols?api-version=2025-09-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_productpackages(
        self, subscription_id: str, rg_name: str, ws_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers"
            f"/Microsoft.OperationalInsights/workspaces/{ws_name}"
            "/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=2025-09-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_loganalytics_datasources(
        self,
        subscription_id: str,
        rg_name: str,
        ws_name: str,
        lgfilter: str = "kind='WindowsEvent'",
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/loganalytics/data-sources/list-by-workspace?view=rest-loganalytics-2026-03-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers/"
            f"Microsoft.OperationalInsights/workspaces/{ws_name}/"
            f"dataSources?api-version=2026-03-01&$filter={lgfilter}"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_loganalytics_tables(
        self, subscription_id: str, rg_name: str, ws_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/loganalytics/tables/list-by-workspace?view=rest-loganalytics-2026-03-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers/"
            f"Microsoft.OperationalInsights/workspaces/{ws_name}/tables?api-version=2026-03-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_loganalytics_savedsearches(
        self, subscription_id: str, rg_name: str, ws_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/loganalytics/saved-searches/list-by-workspace?view=rest-loganalytics-2026-03-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers/"
            f"Microsoft.OperationalInsights/workspaces/{ws_name}/"
            "savedSearches?api-version=2026-03-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_loganalytics_usage(
        self, subscription_id: str, rg_name: str, ws_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/loganalytics/usages/list?view=rest-loganalytics-2026-03-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers/"
            f"Microsoft.OperationalInsights/workspaces/{ws_name}/usages?api-version=2026-03-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_workflows_bysub(self, subscription_id: str) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/logic/workflows/list-by-subscription?view=rest-logic-2019-05-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            "/providers/Microsoft.Logic/workflows?api-version=2019-05-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_workflows_byrg(self, subscription_id: str, rg_name: str) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/logic/workflows/list-by-resource-group?view=rest-logic-2019-05-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers/"
            f"Microsoft.Logic/workflows?api-version=2019-05-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_workflow_runs(
        self, subscription_id: str, rg_name: str, workflow_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/logic/workflow-runs/list?view=rest-logic-2019-05-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/resourceGroups/{rg_name}/providers/"
            f"Microsoft.Logic/workflows/{workflow_name}/runs?api-version=2019-05-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_deployments_bysub(self, subscription_id: str) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/resources/deployments/list-at-subscription-scope?view=rest-resources-2025-04-01
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            "/providers/Microsoft.Resources/deployments?api-version=2025-04-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_availabilitystatuses(self, subscription_id: str) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/resourcehealth/availability-statuses/list-by-subscription-id?view=rest-resourcehealth-2025-05-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/"
            f"Microsoft.ResourceHealth/availabilityStatuses?api-version=2025-05-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_healthevents(self, subscription_id: str) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/resourcehealth/events/list-by-subscription-id?view=rest-resourcehealth-2025-05-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/"
            f"Microsoft.ResourceHealth/events?api-version=2025-05-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    def get_impactedresource(
        self, subscription_id: str, event_tracking_id: str, impacted_resource_name: str
    ) -> dict:
        """
        https://learn.microsoft.com/en-us/rest/api/resourcehealth/impacted-resources/get?view=rest-resourcehealth-2025-05-01&tabs=HTTP
        """
        url = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/"
            f"Microsoft.ResourceHealth/events/{event_tracking_id}/"
            f"impactedResources/{impacted_resource_name}?api-version=2025-05-01"
        )
        logging.info("url %s", url)

        try:
            response = httpx.get(url)
        except httpx.HTTPError as exc:
            logging.exception("HTTP Error %s", exc)

        logging.debug("response %s", response.json())
        return response.json()

    # pylint: disable=R0914
    def healthcheck(self, subscription_id: str) -> str:
        """
        Health check of security environment

        Args:
          subscription_id: Target subscription id

        https://learn.microsoft.com/en-us/azure/sentinel/health-audit
        https://learn.microsoft.com/en-us/azure/sentinel/monitor-data-connector-health
        `SentinelHealth` table
        https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring?tabs=defender-portal
        `_SentinelHealth()`
        https://learn.microsoft.com/en-us/answers/questions/1355103/how-to-get-azure-status-using-rest-api
        """

        res1 = self.get_availabilitystatuses(subscription_id)
        res2 = self.get_healthevents(subscription_id)

        summary = f"""## Healthcheck report for subscription {subscription_id}

Availability status count: {len(res1["value"])}
Affected resources
"""
        count_res1 = 0
        for res in res1["value"]:
            summary += (
                f"* title {res['properties']['title']} "
                f"detailedStatus {res['properties']['detailedStatus']}\n"
            )
            count_res1 += 1
            if count_res1 >= 10:
                summary += "(More than 10 results... truncating)\n"
                break
        if len(res1["value"]) == 0:
            summary += "Not Applicable\n"

        summary += f"""\nHealth events count: {len(res2["value"])}
Events quick view
"""
        count_res2 = 0
        for res in res2["value"]:
            summary += (
                f"* name {res['name']} status {res['properties']['status']} "
                f"title {res['properties']['title']} eventType {res['properties']['eventType']} "
                f"impactedService {res['properties']['impact'][0]['impactedService']}\n"
            )
            count_res2 += 1
            if count_res2 >= 10:
                summary += "(More than 10 results... truncating)\n"
                break
        if len(res2["value"]) == 0:
            summary += "Not Applicable\n"

        summary += """\nFailed LogicApp workflows run
"""
        failed_count = 0
        workflows = self.get_workflows_bysub(subscription_id)
        for wf in workflows["value"]:
            workflow_name = wf["name"]
            rg_name = get_rg_from_id(wf["id"])
            runs = self.get_workflow_runs(subscription_id, rg_name, workflow_name)
            # PendingDeprecationWarning: deprecated string literal syntax
            # = need double quote inside to force json string literal
            failed_runs = jmespath.search(
                'value[?properties.status != `"Succeeded"`]',
                runs,
            )
            if failed_runs is not None and len(failed_runs) > 0:
                for r in failed_runs:
                    summary += (
                        f"* {r['properties']['startTime']} {r['properties']['status']} "
                        f"{r['properties']['correlation']['clientTrackingId']} "
                        f"{r['properties']['workflow']['id']}\n"
                    )
                    failed_count += 1
                    if failed_count >= 10:
                        summary += "(More than 10 results... truncating)\n"
                        break

        if failed_count == 0:
            summary += "Not Applicable\n"

        # TODO: add failed deployments
        # https://learn.microsoft.com/en-us/rest/api/resources/deployments/list-at-subscription-scope?view=rest-resources-2025-04-01
        # TODO: cost management
        # https://learn.microsoft.com/en-us/rest/api/cost-management/alerts/list?view=rest-cost-management-2026-06-01&tabs=HTTP
        # https://learn.microsoft.com/en-us/rest/api/cost-management/query/usage?view=rest-cost-management-2026-06-01&tabs=HTTP

        return summary

    # pylint: disable=R0912,R0913,R0914,R0915
    def list_objects2df(
        self,
        subscription_id: str,
        rg_name: str,
        ws_name: str,
        object_type: str,
        *,
        normalize_max_level: int = 3,
    ) -> pandas.DataFrame:
        """
        List Sentinel/MDE XDR settings for one object type
        Dataframe output

        Args:
          subscription_id: Target subscription id
          rg_name: Target resource group name
          ws_name: Target Workspace name
          object_type: Target object type
          normalize_max_level: depth of panda normalize

        Inspired from
        https://github.com/juju4/python-openobserve/blob/devel/python_openobserve/openobserve.py#L538
        """

        results = None
        if object_type == "alerts":
            results = self.get_alerts(subscription_id, rg_name, ws_name)
        elif object_type == "automationrules":
            results = self.get_automationrules(subscription_id, rg_name, ws_name)
        elif object_type == "bookmarks":
            results = self.get_bookmarks(subscription_id, rg_name, ws_name)
        elif object_type == "contentpackages":
            results = self.get_contentpackages(subscription_id, rg_name, ws_name)
        elif object_type == "watchlists":
            results = self.get_watchlists(subscription_id, rg_name, ws_name)
        elif object_type == "sourcecontrols":
            results = self.get_sourcecontrols(subscription_id, rg_name, ws_name)
        elif object_type == "productpackages":
            results = self.get_productpackages(subscription_id, rg_name, ws_name)
        elif object_type == "datasources":
            results = self.get_loganalytics_datasources(
                subscription_id, rg_name, ws_name
            )
        elif object_type == "tables":
            results = self.get_loganalytics_tables(subscription_id, rg_name, ws_name)
        elif object_type == "savedsearches":
            results = self.get_loganalytics_savedsearches(
                subscription_id, rg_name, ws_name
            )
        elif object_type == "usage":
            results = self.get_loganalytics_usage(subscription_id, rg_name, ws_name)
        elif object_type == "workflows":
            results = self.get_workflows_byrg(subscription_id, rg_name)
        else:
            logging.exception("Invalid object_type %s", object_type)

        return pandas.json_normalize(
            results["value"],  # type: ignore
            max_level=normalize_max_level,
        )

    # pylint: disable=R0912,R0913,R0914,R0915
    def export_objects(
        self,
        subscription_id: str,
        rg_name: str,
        ws_name: str,
        object_type: str,
        file_path: str,
        *,
        outformat: str = "json",
        split: bool = False,
        flat: bool = False,
        strip: bool = False,
        normalize_max_level: int = 3,
    ):
        """
        Export Sentinel/MDE XDR configuration for one object type to json/csv/xlsx

        Args:
          subscription_id: Target subscription id
          rg_name: Target resource group name
          ws_name: Target Workspace name
          object_type: Target object type
          file_path: target file path or prefix
          verbosity: how verbose to run from 0/less to 5/more
          outformat: json, csv, or xlsx
          split: separate list of objects json in one file per object
          flat: put all files in a flat directory or tree hierarchy
          strip: remove too variables data fields
          normalize_max_level: depth of panda normalize

        Inspired from
        https://github.com/juju4/python-openobserve/blob/devel/python_openobserve/openobserve.py#L559
        """

        results = None
        if object_type == "alerts":
            results = self.get_alerts(subscription_id, rg_name, ws_name)
        elif object_type == "automationrules":
            results = self.get_automationrules(subscription_id, rg_name, ws_name)
        elif object_type == "bookmarks":
            results = self.get_bookmarks(subscription_id, rg_name, ws_name)
        elif object_type == "contentpackages":
            results = self.get_contentpackages(subscription_id, rg_name, ws_name)
        elif object_type == "watchlists":
            results = self.get_watchlists(subscription_id, rg_name, ws_name)
        elif object_type == "sourcecontrols":
            results = self.get_sourcecontrols(subscription_id, rg_name, ws_name)
        elif object_type == "productpackages":
            results = self.get_productpackages(subscription_id, rg_name, ws_name)
        elif object_type == "datasources":
            results = self.get_loganalytics_datasources(
                subscription_id, rg_name, ws_name
            )
        elif object_type == "tables":
            results = self.get_loganalytics_tables(subscription_id, rg_name, ws_name)
        elif object_type == "savedsearches":
            results = self.get_loganalytics_savedsearches(
                subscription_id, rg_name, ws_name
            )
        elif object_type == "usage":
            results = self.get_loganalytics_usage(subscription_id, rg_name, ws_name)
        elif object_type == "workflows":
            results = self.get_workflows_byrg(subscription_id, rg_name)
        else:
            logging.exception("Invalid object_type %s", object_type)

        if strip is True:
            # if content too variable or not not needed
            keys_to_remove = [
                # usages
                "currentValue",
            ]
            # data = json.loads(json_object)
            data2 = {
                k: v
                for k, v in results["value"].items()  # type: ignore
                if k not in keys_to_remove
            }
            # json_object = json.dumps(data2)
            results = {"value": data2}

        if results and outformat == "json" and flat is True and split is False:
            with open(f"{file_path}{object_type}.json", "w", encoding="utf-8") as f:
                json.dump(results, f)
            return results
        if results and outformat == "json" and flat is True and split is True:
            for res in results["value"]:
                filename = (
                    f"{file_path}{object_type}-{create_safe_filename(res['name'])}.json"
                )
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(res, f)
            return results
        if results and outformat == "json" and flat is False and split is True:
            os.makedirs(f"{file_path}/{object_type}", exist_ok=True)
            for res in results["value"]:
                filename = f"{file_path}/{object_type}/{create_safe_filename(res['name'])}.json"
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(res, f)
            return results
        if results and outformat in ("csv", "xlsx"):
            df_results = pandas.json_normalize(
                results["value"], max_level=normalize_max_level
            )
            if outformat == "csv":
                df_results.to_csv(f"{file_path}{object_type}.csv", index=False)
                return True
            if outformat == "xlsx":
                df_results.to_excel(f"{file_path}{object_type}.xlsx", index=False)
                return True

        logging.error("No export?")
        return False

    # pylint: disable=R0913
    def config_export(
        self,
        subscription_id: str,
        rg_name: str,
        ws_name: str,
        file_path: str,
        *,
        outformat: str = "json",
        split: bool = False,
        flat: bool = False,
        strip: bool = False,
    ):
        """
        Export Sentinel/MDE XDR configuration aka all object types to json/csv/xlsx

        Args:
          subscription_id: Target subscription id
          rg_name: Target resource group name
          ws_name: Target Workspace name
          object_type: Target object type
          file_path: target file path or prefix
          verbosity: how verbose to run from 0/less to 5/more
          outformat: json, csv, or xlsx
          split: separate list of objects json in one file per object
          flat: put all files in a flat directory or tree hierarchy
          strip: remove variables data like stats or updated_at fields

        Inspired from
        https://github.com/juju4/python-openobserve/blob/devel/python_openobserve/openobserve.py#L559
        """
        all_objects_types = [
            "alerts",
            "automationrules",
            "bookmarks",
            "contentpackages",
            "watchlists",
            "sourcecontrols",
            "productpackages",
            "datasources",
            "tables",
            "savedsearches",
            "usage",
            "workflows",
        ]

        for object_type in all_objects_types:
            # pylint: disable=E1121
            self.export_objects(
                subscription_id,
                rg_name,
                ws_name,
                object_type,
                file_path,
                outformat=outformat,
                split=split,
                flat=flat,
                strip=strip,
            )
