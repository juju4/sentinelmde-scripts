"""
Logs export

With msticpy
alternative:
_exec_split_query()
https://github.com/microsoft/msticpy/blob/main/msticpy/data/core/query_provider_connections_mixin.py#L238

SPDX-FileCopyrightText: 2025 The python_openobserve authors
SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=C0301

import json

# import os
from datetime import datetime, timedelta

from msticpy.data.core.data_providers import QueryProvider  # type: ignore

defender_prov = QueryProvider("M365DGraph")
defender_prov.connect()


# pylint: disable=R0913
def search2export(
    query: str,
    file_prefix: str,
    *,
    start_time: datetime = datetime.now(),
    end_time: datetime = datetime.now(),
    export_format: str = "csv",
    split_period: str = "D",
    provider=None,
) -> bool:
    """
    Msticpy search export function
    Split options to manage large volume

    Note: timerange must be provided in input even if included
    in query as use for output filename and not possible to extract
    reliably from query

    Args:
      query: input kql query
      start_time: start of search interval (datetime)
      end_time: end of search interval (datetime)
      export_format: csv only
      split_period: interval per file, H, D, W or M
      file_prefix: file prefix for export
      provider: msticpy provider instance
    """
    if not file_prefix:
        print(f"FATAL! no file_prefix input: {file_prefix}")
        return False
    period_start = start_time
    interval = timedelta(days=1)
    time_fmt = "%Y-%m-%dT%H:%M"
    if split_period == "H":
        interval = timedelta(hours=1)
    if split_period == "W":
        interval = timedelta(weeks=1)
        time_fmt = "%Y-%m-%d"
    if split_period not in ("H", "D", "W"):
        print(f"FATAL! invalid split period input: {split_period}")
        return False
    period_end = start_time + interval

    if export_format == "json":
        while period_end < end_time:
            # file_name = f"{file_prefix}-{period_start.isoformat()}-{period_end.isoformat()}-export.json"
            file_name = (
                f"{file_prefix}--"
                # f"{period_start.isoformat()}-{period_end.isoformat()}"
                f"{period_start.strftime(time_fmt)}--{period_end.strftime(time_fmt)}"
                "--export.json"
            )
            # usually always dataframe output.
            # https://github.com/microsoft/msticpy/blob/main/msticpy/data/drivers/odata_driver.py
            # query() or query_with_results()
            df_res = provider.exec_query(query, start=period_start, end=period_end)
            res_json = df_res.to_json(orient="records")
            with open(
                file_name,
                "w",
                encoding="utf-8",
            ) as f:
                json.dump(res_json, f)
            # loop
            period_start = period_end
            period_end = period_start + interval
    if export_format == "csv":
        while period_end < end_time:
            file_name = (
                f"{file_prefix}--"
                f"{period_start.strftime(time_fmt)}--{period_end.strftime(time_fmt)}"
                "--export.csv"
            )
            df_res = provider.exec_query(query, start=period_start, end=period_end)
            df_res.to_csv(
                file_name,
                index=False,
            )
            # loop
            period_start = period_end
            period_end = period_start + interval

    return True


# query = "DeviceAlertEvents | sample 10"
# defender_prov.exec_query(query)
QUERY = "DeviceAlertEvents"
start_timeperiod = datetime.now() - timedelta(hours=6)
end_timeperiod = datetime.now()
search2export(QUERY, "kqldata", start_time=start_timeperiod, end_time=end_timeperiod)
