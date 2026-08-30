"""
Healtcheck through Sentinel/MDE tables

With msticpy
https://github.com/microsoft/msticpy/blob/main/docs/notebooks/MicrosoftDefender.ipynb

SPDX-FileCopyrightText: 2026 The sentinelmde-scripts authors
SPDX-License-Identifier: GPL-3.0-or-later
"""

# pylint: disable=C0301

from msticpy.data.core.data_providers import QueryProvider  # type: ignore

defender_prov = QueryProvider("M365DGraph")
defender_prov.connect()

defender_prov.MDATP.list_alerts(start=-10)

# query = "DeviceAlertEvents | sample 10"
# defender_prov.exec_query(query)

queries = {
    # https://learn.microsoft.com/en-us/azure/sentinel/monitor-data-connector-health
    "Detect latest failure events per connector": """SentinelHealth
| where TimeGenerated > ago(3d)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId
| where Status == 'Failure'""",
    "Detect connectors with changes from fail to success state": """let latestStatus = SentinelHealth
| where TimeGenerated > ago(12h)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| project TimeGenerated, SentinelResourceName, SentinelResourceId, LastStatus = Status
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId;
let nextTolatestStatus = SentinelHealth
| where TimeGenerated > ago(12h)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| join kind = leftanti (latestStatus) on SentinelResourceName, SentinelResourceId, TimeGenerated
| project TimeGenerated, SentinelResourceName, SentinelResourceId, NextToLastStatus = Status
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId;
latestStatus
| join kind=inner (nextTolatestStatus) on SentinelResourceName, SentinelResourceId
| where NextToLastStatus == 'Failure' and LastStatus == 'Success'
""",
    "Detect connectors with changes from success to fail state": """let latestStatus = SentinelHealth
| where TimeGenerated > ago(12h)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| project TimeGenerated, SentinelResourceName, SentinelResourceId, LastStatus = Status
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId;
let nextTolatestStatus = SentinelHealth
| where TimeGenerated > ago(12h)
| where OperationName == 'Data fetch status change'
| where Status in ('Success', 'Failure')
| join kind = leftanti (latestStatus) on SentinelResourceName, SentinelResourceId, TimeGenerated
| project TimeGenerated, SentinelResourceName, SentinelResourceId, NextToLastStatus = Status
| summarize TimeGenerated = arg_max(TimeGenerated,*) by SentinelResourceName, SentinelResourceId;
latestStatus
| join kind=inner (nextTolatestStatus) on SentinelResourceName, SentinelResourceId
| where NextToLastStatus == 'Success' and LastStatus == 'Failure'
""",
    # https://learn.microsoft.com/en-us/azure/sentinel/enable-monitoring?tabs=defender-portal
    "Sentinelhealth": """_SentinelHealth()
 | take 20""",
    "SentinelAudit": """_SentinelAudit()
 | take 20
""",
    # https://kqlquery.com/posts/monitor-new-actions/
    "Defender For Endpoint New ActionType": """let TimeFrame = 30d;
let Schedule = 1d;
let KnownActions = union Device*
| where TimeGenerated between (startofday(ago(TimeFrame)) .. startofday(ago(Schedule)))
| where isnotempty(ActionType)
| distinct ActionType;
union Device*
| where TimeGenerated > startofday(ago(Schedule))
| where isnotempty(ActionType) and ActionType !in (KnownActions)
| distinct Type, ActionType
| project-rename DataType = Type
| sort by DataType, ActionType
""",
    # https://jeffreyappel.nl/how-to-check-for-a-healthy-defender-for-endpoint-environment/
    "Defender AV disabled": """DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2011" // Update Microsoft Defender for Windows Antivirus definitions
| join kind=leftouter DeviceTvmSecureConfigurationAssessmentKB on ConfigurationId
| mv-expand  e = parse_json(Context)
| project DeviceName,DeviceId, OSPlatform, SignatureVersion=tostring(e[0]), SignatureDate=todatetime(e[2]), EngineVersion=e[1], ProductVersion=e[3]
 | join kind=inner    (DeviceInfo
| where Timestamp > ago(30d)
| summarize arg_max(Timestamp,*) by DeviceName
| extend LastSeen = Timestamp
)
on $left.DeviceId ==  $right.DeviceId
| project DeviceName, DeviceId, OSPlatform, SignatureVersion, SignatureDate, EngineVersion, ProductVersion, LastSeen
| where SignatureVersion == "0.0.0.0"
""",
    "Defender AV mode not active": """let avmodetable = DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2010" and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVMode = iif(tostring(avdata[0][0]) == '0', 'Active' , iif(tostring(avdata[0][0]) == '1', 'Passive' ,iif(tostring(avdata[0][0]) == '4', 'EDR Blocked' ,'Unknown')))
| project DeviceId, AVMode;
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == "scid-2011" and isnotnull(Context)
| extend avdata=parsejson(Context)
| extend AVSigVersion = tostring(avdata[0][0])
| extend AVEngineVersion = tostring(avdata[0][1])
| extend AVSigLastUpdateTime = tostring(avdata[0][2])
| project DeviceId, DeviceName, OSPlatform, AVSigVersion, AVEngineVersion, AVSigLastUpdateTime, IsCompliant, IsApplicable
| join avmodetable on DeviceId
| where AVMode != '0'
| project-away DeviceId1
""",
    # https://learn.microsoft.com/en-us/defender-endpoint/msda-updates-previous-versions-technical-upgrade-support
    "Defender version outdated": """DeviceTvmInfoGathering
| extend AdditionalFields = parse_json(AdditionalFields)
| extend AvPlatformVersion = tostring(AdditionalFields.["AvPlatformVersion"])
| where OSPlatform startswith "Windows"
| where parse_version(AvPlatformVersion) < parse_version("4.18.26020.3")
""",
}

out_report = ""
for title, q in queries.items():
    df_res = defender_prov.exec_query(q)
    out_report += f"## {title}\n\n"
    out_report += df_res.to_markdown()

print(out_report)
