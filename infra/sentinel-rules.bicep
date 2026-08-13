// Agent 365-era lab - current Defender for AI Services model/application alerts.
// Deploy against your Sentinel-onboarded Log Analytics workspace.
//
// These rules intentionally exclude the retired AI.Azure_Agentic_* contract.
// Agent-level protection moved to Agent 365 observability and Defender XDR on
// July 1, 2026; this template has no supported way to configure that service.

targetScope = 'resourceGroup'

@description('Name of the Sentinel-onboarded Log Analytics workspace.')
param workspaceName string

@description('Stable owner marker verified by deploy and cleanup scripts.')
@minLength(1)
param ownerMarker string

@description('Deployment identifier recorded in the local provenance manifest and resource-group tag.')
@minLength(16)
param deploymentId string

var ownershipSuffix = '[Owner: ${ownerMarker}; Deployment: ${deploymentId}]'

// ---- Rule 1: Azure AI model jailbreak burst (detected or blocked) ----

resource ruleJailbreakBurst 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/ai-model-jailbreak-burst'
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Azure AI Model Jailbreak Attempts (burst)'
    description: 'Correlates documented Defender for AI Services blocked and detected jailbreak alerts for an Azure AI model deployment. ${ownershipSuffix}'
    severity: 'Medium'
    enabled: true
    query: '''
let lookback = 15m;
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, AlertSeverity:string, CompromisedEntity:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(lookback)
    | where ProviderName != "ASI Scheduled Alerts"
    | where AlertType in~ (
            "AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt",
            "AI.Azure_Jailbreak.ContentFiltering.DetectedAttempt"
        ))
| summarize count(), make_set(AlertName), make_set(AlertType), arg_max(TimeGenerated, *) by CompromisedEntity
| where count_ >= 2
| project TimeGenerated, CompromisedEntity, AlertName, AlertType, AlertSeverity, AttemptCount=count_
'''
    // Run every 5 minutes over a 15-minute window so consecutive evaluations
    // overlap. At PT15M/PT15M the windows are adjacent, so a burst split across
    // a boundary lands as one alert per window and never reaches count_ >= 2.
    queryFrequency: 'PT5M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['DefenseEvasion', 'PrivilegeEscalation']
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    entityMappings: [
      {
        entityType: 'AzureResource'
        fieldMappings: [
          {
            identifier: 'ResourceId'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

// ---- Rule 2: ASCII smuggling against an Azure AI model deployment ----

resource ruleAsciiSmuggling 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/ai-model-ascii-smuggling'
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Azure AI Model ASCII Smuggling'
    description: 'Matches the documented Defender for AI Services ASCII-smuggling alert for an Azure AI model deployment. ${ownershipSuffix}'
    severity: 'High'
    enabled: true
    query: '''
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, AlertSeverity:string, CompromisedEntity:string, Description:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(1h)
    | where ProviderName != "ASI Scheduled Alerts"
    | where AlertType =~ "AI.Azure_ASCIISmuggling")
| project TimeGenerated, AlertName, AlertType, AlertSeverity, CompromisedEntity, Description
'''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['Impact']
    entityMappings: [
      {
        entityType: 'AzureResource'
        fieldMappings: [
          {
            identifier: 'ResourceId'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

// ---- Rule 3: LLM reconnaissance against an Azure AI model deployment ----

resource ruleLlmReconnaissance 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/ai-model-llm-reconnaissance'
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Azure AI Model LLM Reconnaissance'
    description: 'Correlates repeated documented Defender for AI Services LLM reconnaissance alerts for an Azure AI model deployment. ${ownershipSuffix}'
    severity: 'Low'
    enabled: true
    query: '''
let lookback = 1h;
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, CompromisedEntity:string, Description:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(lookback)
    | where ProviderName != "ASI Scheduled Alerts"
    | where AlertType =~ "AI.Azure_LLMReconnaissance")
| summarize AttemptCount=count(), make_set(AlertName), make_set(AlertType), arg_max(TimeGenerated, *) by CompromisedEntity
| where AttemptCount >= 2
| project TimeGenerated, CompromisedEntity, AlertName, AlertType, AttemptCount, Description
'''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['Reconnaissance']
    entityMappings: [
      {
        entityType: 'AzureResource'
        fieldMappings: [
          {
            identifier: 'ResourceId'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

// ---- Rule 4: Credential theft in an Azure AI model response ----

resource ruleCredentialTheft 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/ai-model-credential-theft'
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Azure AI Model Credential Theft'
    description: 'Matches the documented Defender for AI Services credential-theft alert for credentials detected in an Azure AI model response. ${ownershipSuffix}'
    severity: 'Medium'
    enabled: true
    query: '''
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, AlertSeverity:string, CompromisedEntity:string, Description:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(1h)
    | where ProviderName != "ASI Scheduled Alerts"
    | where AlertType =~ "AI.Azure_CredentialTheftAttempt")
| project TimeGenerated, AlertName, AlertType, AlertSeverity, CompromisedEntity, Description
'''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['CredentialAccess', 'LateralMovement', 'Exfiltration']
    entityMappings: [
      {
        entityType: 'AzureResource'
        fieldMappings: [
          {
            identifier: 'ResourceId'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

// ---- Rule 5: Documented Azure AI application/model activity anomalies ----

resource ruleAnomalousActivity 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/ai-model-anomalous-activity'
  kind: 'Scheduled'
  properties: {
    displayName: 'LAB - Azure AI Model/Application Anomalous Activity'
    description: 'Matches documented Defender for AI Services tool-invocation, wallet-abuse, and access-anomaly alerts for an Azure AI application or model deployment. ${ownershipSuffix}'
    severity: 'Medium'
    enabled: true
    query: '''
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, AlertSeverity:string, CompromisedEntity:string, Description:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(1h)
    | where ProviderName != "ASI Scheduled Alerts"
    | where AlertType in~ (
            "AI.Azure_AnomalousToolInvocation",
            "AI.Azure_DOWDuplicateRequests",
            "AI.Azure_DOWVolumeAnomaly",
            "AI.Azure_AccessFromSuspiciousUserAgent",
            "AI.Azure_AccessFromAnonymizedIP",
            "AI.Azure_AccessFromSuspiciousIP",
            "AI.Azure_AccessAnomaly"
        ))
| project TimeGenerated, AlertName, AlertType, AlertSeverity, CompromisedEntity, Description
'''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['Execution', 'Reconnaissance', 'InitialAccess', 'Impact']
    entityMappings: [
      {
        entityType: 'AzureResource'
        fieldMappings: [
          {
            identifier: 'ResourceId'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

output ruleCount int = 5
