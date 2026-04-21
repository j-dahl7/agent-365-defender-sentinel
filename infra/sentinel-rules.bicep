// Agent 365 Defender Lab - Sentinel analytics rules + workbook
// Deploy against your Sentinel-onboarded Log Analytics workspace.

targetScope = 'resourceGroup'

@description('Name of the Sentinel-onboarded Log Analytics workspace.')
param workspaceName string

// ---- Rule 1: Agent jailbreak burst (detected or blocked) ----

resource ruleJailbreakBurst 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/agent365-jailbreak-burst'
  properties: {
    displayName: 'LAB - Agent Jailbreak Attempts (burst)'
    description: 'Detects a burst of jailbreak attempts against a Foundry AI agent within 15 minutes. Correlates detected + blocked attempts.'
    severity: 'High'
    enabled: true
    query: '''
let lookback = 15m;
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, AlertSeverity:string, CompromisedEntity:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(lookback)
    | where AlertName has_any ("Jailbreak", "jailbreak")
        or AlertType in~ (
            "AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt",
            "AI.Azure_Jailbreak.ContentFiltering.DetectedAttempt",
            "AI.Azure_Agentic_Jailbreak",
            "Azure_Agentic_BlockedJailbreak",
            "AI.Azure_Agentic_BlockedJailbreak"
        ))
| summarize count(), make_set(AlertName), make_set(AlertType), arg_max(TimeGenerated, *) by CompromisedEntity
| where count_ >= 2
| project TimeGenerated, CompromisedEntity, AlertName, AlertType, AlertSeverity, AttemptCount=count_
'''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['DefenseEvasion', 'PrivilegeEscalation']
    techniques: ['T1548']
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    entityMappings: [
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

// ---- Rule 2: Indirect prompt injection / XPIA on agent ----

resource ruleXPIA 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/agent365-xpia-ascii-smuggling'
  properties: {
    displayName: 'LAB - Indirect Prompt Injection (XPIA/ASCII Smuggling) on AI Agent'
    description: 'Detects indirect prompt injection attempts targeting Foundry agents. Covers ASCII smuggling (invisible unicode) and malicious content embedded in RAG/tool data.'
    severity: 'High'
    enabled: true
    query: '''
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, AlertSeverity:string, CompromisedEntity:string, Description:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(1h)
    | where AlertName has_any ("ASCII smuggling", "ASCIISmuggling", "indirect prompt", "prompt injection")
        or AlertType in~ (
            "AI.Azure_ASCIISmuggling",
            "AI.Azure_Agentic_ASCIISmuggling",
            "AI.Azure_MaliciousUrl.ToolOutput",
            "AI.Azure_Agentic_MaliciousUrl.ToolOutput"
        ))
| project TimeGenerated, AlertName, AlertType, AlertSeverity, CompromisedEntity, Description
'''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['Impact']
    techniques: ['T1565']
    entityMappings: [
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

// ---- Rule 3: Instruction prompt leak / reconnaissance ----

resource ruleInstructionLeak 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/agent365-instruction-leak'
  properties: {
    displayName: 'LAB - AI Agent Instruction Leak / Reconnaissance'
    description: 'Correlates system-prompt leakage attempts with reconnaissance probes — common precursors to jailbreak or prompt-injection campaigns.'
    severity: 'Medium'
    enabled: true
    query: '''
let lookback = 1h;
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, CompromisedEntity:string, Description:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(lookback)
    | where AlertName has_any ("Instruction leak", "instruction leak", "InstructionLeakage", "LLM reconnaissance", "LLMReconnaissance", "reconnaissance probe")
        or AlertType in~ (
            "AI.Azure_InstructionLeakage",
            "AI.Azure_Agentic_InstructionLeakage",
            "AI.Azure_LLMReconaissance",
            "AI.Azure_Agentic_LLMReconaissance"
        ))
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
    techniques: ['T1590']
    entityMappings: [
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

// ---- Rule 4: Credential theft / sensitive data leak via agent ----

resource ruleCredentialLeak 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/agent365-credential-data-leak'
  properties: {
    displayName: 'LAB - AI Agent Exposed Credentials or Sensitive Data'
    description: 'Fires when Defender for AI detects credentials or sensitive data in agent responses — indicates model/tool compromise or prompt-injected exfiltration.'
    severity: 'High'
    enabled: true
    query: '''
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, AlertSeverity:string, CompromisedEntity:string, Description:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(1h)
    | where AlertName has_any ("credential theft", "CredentialTheftAttempt", "sensitive data", "SensitiveDataAnomaly")
        or AlertType in~ (
            "AI.Azure_CredentialTheftAttempt",
            "AI.Azure_SensitiveDataAnomaly",
            "AI.Azure_Agentic_SensitiveDataAnomaly"
        ))
| project TimeGenerated, AlertName, AlertType, AlertSeverity, CompromisedEntity, Description
'''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['CredentialAccess', 'Exfiltration']
    techniques: ['T1552', 'T1041']
    entityMappings: [
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

// ---- Rule 5: Anomalous tool invocation pattern ----

resource ruleAnomalousTool 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/agent365-anomalous-tool-invocation'
  properties: {
    displayName: 'LAB - AI Agent Anomalous Tool Invocation or Volume Anomaly'
    description: 'Detects tool abuse or wallet/DOW volume anomalies against a Foundry AI agent. May indicate prohibited-action exploitation or DDoS-style attack.'
    severity: 'Medium'
    enabled: true
    query: '''
union isfuzzy=true
  (datatable(TimeGenerated:datetime, AlertName:string, AlertType:string, AlertSeverity:string, CompromisedEntity:string, Description:string)[]),
  (SecurityAlert
    | where TimeGenerated > ago(1h)
    | where AlertName has_any ("anomalous tool", "AnomalousToolInvocation", "suspicious user agent", "anonymized IP", "DOW volume")
        or AlertType in~ (
            "AI.Azure_AnomalousToolInvocation",
            "AI.Azure_Agentic_DOWVolumeAnomaly",
            "AI.Azure_AccessFromSuspiciousUserAgent",
            "AI.Azure_AccessFromAnonymizedIP"
        ))
| project TimeGenerated, AlertName, AlertType, AlertSeverity, CompromisedEntity, Description
'''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: ['Execution', 'Impact']
    techniques: ['T1059']
    entityMappings: [
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'CompromisedEntity'
          }
        ]
      }
    ]
  }
}

output ruleCount int = 5
