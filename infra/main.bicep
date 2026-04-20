// Agent 365 Defender Lab - Foundry project with hosted AI agent, Defender for AI enabled
// Companion to blog: "AI Agents Are Running in Containers. Here's the Defender Playbook."
//
// Defender for AI Services plan is configured at subscription scope (see deploy-lab.sh).

targetScope = 'resourceGroup'

@description('Deployment location. Foundry hosted agents require specific regions; eastus2 is recommended.')
param location string = 'eastus2'

@description('Short suffix appended to resource names for uniqueness.')
param suffix string = uniqueString(resourceGroup().id)

@description('Log Analytics workspace resource ID for Sentinel correlation.')
param sentinelWorkspaceId string

@description('Object ID of the lab operator - gets Foundry project Owner.')
param operatorObjectId string

var hubName = 'agent365hub${take(suffix, 6)}'
var projectName = 'agent365proj${take(suffix, 6)}'
var aiServicesName = 'agent365ais${take(suffix, 6)}'
var storageName = 'agent365sa${take(suffix, 8)}'
var kvName = 'agent365kv${take(suffix, 8)}'
var appInsightsName = 'agent365ai-${take(suffix, 6)}'
var acrName = 'agent365acr${take(suffix, 8)}'

// ---- Core dependencies ----

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowSharedKeyAccess: true
  }
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: sentinelWorkspaceId
  }
}

// Basic tier is sufficient for this lab. The ACR is scaffolding for the future
// hosted-agent container path; the current attack loop talks to Azure OpenAI
// chat completions directly and does not pull any images from this registry.
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: acrName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}

// ---- AI Services (OpenAI) ----

resource aiServices 'Microsoft.CognitiveServices/accounts@2024-10-01' = {
  name: aiServicesName
  location: location
  kind: 'AIServices'
  sku: {
    name: 'S0'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    customSubDomainName: aiServicesName
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: false
  }
}

resource modelDeployment 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: aiServices
  name: 'gpt-4-1-mini'
  sku: {
    name: 'Standard'
    capacity: 50
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-4.1-mini'
      version: '2025-04-14'
    }
  }
}

resource aiServicesDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'agent365-ai-services-to-sentinel'
  scope: aiServices
  properties: {
    workspaceId: sentinelWorkspaceId
    // AI Services diagnostic logs land in the shared AzureDiagnostics table. The
    // logAnalyticsDestinationType: 'Dedicated' mode (resource-specific tables) is
    // not currently supported for Microsoft.CognitiveServices accounts; server-side
    // the property accepts but does not persist.
    logs: [
      {
        category: 'Audit'
        enabled: true
      }
      {
        category: 'RequestResponse'
        enabled: true
      }
      {
        category: 'AzureOpenAIRequestUsage'
        enabled: true
      }
      {
        category: 'Trace'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// ---- Foundry Hub + Project ----

resource hub 'Microsoft.MachineLearningServices/workspaces@2024-10-01' = {
  name: hubName
  location: location
  kind: 'Hub'
  identity: {
    type: 'SystemAssigned'
  }
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
  properties: {
    friendlyName: 'Agent 365 Lab Hub'
    storageAccount: storage.id
    keyVault: kv.id
    applicationInsights: appInsights.id
    containerRegistry: acr.id
    publicNetworkAccess: 'Enabled'
    managedNetwork: {
      isolationMode: 'Disabled'
    }
  }
}

resource project 'Microsoft.MachineLearningServices/workspaces@2024-10-01' = {
  name: projectName
  location: location
  kind: 'Project'
  identity: {
    type: 'SystemAssigned'
  }
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
  properties: {
    friendlyName: 'Agent 365 Lab Project'
    hubResourceId: hub.id
    publicNetworkAccess: 'Enabled'
  }
}

// ---- RBAC: operator owns the project, project pulls ACR ----

resource ownerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(project.id, operatorObjectId, 'AzureMLDataScientist')
  scope: project
  properties: {
    principalId: operatorObjectId
    // Azure ML Data Scientist - can run experiments and create agents
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'f6c7c914-8db3-469d-8ca1-694a8f32e121')
    principalType: 'User'
  }
}

resource acrPullProject 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, project.id, 'AcrPull')
  scope: acr
  properties: {
    principalId: project.identity.principalId
    // AcrPull
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
    principalType: 'ServicePrincipal'
  }
}

resource openAIUserProject 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(aiServices.id, project.id, 'CognitiveServicesOpenAIUser')
  scope: aiServices
  properties: {
    principalId: project.identity.principalId
    // Cognitive Services OpenAI User
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd')
    principalType: 'ServicePrincipal'
  }
}

resource openAIUserOperator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(aiServices.id, operatorObjectId, 'CognitiveServicesOpenAIUser')
  scope: aiServices
  properties: {
    principalId: operatorObjectId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd')
    principalType: 'User'
  }
}

// ---- Outputs ----

output hubId string = hub.id
output projectId string = project.id
output projectName string = project.name
output projectEndpoint string = 'https://${aiServices.name}.services.ai.azure.com/api/projects/${project.name}'
output aiServicesEndpoint string = aiServices.properties.endpoint
output aiServicesName string = aiServices.name
output openAIDeploymentName string = modelDeployment.name
output acrLoginServer string = acr.properties.loginServer
output appInsightsConnectionString string = appInsights.properties.ConnectionString
