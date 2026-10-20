targetScope = 'resourceGroup'
param location string = resourceGroup().location
param prefix string = 'v1fs'
@description('Immutable image reference in a registry reachable by Container Apps. Use a digest.')
param image string
param tenantId string
param apiAudience string
param consoleOrigin string
param trendRegion string = 'us-east-1'
@secure()
param databasePassword string
@secure()
param trendApiKey string
param databaseAdmin string = 'gatewayadmin'
param maxWorkerReplicas int = 10
var suffix = uniqueString(resourceGroup().id)
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
 name: '${prefix}-identity'
 location: location
}
resource network 'Microsoft.Network/virtualNetworks@2024-05-01' = {
 name: '${prefix}-network'
 location: location
 properties: {
  addressSpace: { addressPrefixes: ['10.30.0.0/16'] }
  subnets: [
   { name: 'apps', properties: { addressPrefix: '10.30.0.0/23', delegations: [{ name: 'containerapps', properties: { serviceName: 'Microsoft.App/environments' } }] } }
   { name: 'postgres', properties: { addressPrefix: '10.30.2.0/24', delegations: [{ name: 'postgres', properties: { serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers' } }] } }
   { name: 'endpoints', properties: { addressPrefix: '10.30.3.0/24', privateEndpointNetworkPolicies: 'Disabled' } }
  ]
 }
}
resource pgDns 'Microsoft.Network/privateDnsZones@2024-06-01' = {name: '${prefix}.postgres.database.azure.com', location: 'global'}
resource pgLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
 parent: pgDns
 name: 'gateway-network'
 location: 'global'
 properties: { virtualNetwork: {id: network.id}, registrationEnabled: false }
}
resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
 name: '${prefix}-pg-${suffix}'
 location: location
 sku: {name: 'Standard_D2ds_v5', tier: 'GeneralPurpose'}
 properties: {
  version: '17'
  administratorLogin: databaseAdmin
  administratorLoginPassword: databasePassword
  storage: {storageSizeGB: 128}
  backup: {backupRetentionDays: 14, geoRedundantBackup: 'Enabled'}
  highAvailability: {mode: 'ZoneRedundant'}
  network: {delegatedSubnetResourceId: '${network.id}/subnets/postgres', privateDnsZoneArmResourceId: pgDns.id, publicNetworkAccess: 'Disabled'}
 }
 dependsOn: [pgLink]
}
resource db 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
 parent: postgres
 name: 'gateway'
 properties: {charset: 'UTF8', collation: 'en_US.utf8'}
}
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
 name: '${prefix}-logs'
 location: location
 properties: {sku: {name: 'PerGB2018'}, retentionInDays: 30}
}
resource insights 'Microsoft.Insights/components@2020-02-02' = {
 name: '${prefix}-insights'
 location: location
 kind: 'web'
 properties: {Application_Type: 'web', WorkspaceResourceId: logs.id}
}
resource env 'Microsoft.App/managedEnvironments@2025-01-01' = {
 name: '${prefix}-environment'
 location: location
 properties: {
  vnetConfiguration: {infrastructureSubnetId: '${network.id}/subnets/apps', internal: false}
  workloadProfiles: [{name: 'Consumption', workloadProfileType: 'Consumption'}]
  appLogsConfiguration: {destination: 'log-analytics', logAnalyticsConfiguration: {customerId: logs.properties.customerId, sharedKey: logs.listKeys().primarySharedKey}}
  zoneRedundant: true
 }
}
resource bus 'Microsoft.ServiceBus/namespaces@2024-01-01' = {
 name: '${prefix}-bus-${suffix}'
 location: location
 sku: {name: 'Premium', tier: 'Premium', capacity: 1}
 properties: {disableLocalAuth: true, publicNetworkAccess: 'Disabled', minimumTlsVersion: '1.2'}
}
resource queues 'Microsoft.ServiceBus/namespaces/queues@2024-01-01' = [for q in ['scan','promote','quarantine','retry','deadletter']:{
 parent: bus
 name: 'v1fs-${q}'
 properties: {requiresDuplicateDetection: true, duplicateDetectionHistoryTimeWindow: 'PT10M', lockDuration: 'PT1M', maxDeliveryCount: 10, deadLetteringOnMessageExpiration: true, defaultMessageTimeToLive: 'P14D', enablePartitioning: false}
}]
resource busRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
 name: guid(bus.id,identity.id,'bus-owner')
 scope: bus
 properties: {roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions','090c5cfd-751d-490a-894a-3ce6f1109419'), principalId: identity.properties.principalId, principalType: 'ServicePrincipal'}
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
 name: '${prefix}-kv-${suffix}'
 location: location
 properties: {tenantId: subscription().tenantId, sku: {family: 'A', name: 'standard'}, enableRbacAuthorization: true, enableSoftDelete: true, softDeleteRetentionInDays: 90, enablePurgeProtection: true, publicNetworkAccess: 'Disabled'}
}
resource trendSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = { parent: vault, name: 'trend-api-key', properties: {value: trendApiKey} }
resource dbSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
 parent: vault
 name: 'database-url'
 properties: {value: 'postgres://${databaseAdmin}:${uriComponent(databasePassword)}@${postgres.properties.fullyQualifiedDomainName}:5432/gateway?sslmode=verify-full'}
}
resource vaultRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
 name: guid(vault.id,identity.id,'secret-reader')
 scope: vault
 properties: {roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions','4633458b-17de-408a-b874-0445c86b69e6'), principalId: identity.properties.principalId, principalType: 'ServicePrincipal'}
}
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
 name: 'v1fs${suffix}'
 location: location
 sku: {name: 'Standard_ZRS'}
 kind: 'StorageV2'
 properties: {allowBlobPublicAccess: false, allowSharedKeyAccess: false, supportsHttpsTrafficOnly: true, minimumTlsVersion: 'TLS1_2', publicNetworkAccess: 'Disabled'}
}
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {parent: storage, name: 'default', properties: {isVersioningEnabled: true, deleteRetentionPolicy: {enabled: true, days: 14}}}
resource containers 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = [for name in ['safe','quarantine','hold']:{parent: blobService, name: name, properties: {publicAccess: 'None'}}]
resource storageRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
 name: guid(storage.id,identity.id,'blob-writer')
 scope: storage
 properties: {roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions','ba92f5b4-2d11-453d-a403-e96b0029c9fe'), principalId: identity.properties.principalId, principalType: 'ServicePrincipal'}
}
var endpoints = [
 {name: 'bus', id: bus.id, group: 'namespace', zone: 'privatelink.servicebus.windows.net'}
 {name: 'vault', id: vault.id, group: 'vault', zone: 'privatelink.vaultcore.azure.net'}
 {name: 'storage', id: storage.id, group: 'blob', zone: 'privatelink.blob.core.windows.net'}
]
resource dns 'Microsoft.Network/privateDnsZones@2024-06-01' = [for endpoint in endpoints:{name: endpoint.zone, location: 'global'}]
resource links 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [for (endpoint,i) in endpoints:{name: '${dns[i].name}/gateway-network', location: 'global', properties: {virtualNetwork: {id: network.id}, registrationEnabled: false}}]
resource pe 'Microsoft.Network/privateEndpoints@2024-05-01' = [for endpoint in endpoints:{name: '${prefix}-${endpoint.name}-endpoint', location: location, properties: {subnet: {id: '${network.id}/subnets/endpoints'}, privateLinkServiceConnections: [{name: endpoint.name, properties: {privateLinkServiceId: endpoint.id, groupIds: [endpoint.group]}}]}}]
resource zoneGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = [for (endpoint,i) in endpoints:{name: '${pe[i].name}/default', properties: {privateDnsZoneConfigs: [{name: 'default', properties: {privateDnsZoneId: dns[i].id}}]}}]
var modes = ['api','dispatch','scan','promote','quarantine','retry','reconcile']
resource apps 'Microsoft.App/containerApps@2025-01-01' = [for mode in modes:{
 name: '${prefix}-${mode}'
 location: location
 identity: {type: 'UserAssigned', userAssignedIdentities: {'${identity.id}': {}}}
 properties: {
  managedEnvironmentId: env.id
  workloadProfileName: 'Consumption'
  configuration: {
   activeRevisionsMode: 'Single'
   ingress: mode == 'api' ? {external: true, targetPort: 8080, transport: 'http', allowInsecure: false} : null
   secrets: [
    {name: 'database-url', keyVaultUrl: '${vault.properties.vaultUri}secrets/database-url', identity: identity.id}
    {name: 'trend-key', keyVaultUrl: '${vault.properties.vaultUri}secrets/trend-api-key', identity: identity.id}
   ]
  }
  template: {
   containers: [{name: 'gateway', image: image, resources: {cpu: 1, memory: '2Gi'}, env: [
    {name: 'MODE', value: mode}
    {name: 'DATABASE_URL', secretRef: 'database-url'}
    {name: 'TM_AM_AUTH_KEY', secretRef: 'trend-key'}
    {name: 'TM_REGION', value: trendRegion}
    {name: 'ENVIRONMENT', value: 'production'}
    {name: 'SIMULATED_SCANNER', value: 'false'}
    {name: 'AZURE_CLIENT_ID', value: identity.properties.clientId}
    {name: 'SERVICEBUS_NAMESPACE', value: '${bus.name}.servicebus.windows.net'}
    {name: 'ENTRA_ISSUER', value: 'https://login.microsoftonline.com/${tenantId}/v2.0'}
    {name: 'ENTRA_AUDIENCE', value: apiAudience}
    {name: 'CONSOLE_ORIGIN', value: consoleOrigin}
   ]}]
   scale: {
    minReplicas: mode == 'api' ? 2 : 1
    maxReplicas: mode == 'api' ? 5 : maxWorkerReplicas
    rules: contains(['scan','promote','quarantine','retry'],mode) ? [{name: 'queue', custom: {type: 'azure-servicebus', metadata: {namespace: bus.name, queueName: 'v1fs-${mode}', messageCount: '10'}, identity: identity.id}}] : []
   }
  }
 }
 dependsOn: [vaultRole,busRole,storageRole,trendSecret,dbSecret,zoneGroups]
}]
output apiUrl string = 'https://${apps[0].properties.configuration.ingress.fqdn}'
output workerIdentityPrincipalId string = identity.properties.principalId
output destinationStorageAccount string = storage.name
output databaseHost string = postgres.properties.fullyQualifiedDomainName
output serviceBusNamespace string = bus.name
