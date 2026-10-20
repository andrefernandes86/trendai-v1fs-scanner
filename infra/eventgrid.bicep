targetScope = 'resourceGroup'
param storageAccountName string
param gatewayEndpoint string
param tenantId string
param apiApplicationId string
param container string
param blobPrefix string = ''
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: storageAccountName }
resource subscription 'Microsoft.EventGrid/eventSubscriptions@2022-06-15' = {
 name: 'v1fs-gateway-${container}'
 scope: storage
 properties: {
  destination: {
   endpointType: 'WebHook'
   properties: {endpointUrl: '${gatewayEndpoint}/api/eventgrid', azureActiveDirectoryTenantId: tenantId, azureActiveDirectoryApplicationIdOrUri: apiApplicationId, maxEventsPerBatch: 50, preferredBatchSizeInKilobytes: 256}
  }
  filter: {
   includedEventTypes: ['Microsoft.Storage.BlobCreated']
   subjectBeginsWith: '/blobServices/default/containers/${container}/blobs/${blobPrefix}'
   advancedFilters: [{operatorType: 'StringIn', key: 'data.api', values: ['PutBlob','PutBlockList','FlushWithClose','SftpCommit','CopyBlob']}]
  }
  retryPolicy: {maxDeliveryAttempts: 30, eventTimeToLiveInMinutes: 1440}
 }
}
