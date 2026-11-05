param location string = 'eastus'

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'corpinsecurestorage2026'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
  }
}
