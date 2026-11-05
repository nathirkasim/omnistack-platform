param location string = 'eastus'

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'open-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAllInbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}
