from azure.identity import DefaultAzureCredential
from azure.mgmt.datafactory import DataFactoryManagementClient
import requests
import time

class ADFOperations:
    def __init__(self, subscription_id, resource_group_name, factory_name):
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.factory_name = factory_name
        self.credential = DefaultAzureCredential()
        self.client = DataFactoryManagementClient(
            credential=self.credential,
            subscription_id=subscription_id
        )

    def update_managed_private_endpoint_fqdn(self, managed_vnet_name, managed_private_endpoint_name, fqdns, group_id, private_link_resource_id):
        """
        Update the FQDN in a managed private endpoint
        """
        try:
            response = self.client.managed_private_endpoints.create_or_update(
                resource_group_name=self.resource_group_name,
                factory_name=self.factory_name,
                managed_virtual_network_name=managed_vnet_name,
                managed_private_endpoint_name=managed_private_endpoint_name,
                managed_private_endpoint={
                    "properties": {
                        "fqdns": fqdns,
                        "groupId": group_id,
                        "privateLinkResourceId": private_link_resource_id,
                    }
                },
            )
            print(f"Successfully updated managed private endpoint: {managed_private_endpoint_name}")
            return response
        except Exception as e:
            print(f"Error updating managed private endpoint: {str(e)}")
            raise

    def enable_interactive_authoring(self, ir_name, minutes=10):
        """
        Enable interactive authoring for the specified integration runtime
        """
        try:
            # Get access token
            token = self.credential.get_token("https://management.azure.com/.default").token
            
            # Construct the API URL
            ir_resource_id = f"subscriptions/{self.subscription_id}/resourcegroups/{self.resource_group_name}/providers/Microsoft.DataFactory/factories/{self.factory_name}/integrationruntimes/{ir_name}"
            api_url = f"https://management.azure.com/{ir_resource_id}/enableInteractiveQuery?api-version=2018-06-01"
            
            # Make the API call
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            body = {"autoTerminationMinutes": minutes}
            
            response = requests.post(api_url, headers=headers, json=body)
            response.raise_for_status()
            
            print(f"Successfully enabled interactive authoring for {minutes} minutes")
            return response.json()
        except Exception as e:
            print(f"Error enabling interactive authoring: {str(e)}")
            raise

    def test_linked_service_connection(self, linked_service_name):
        """
        Test the connection of a linked service
        """
        try:
            # Get access token
            token = self.credential.get_token("https://management.azure.com/.default").token
            
            # Construct the API URL
            api_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourcegroups/{self.resource_group_name}/providers/Microsoft.DataFactory/factories/{self.factory_name}/testConnectivity?api-version=2018-06-01"
            
            # Make the API call
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            body = {
                "linkedServiceName": linked_service_name
            }
            
            response = requests.post(api_url, headers=headers, json=body)
            response.raise_for_status()
            
            result = response.json()
            if result.get("succeeded"):
                print("Linked service connection test successful")
            else:
                print(f"Linked service connection test failed: {result.get('errors', [{}])[0].get('message', 'Unknown error')}")
            
            return result
        except Exception as e:
            print(f"Error testing linked service connection: {str(e)}")
            raise

def main():
    # Initialize with your Azure credentials and ADF details
    subscription_id = "your-subscription-id"
    resource_group_name = "your-resource-group"
    factory_name = "your-factory-name"
    
    adf_ops = ADFOperations(subscription_id, resource_group_name, factory_name)
    
    # Example usage:
    try:
        # 1. Update managed private endpoint FQDN
        adf_ops.update_managed_private_endpoint_fqdn(
            managed_vnet_name="your-managed-vnet",
            managed_private_endpoint_name="your-private-endpoint",
            fqdns=["your.fqdn.com"],
            group_id="blob",
            private_link_resource_id="/subscriptions/your-subscription-id/resourceGroups/your-resource-group/providers/Microsoft.Storage/storageAccounts/your-storage-account"
        )
        
        # 2. Enable interactive authoring
        adf_ops.enable_interactive_authoring(
            ir_name="your-ir-name",
            minutes=10
        )
        
        # 3. Test linked service connection
        adf_ops.test_linked_service_connection(
            linked_service_name="your-linked-service-name"
        )
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main() 