from azure.identity import DefaultAzureCredential
from azure.mgmt.datafactory import DataFactoryManagementClient
import requests
import time
import json

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

    def get_integration_runtime_status(self, ir_name):
        """
        Get the status of an integration runtime
        Returns True if interactive authoring is enabled, False otherwise
        """
        try:
            # Get access token
            token = self.credential.get_token("https://management.azure.com/.default").token
            
            # Construct the API URL
            ir_resource_id = f"subscriptions/{self.subscription_id}/resourcegroups/{self.resource_group_name}/providers/Microsoft.DataFactory/factories/{self.factory_name}/integrationruntimes/{ir_name}"
            api_url = f"https://management.azure.com/{ir_resource_id}/getStatus?api-version=2018-06-01"
            
            # Make the API call
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(api_url, headers=headers)
            response.raise_for_status()
            
            status_data = response.json()
            interactive_status = status_data.get("properties", {}).get("typeProperties", {}).get("interactiveQuery", {}).get("status")
            
            is_enabled = interactive_status == "Enabled"
            print(f"Integration runtime {ir_name} interactive authoring status: {'Enabled' if is_enabled else 'Disabled'}")
            return is_enabled
        except Exception as e:
            print(f"Error getting integration runtime status: {str(e)}")
            raise

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
            # First check if interactive authoring is already enabled
            if self.get_integration_runtime_status(ir_name):
                print(f"Interactive authoring is already enabled for integration runtime {ir_name}")
                return
            
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
            
            # Verify the status after enabling
            if self.get_integration_runtime_status(ir_name):
                print("Interactive authoring was successfully enabled")
            else:
                print("Warning: Interactive authoring status check failed after enabling")
            
            return response.json()
        except Exception as e:
            print(f"Error enabling interactive authoring: {str(e)}")
            raise

    def get_linked_service_details(self, linked_service_name):
        """
        Get the details of a linked service
        """
        try:
            # Get access token
            token = self.credential.get_token("https://management.azure.com/.default").token
            
            # Construct the API URL
            api_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourcegroups/{self.resource_group_name}/providers/Microsoft.DataFactory/factories/{self.factory_name}/linkedservices/{linked_service_name}?api-version=2018-06-01"
            
            # Make the API call
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            print(f"Error getting linked service details: {str(e)}")
            raise

    def test_linked_service_connection(self, linked_service_name, parameters=None):
        """
        Test the connection of a linked service
        """
        try:
            # Get access token
            token = self.credential.get_token("https://management.azure.com/.default").token
            
            # First get the linked service details
            linked_service = self.get_linked_service_details(linked_service_name)
            
            # If parameters are provided, update the linked service properties
            if parameters:
                linked_service["properties"]["parameters"] = parameters
            
            # Construct the test connectivity request body
            body = {
                "linkedService": linked_service
            }
            
            # Construct the API URL
            api_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourcegroups/{self.resource_group_name}/providers/Microsoft.DataFactory/factories/{self.factory_name}/testConnectivity?api-version=2018-06-01"
            
            # Make the API call
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            print("Testing linked service connection with the following configuration:")
            print(json.dumps(body, indent=2))
            
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
        # You can optionally provide parameters for the linked service
        parameters = {
            "param1": "value1",
            "param2": "value2"
        }
        adf_ops.test_linked_service_connection(
            linked_service_name="your-linked-service-name",
            parameters=parameters  # Optional
        )
        
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main() 
