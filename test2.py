import base64
import json
from typing import Optional, Dict, Any
from enum import Enum
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


class PrivacyLevel(Enum):
    NONE = "None"
    PRIVATE = "Private"
    ORGANIZATIONAL = "Organizational"
    PUBLIC = "Public"


class EncryptedConnection(Enum):
    ENCRYPTED = "Encrypted"
    NOT_ENCRYPTED = "NotEncrypted"


class CredentialType(Enum):
    BASIC = "Basic"
    WINDOWS = "Windows"
    OAUTH2 = "OAuth2"
    ANONYMOUS = "Anonymous"


class BasicCredentials:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.credential_type = CredentialType.BASIC

    def to_dict(self) -> Dict[str, Any]:
        return {
            "credentialType": self.credential_type.value,
            "basicCredentials": {
                "username": self.username,
                "password": self.password
            }
        }


class WindowsCredentials:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.credential_type = CredentialType.WINDOWS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "credentialType": self.credential_type.value,
            "windowsCredentials": {
                "username": self.username,
                "password": self.password
            }
        }


class OAuth2Credentials:
    def __init__(self, access_token: str):
        self.access_token = access_token
        self.credential_type = CredentialType.OAUTH2

    def to_dict(self) -> Dict[str, Any]:
        return {
            "credentialType": self.credential_type.value,
            "oAuth2Credentials": {
                "accessToken": self.access_token
            }
        }


class AnonymousCredentials:
    def __init__(self):
        self.credential_type = CredentialType.ANONYMOUS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "credentialType": self.credential_type.value
        }


class AsymmetricKeyEncryptor:
    def __init__(self, public_key_pem: str):
        self.public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )

    def encrypt_credentials(self, credentials) -> str:
        credentials_json = json.dumps(credentials.to_dict())
        encrypted_data = self.public_key.encrypt(
            credentials_json.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_data).decode('utf-8')


class CredentialDetails:
    def __init__(self, credentials, privacy_level: PrivacyLevel, 
                 encrypted_connection: EncryptedConnection, 
                 encryptor: Optional[AsymmetricKeyEncryptor] = None):
        self.credentials = credentials
        self.privacy_level = privacy_level
        self.encrypted_connection = encrypted_connection
        self.encryptor = encryptor

    def to_dict(self) -> Dict[str, Any]:
        if self.encryptor:
            encrypted_credentials = self.encryptor.encrypt_credentials(self.credentials)
            return {
                "credentialDetails": {
                    "credentials": encrypted_credentials,
                    "privacyLevel": self.privacy_level.value,
                    "encryptedConnection": self.encrypted_connection.value
                }
            }
        else:
            return {
                "credentialDetails": {
                    "credentials": self.credentials.to_dict(),
                    "privacyLevel": self.privacy_level.value,
                    "encryptedConnection": self.encrypted_connection.value
                }
            }


class PowerBICredentialManager:
    def __init__(self, pbi_client):
        self.pbi_client = pbi_client

    def get_datasources(self, dataset_id: str):
        """Equivalent to: var datasources = pbiClient.Datasets.GetDatasources(datasetId).Value;"""
        try:
            response = self.pbi_client.datasets.get_datasources(dataset_id)
            return response.get('value', [])
        except Exception as e:
            print(f"Error getting datasources: {e}")
            return []

    def get_first_datasource(self, dataset_id: str):
        """Equivalent to: var datasource = datasources.First();"""
        datasources = self.get_datasources(dataset_id)
        return datasources[0] if datasources else None

    def get_gateway(self, gateway_id: str):
        """Equivalent to: var gateway = pbiClient.Gateways.GetGatewayById(datasource.GatewayId);"""
        try:
            return self.pbi_client.gateways.get_gateway_by_id(gateway_id)
        except Exception as e:
            print(f"Error getting gateway: {e}")
            return None

    def create_encryptor(self, public_key: str) -> AsymmetricKeyEncryptor:
        """Equivalent to: var credentialsEncryptor = new AsymmetricKeyEncryptor(gateway.publicKey);"""
        return AsymmetricKeyEncryptor(public_key)

    def update_datasource_credentials(self, gateway_id: str, datasource_id: str, 
                                    credential_details: CredentialDetails):
        """Equivalent to: pbiClient.Gateways.UpdateDatasource(...)"""
        try:
            update_request = credential_details.to_dict()
            return self.pbi_client.gateways.update_datasource(
                gateway_id, datasource_id, update_request
            )
        except Exception as e:
            print(f"Error updating datasource: {e}")
            return None


def example_usage():
    """Example usage demonstrating the converted .NET code functionality"""
    
    # Mock Power BI client (replace with actual client implementation)
    class MockPBIClient:
        class Datasets:
            def get_datasources(self, dataset_id):
                return {"value": [{"gatewayId": "gateway123", "datasourceId": "ds456"}]}
        
        class Gateways:
            def get_gateway_by_id(self, gateway_id):
                return {"publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}
            
            def update_datasource(self, gateway_id, datasource_id, request):
                print(f"Updated datasource {datasource_id} in gateway {gateway_id}")
                return {"success": True}
        
        def __init__(self):
            self.datasets = self.Datasets()
            self.gateways = self.Gateways()

    # Initialize client and manager
    pbi_client = MockPBIClient()
    credential_manager = PowerBICredentialManager(pbi_client)
    
    dataset_id = "your-dataset-id"
    
    # 1. Discover data sources
    datasources = credential_manager.get_datasources(dataset_id)
    datasource = credential_manager.get_first_datasource(dataset_id)
    
    if not datasource:
        print("No datasources found")
        return
    
    # 2. Get gateway
    gateway = credential_manager.get_gateway(datasource["gatewayId"])
    
    if not gateway:
        print("Gateway not found")
        return
    
    # 3. Create credentials (choose one type)
    
    # Basic credentials
    credentials = BasicCredentials(username="username", password="password123")
    
    # Windows credentials
    # credentials = WindowsCredentials(username="domain\\user", password="password123")
    
    # OAuth2 credentials
    # credentials = OAuth2Credentials("your-oauth-token")
    
    # Anonymous credentials
    # credentials = AnonymousCredentials()
    
    # 4. Create encryptor
    encryptor = credential_manager.create_encryptor(gateway["publicKey"])
    
    # 5. Create credential details
    credential_details = CredentialDetails(
        credentials=credentials,
        privacy_level=PrivacyLevel.PRIVATE,
        encrypted_connection=EncryptedConnection.ENCRYPTED,
        encryptor=encryptor
    )
    
    # 6. Update data source credentials
    result = credential_manager.update_datasource_credentials(
        gateway_id=datasource["gatewayId"],
        datasource_id=datasource["datasourceId"],
        credential_details=credential_details
    )
    
    print("Credentials update completed:", result)


if __name__ == "__main__":
    example_usage()
