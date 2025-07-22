import requests
from datetime import datetime, timedelta
from pathlib import Path
from .azure_keyvault import KeyVaultClient
import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hmac
from cryptography.hazmat.backends import default_backend
import time

akv = KeyVaultClient("kmxdapeaihubstg")
client_id = akv.get_secret_value_if_exists("fabric-spn-client-id")
client_secret = akv.get_secret_value_if_exists("fabric-spn-client-secret")
tenant_id = akv.get_secret_value_if_exists("fabric-spn-client-tenant")


class PowerBIGatewayEncryptor:
    """Handles encryption of credentials for Power BI gateway datasources"""
    
    MODULUS_SIZE_1024 = 128
    SEGMENT_SIZE = 60  # For 1024-bit keys
    ENCRYPTED_LENGTH = 128  # For 1024-bit keys
    MAX_ATTEMPTS = 3
    
    def __init__(self, gateway_public_key):
        """
        Initialize encryptor with gateway public key
        
        Args:
            gateway_public_key (dict): Gateway public key with 'modulus' and 'exponent'
        """
        if not gateway_public_key or not gateway_public_key.get('modulus') or not gateway_public_key.get('exponent'):
            raise ValueError("Invalid gateway public key")
            
        self.public_key = gateway_public_key
    
    def encrypt_credentials(self, credentials_json):
        """
        Encrypt credentials using appropriate method based on key size
        
        Args:
            credentials_json (str): JSON string of credentials to encrypt
            
        Returns:
            str: Base64 encoded encrypted credentials
        """
        plain_text_bytes = credentials_json.encode('utf-8')
        modulus_bytes = base64.b64decode(self.public_key['modulus'])
        exponent_bytes = base64.b64decode(self.public_key['exponent'])
        
        # Use different encryption methods based on modulus size
        if len(modulus_bytes) == self.MODULUS_SIZE_1024:
            return self._encrypt_1024_bit(plain_text_bytes, modulus_bytes, exponent_bytes)
        else:
            return self._encrypt_higher_bit(plain_text_bytes, modulus_bytes, exponent_bytes)
    
    def _encrypt_1024_bit(self, plain_text_bytes, modulus_bytes, exponent_bytes):
        """Encrypt using segment-based RSA-OAEP for 1024-bit keys - matches Microsoft implementation"""
        # Calculate segments like Microsoft implementation
        has_incomplete_segment = len(plain_text_bytes) % self.SEGMENT_SIZE != 0
        segment_number = (len(plain_text_bytes) // self.SEGMENT_SIZE)
        if has_incomplete_segment:
            segment_number += 1
        
        # Create a byte array for encrypted bytes
        encrypted_bytes = bytearray([0] * (segment_number * self.ENCRYPTED_LENGTH))
        
        # Process each segment
        for i in range(segment_number):
            # Determine segment length
            if i == segment_number - 1 and has_incomplete_segment:
                length_to_copy = len(plain_text_bytes) % self.SEGMENT_SIZE
            else:
                length_to_copy = self.SEGMENT_SIZE
            
            # Extract segment
            start_pos = i * self.SEGMENT_SIZE
            segment = plain_text_bytes[start_pos:start_pos + length_to_copy]
            
            # Encrypt segment with retry logic
            segment_encrypted_result = self._encrypt_segment(modulus_bytes, exponent_bytes, segment)
            
            # Copy encrypted result to final array
            start_index = i * self.ENCRYPTED_LENGTH
            for j, byte_val in enumerate(segment_encrypted_result):
                encrypted_bytes[start_index + j] = byte_val
        
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    
    def _encrypt_segment(self, modulus_bytes, exponent_bytes, data):
        """Encrypt a single segment with retry logic"""
        if not data:
            raise TypeError('Data is null')
        
        # Retry logic like Microsoft implementation
        for attempt in range(self.MAX_ATTEMPTS):
            try:
                # Convert exponent and modulus byte arrays to integer
                exponent = int.from_bytes(exponent_bytes, 'big')
                modulus = int.from_bytes(modulus_bytes, 'big')
                
                # Generate public key with explicit backend
                public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())
                
                # Encrypt the data using OAEP padding
                encrypted_bytes = public_key.encrypt(
                    bytes(data),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                return encrypted_bytes
                
            except Exception as ex:
                # Sleep for 50 milliseconds like Microsoft implementation
                time.sleep(0.05)
                if attempt == self.MAX_ATTEMPTS - 1:
                    raise Exception(f"Encryption failed after {self.MAX_ATTEMPTS} attempts: {ex}")
        
        raise Exception("Invalid Operation")
    
    def _encrypt_higher_bit(self, plain_text_bytes, modulus_bytes, exponent_bytes):
        """Encrypt using hybrid AES+RSA for higher bit keys"""
        # Generate ephemeral keys
        aes_key = os.urandom(32)  # 256-bit AES key
        hmac_key = os.urandom(64)  # 512-bit HMAC key
        
        # Encrypt data with AES-256-CBC
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # PKCS7 padding
        block_size = 16
        padding_length = block_size - (len(plain_text_bytes) % block_size)
        padded_data = plain_text_bytes + bytes([padding_length] * padding_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Create HMAC
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(iv + encrypted_data)
        mac = h.finalize()
        
        # Combine ephemeral keys
        ephemeral_keys = aes_key + hmac_key
        
        # Encrypt ephemeral keys with RSA
        modulus_int = int.from_bytes(modulus_bytes, byteorder='big')
        exponent_int = int.from_bytes(exponent_bytes, byteorder='big')
        
        public_key = rsa.RSAPublicNumbers(exponent_int, modulus_int).public_key()
        encrypted_keys = public_key.encrypt(
            ephemeral_keys,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine: encrypted_keys + iv + encrypted_data + mac
        final_encrypted = encrypted_keys + iv + encrypted_data + mac
        return base64.b64encode(final_encrypted).decode('utf-8')


class BaseAzureClient:
    def __init__(self, scope):
        """Initialize Azure client and get authentication token
        
        Args:
            scope: The OAuth scope for the specific API (e.g., Fabric, Power BI)
        """
        self.scope = scope
        self.token = self._get_token()
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        } if self.token else None

    def _get_token(self):
        """Get access token using service principal"""
        # Token endpoint
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

        # Request payload
        payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": self.scope,
        }

        try:
            response = requests.post(token_url, data=payload, timeout=30)
            response.raise_for_status()

            token_data = response.json()
            access_token = token_data["access_token"]
            return access_token

        except Exception as e:
            print(f"Failed to get token: {e}")
            raise


class PowerBIClient(BaseAzureClient):
    def __init__(self, gateway_id=None):
        """Initialize Power BI client and get authentication token
        
        Args:
            gateway_id (str, optional): Default gateway ID to use for operations.
                                      If provided, methods can omit gateway_id parameter.
        """
        # Initialize base class with Power BI scope
        super().__init__("https://analysis.windows.net/powerbi/api/.default")
        self.gateway_id = gateway_id

    def upload_report(
        self, workspace_id, file_path, name_conflict, dataset_display_name
    ):
        """
        Upload a Power BI .pbix file to a specified workspace

        Args:
            workspace_id: The workspace (group) ID where to upload the file
            file_path: Path to the .pbix file
            dataset_display_name: Display name for the dataset (defaults to filename)
            name_conflict: What to do if dataset exists ('Ignore', 'Abort', 'Overwrite', 'CreateOrOverwrite')
            skip_report: Whether to skip importing the report (bool)

        Returns:
            dict: Import response data or None if failed
        """
        if not self.token:
            print("No token available for uploading PBIX file")
            return None

        # Validate file exists
        file_path = Path(file_path)
        if not file_path.exists():
            print(f"File not found: {file_path}")
            return None

        # Set dataset display name if not provided
        if not dataset_display_name:
            dataset_display_name = os.path.basename(file_path.name)

        # Construct API URL
        base_url = f"https://api.powerbi.com/v1.0/myorg/groups/{workspace_id}/imports"

        # Build query parameters
        params = {
            "datasetDisplayName": dataset_display_name,
            "nameConflict": name_conflict,
        }

        # Prepare headers (don't set Content-Type for multipart)
        upload_headers = {"Authorization": f"Bearer {self.token}"}

        # Prepare the file for upload
        with open(file_path, "rb") as file:
            files = {"file": (file_path.name, file, "application/octet-stream")}

            print(f"Uploading {file_path.name} to workspace {workspace_id}")

            # Make the POST request
            response = requests.post(
                base_url,
                headers=upload_headers,
                params=params,
                files=files,
                timeout=300,  # 5 minutes timeout for large files
            )

            # Handle response
            if response.status_code in [200, 202]:
                result = response.json()
                status = "initiated" if response.status_code == 202 else "completed"
                print(f"Upload {status} successfully")
                print(f"Import ID: {result.get('id')}")

            else:
                print(f"Upload failed. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                response.raise_for_status()

    def _get_gateway_id(self, provided_gateway_id):
        """
        Get gateway ID using fallback logic
        
        Args:
            provided_gateway_id (str or None): Gateway ID provided to method
            
        Returns:
            str: Gateway ID to use
            
        Raises:
            ValueError: If no gateway ID is available
        """
        gateway_id = provided_gateway_id or self.gateway_id
        if not gateway_id:
            raise ValueError("No gateway_id provided. Either pass gateway_id parameter or set default gateway_id in PowerBIClient.__init__()")
        return gateway_id

    def get_gateway(self, gateway_id=None):
        """
        Get gateway information including public key
        
        Args:
            gateway_id (str, optional): Gateway ID. If not provided, uses default gateway_id from initialization.
            
        Returns:
            dict: Gateway information
        """
        if not self.token:
            print("No token available for getting gateway")
            return None
        
        gateway_id = self._get_gateway_id(gateway_id)
        url = f"https://api.powerbi.com/v1.0/myorg/gateways/{gateway_id}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            gateway_info = response.json()
            print(f"Gateway retrieved successfully: {gateway_info.get('name', 'Unknown')}")
            return gateway_info
        else:
            print(f"Failed to get gateway: {response.status_code} {response.text}")
            response.raise_for_status()
            return None

    def _serialize_credentials(self, credentials, credential_type):
        """
        Serialize credentials to JSON format
        
        Args:
            credentials (dict): Credential data
            credential_type (str): Type of credentials (Basic, Windows, Key, OAuth2)
            
        Returns:
            str: JSON string of credentials
        """
        if credential_type.lower() == 'basic':
            return json.dumps({
                "credentialData": [
                    {"name": "username", "value": credentials.get('username', '')},
                    {"name": "password", "value": credentials.get('password', '')}
                ]
            })
        elif credential_type.lower() == 'windows':
            return json.dumps({
                "credentialData": [
                    {"name": "username", "value": credentials.get('username', '')},
                    {"name": "password", "value": credentials.get('password', '')}
                ]
            })
        elif credential_type.lower() == 'key':
            return json.dumps({
                "credentialData": [
                    {"name": "key", "value": credentials.get('key', '')}
                ]
            })
        else:
            raise ValueError(f"Unsupported credential type: {credential_type}")

    def create_datasource(self, datasource_config, gateway_id=None):
        """
        Create a new datasource in the gateway with encrypted credentials
        
        Args:
            datasource_config (dict): Datasource configuration containing:
                - dataSourceType (str): Type of datasource (e.g., "SQL")
                - connectionDetails (str): JSON string with connection details
                - datasourceName (str): Name for the datasource
                - credentialType (str): Type of credentials (Basic, Windows, Key)
                - credentials (dict): Credential data
                - privacyLevel (str, optional): Privacy level (None, Organizational, Private, Public)
            gateway_id (str, optional): Gateway ID. If not provided, uses default gateway_id from initialization.
                
        Returns:
            dict: API response with created datasource information
        """
        if not self.token:
            print("No token available for creating datasource")
            return None
        
        try:
            # Get gateway information
            gateway_id = self._get_gateway_id(gateway_id)
            gateway_info = self.get_gateway(gateway_id)
            if not gateway_info:
                raise Exception("Failed to retrieve gateway information")
            
            # Check if it's a cloud gateway (not supported)
            if 'name' not in gateway_info:
                raise Exception("Add datasource is not supported for cloud gateways")
            
            # Serialize credentials
            credentials_json = self._serialize_credentials(
                datasource_config['credentials'], 
                datasource_config['credentialType']
            )
            
            # Encrypt credentials
            encryptor = PowerBIGatewayEncryptor(gateway_info['publicKey'])
            encrypted_credentials = encryptor.encrypt_credentials(credentials_json)
            
            # Prepare request body
            connection_details = datasource_config['connectionDetails']
            if isinstance(connection_details, dict):
                connection_details = json.dumps(connection_details)
                
            request_body = {
                "dataSourceType": datasource_config['dataSourceType'],
                "connectionDetails": connection_details,
                "datasourceName": datasource_config['datasourceName'],
                "credentialDetails": {
                    "credentialType": datasource_config['credentialType'],
                    "credentials": encrypted_credentials,
                    "encryptedConnection": "Encrypted",
                    "encryptionAlgorithm": "RSA-OAEP",
                    "privacyLevel": datasource_config.get('privacyLevel', 'None')
                }
            }
            
            # Make API request
            url = f"https://api.powerbi.com/v1.0/myorg/gateways/{gateway_id}/datasources"
            response = requests.post(url, headers=self.headers, json=request_body)
            
            if response.status_code == 201:
                result = response.json()
                print(f"Datasource created successfully: {result.get('datasourceName')}")
                print(f"Datasource ID: {result.get('id')}")
                return result
            else:
                print(f"Failed to create datasource: {response.status_code} {response.text}")
                response.raise_for_status()
                return None
                
        except Exception as e:
            print(f"Error creating datasource: {e}")
            raise
