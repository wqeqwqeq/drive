import requests
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def encrypt_credentials(credentials, gateway_public_key_dict):
    """
    Encrypt credentials using RSA-OAEP with the gateway's public key
    
    Args:
        credentials (dict): Dictionary containing username and password
        gateway_public_key_dict (dict): Dictionary with 'exponent' and 'modulus' keys
    
    Returns:
        str: Base64 encoded encrypted credentials
    """
    # Convert credentials to JSON string
    credentials_json = json.dumps(credentials)
    
    # Extract modulus and exponent from the public key dictionary
    modulus_b64 = gateway_public_key_dict["modulus"]
    exponent_b64 = gateway_public_key_dict["exponent"]
    
    # Decode base64url encoded values
    modulus_bytes = base64.urlsafe_b64decode(modulus_b64 + '==')  # Add padding if needed
    exponent_bytes = base64.urlsafe_b64decode(exponent_b64 + '==')
    
    # Convert bytes to integers
    modulus = int.from_bytes(modulus_bytes, byteorder='big')
    exponent = int.from_bytes(exponent_bytes, byteorder='big')
    
    # Create RSA public key from modulus and exponent
    public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
    public_key = public_numbers.public_key()
    
    # Encrypt using RSA-OAEP
    encrypted_data = public_key.encrypt(
        credentials_json.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return base64 encoded encrypted data
    return base64.b64encode(encrypted_data).decode('utf-8')


def create_powerbi_datasource(token, gateway_id, gateway_public_key_dict, datasource_config):
    """
    Create a Power BI gateway datasource with encrypted credentials
    
    Args:
        token (str): Service principal access token
        gateway_id (str): Gateway ID
        gateway_public_key_dict (dict): Gateway public key dict with 'exponent' and 'modulus'
        datasource_config (dict): Datasource configuration
    
    Returns:
        requests.Response: API response
    """
    
    # Extract credentials for encryption
    credentials = {
        "username": datasource_config["credentials"]["username"],
        "password": datasource_config["credentials"]["password"]
    }
    
    # Encrypt credentials
    encrypted_credentials = encrypt_credentials(credentials, gateway_public_key_dict)
    
    # Prepare the request body
    request_body = {
        "dataSourceType": datasource_config["dataSourceType"],
        "connectionDetails": json.dumps(datasource_config["connectionDetails"]),
        "datasourceName": datasource_config["datasourceName"],
        "credentialDetails": {
            "credentialType": datasource_config["credentialType"],
            "credentials": encrypted_credentials,
            "encryptedConnection": "Encrypted",
            "encryptionAlgorithm": "RSA-OAEP",
            "privacyLevel": datasource_config["privacyLevel"]
        }
    }
    
    # API endpoint URL
    url = f"https://api.powerbi.com/v1.0/myorg/gateways/{gateway_id}/datasources"
    
    # Request headers
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # Make the API call
    response = requests.post(url, headers=headers, data=json.dumps(request_body))
    
    return response


# Example usage
if __name__ == "__main__":
    # Your configuration
    token = "your_service_principal_token"
    gateway_id = "your_gateway_id"
    
    # Gateway public key (from API response)
    gateway_public_key = {
        "exponent": "AQAB",
        "modulus": "1KialZvkPP1t1FZqCoHA+4Ata909VcuEVTFQ5j1QLdvqoxsa+"
    }
    
    # Datasource configuration
    datasource_config = {
        "dataSourceType": "ODBC",
        "connectionDetails": {
            "connectionString": "dsn=Snowflake Prod"
        },
        "datasourceName": "Snowflake test datasource",
        "credentialType": "Basic",
        "credentials": {
            "username": "stanleytest",
            "password": "staneypassword"
        },
        "privacyLevel": "Organizational"
    }
    
    # Create the datasource
    response = create_powerbi_datasource(token, gateway_id, gateway_public_key, datasource_config)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
