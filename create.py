import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from kubernetes import client, config
import subprocess
import os

def execute_kubectl_command(command):
    try:
        subprocess.run(command, check=True)
        print(f"Command '{' '.join(command)}' executed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to execute command '{' '.join(command)}'.")
        print(f"Error message: {e}")
        
def generate_rsa_key(subject: str, organization=None, key_size=2048):
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize the private key to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    csr_builder = x509.CertificateSigningRequestBuilder()

     # Add subject information
    csr_attirbs = [
        x509.NameAttribute(NameOID.COMMON_NAME, subject),
    ]

    if organization != None:
        csr_attirbs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    csr_builder = csr_builder.subject_name(x509.Name(csr_attirbs))

    # Sign the CSR with the private key
    csr = csr_builder.sign(
        private_key,
        hashes.SHA256(),
        default_backend()
    )

    csr_bytes = csr.public_bytes(serialization.Encoding.PEM)

    

    base64_data_pem = base64.b64encode(pem)
    base64_pem = base64_data_pem.decode('utf-8')

    base64_data_csr = base64.b64encode(csr_bytes)
    base64_csr = base64_data_csr.decode('utf-8')

    
    return base64_pem, base64_csr

def create_and_approve_csr(username, base64_csr, expiration_seconds):
    config.load_kube_config()
    csr_name = f"{username}"
    api_instance = client.CertificatesV1Api()

    # Define the Certificate Signing Request (CSR) object
    csr_manifest = {
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": {
            "name": csr_name,
        },
        "spec": {
            "groups": [
                "system:authenticated"
            ],
            "request": base64_csr,
            "signerName": "kubernetes.io/kube-apiserver-client",
            "expirationSeconds": expiration_seconds,
            "usages": [
                "digital signature",
                "key encipherment",
                "client auth"
            ]
        }
    }

    # Create the CSR
    try:
        api_instance.create_certificate_signing_request(body=csr_manifest)
    except Exception as e:
        print("encountered", e)
        return

    try:
        # Run the kubectl command to approve the certificate request
        subprocess.run(["kubectl", "certificate", "approve", csr_name], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error message: {e}")

    try:
        result = subprocess.run(["kubectl", "get", "csr", csr_name, "-o", "jsonpath='{.status.certificate}'"], capture_output=True, text=True, check=True)
        certificate_base64 = result.stdout.strip()[1:-1]  # Strip leading and trailing single quotes
        # base64_data_certificate = base64.b64encode(result.stdout.strip()[1:-1])
        # base64_certificate = base64_data_certificate.decode('utf-8')
        return result.stdout[1:-1]
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to get certificate from CSR '{csr_name}'.")
        print(f"Error message: {e}")
        return None
    
def append_to_kubeconfig(string_to_append):
    # Step 1: Retrieve file path from environment variable
    file_path = os.getenv("KUBECONFIG")

    if file_path:
        # Step 2: Open the file in append mode
        with open(file_path, "a") as file:
            # Step 3: Write the string to the file
            file.write(string_to_append)
    else:
        print("Environment variable not set or invalid.")

def main():
    parser = argparse.ArgumentParser(description='Process a string argument.')
    parser.add_argument('username', type=str, help='Name of the user of email')
    parser.add_argument('-d', '--days', type=int, default=60 * 60 * 24 * 365, help='Expirity date of the certificate in seconds (default to 1 year)')
    args = parser.parse_args()

    username = args.username
    exp_seconds = args.days 

    base64_pem, base64_csr = generate_rsa_key(username)
    base64_certificate = create_and_approve_csr(username, base64_csr, exp_seconds)

    print(base64_certificate != None)

    print("Signed the certificate, adding this line to kubeconfig.")
    str_to_add = f'''
- name: {username}
  user:
    client-certificate-data: {base64_certificate}
    client-key-data: {base64_pem}
'''
    append_to_kubeconfig(str_to_add)
    print("DONE")

if __name__ == "__main__":
    main()
