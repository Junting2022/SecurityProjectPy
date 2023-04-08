import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate



# Hash a message using SHA-256
def hash_message(message):
    hash_object = hashlib.sha256(message)
    return hash_object.digest()


# Asymmetric encryption using RSA
def encrypt_asymmetric(public_key, message):
    if isinstance(public_key, rsa.RSAPublicKey):
        encrypted_message = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message
    else:
        raise ValueError("The public_key provided is not an RSA public key.")


# Asymmetric decryption using RSA
def decrypt_asymmetric(private_key, encrypted_message):
    if isinstance(private_key, rsa.RSAPrivateKey):
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message
    else:
        raise ValueError("The private_key provided is not an RSA private key.")


def decrypt_symmetric(encrypted_message, symmetric_key, iv):
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    message = unpad(padded_message, 16)

    return message


def encrypt_symmetric(message, symmetric_key):
    # Encrypt the message using the symmetric key
    # Usage:
    # iv, encrypted_message = encrypt_message_with_symmetric_key(message, symmetric_key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_message = pad(message, 16)  # Assuming you have a padding function
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    return iv, encrypted_message


# Sign a message using RSA and SHA-256
def sign_message(private_key, message):
    # private_key is a cryptography.hazmat.primitives.asymmetric.RSAPrivateKey object
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(message)
    signature = private_key.sign(
        message_hash.finalize(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    return signature


# Verify a signature using RSA and SHA-256
def verify_signature(client_public_key, der_cert_data, signature):
    # Verify the signature using the client's public key
    try:
        client_public_key.verify(
            signature,
            der_cert_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except InvalidSignature:
        print("Signature is invalid.")
        # Handle the invalid signature case, e.g., disconnect the client or raise an exception


# Verify a certificate
def verify_certificate(der_cert_data, ca_cert_file):
    # Load the server's CA certificate
    with open(ca_cert_file, 'rb') as f:
        ca_cert_data = f.read()
        ca_cert = load_pem_x509_certificate(ca_cert_data)

    # Verify the client's certificate using the CA certificate
    client_cert = load_der_x509_certificate(der_cert_data)
    ca_cert.public_key().verify(client_cert.signature, client_cert.tbs_certificate_bytes, padding.PKCS1v15(),
                                client_cert.signature_hash_algorithm)

    # Extract the public key from the verified client's certificate
    client_public_key = client_cert.public_key()
    return client_public_key


def encrypt_asymmetric_with_symmetric_key(message, public_key):
    # Generate a symmetric key
    symmetric_key = os.urandom(32)

    # Encrypt the message using the symmetric key
    iv, encrypted_message = encrypt_symmetric(message, symmetric_key)

    # Encrypt the symmetric key using the provided public key
    encrypted_symmetric_key = encrypt_asymmetric(public_key, symmetric_key)

    # Get the RSA key size in bytes
    rsa_key_size = public_key.key_size // 8

    # Combine the encrypted symmetric key, RSA key size, IV, and encrypted message
    encrypted_data = rsa_key_size.to_bytes(2, 'big') + encrypted_symmetric_key + iv + encrypted_message

    return encrypted_data


def decrypt_asymmetric_with_symmetric_key(encrypted_data, private_key):
    # Extract the RSA key size from the encrypted data
    rsa_key_size = int.from_bytes(encrypted_data[:2], 'big')

    # Extract the encrypted symmetric key, IV, and encrypted message from the encrypted data
    encrypted_symmetric_key = encrypted_data[2:2 + rsa_key_size]
    iv = encrypted_data[2 + rsa_key_size:2 + rsa_key_size + 16]
    encrypted_message = encrypted_data[2 + rsa_key_size + 16:]

    # Decrypt the symmetric key using the server's private key
    symmetric_key = decrypt_asymmetric(private_key, encrypted_symmetric_key)

    # Decrypt the message using the symmetric key
    message = decrypt_symmetric(encrypted_message, symmetric_key, iv)

    return message


def unpad(padded_data, block_size):
    # PKCS7 unpadding
    unpadder = PKCS7(block_size * 8).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def pad(data, block_size):
    # PKCS7 padding
    padder = PKCS7(block_size * 8).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data
