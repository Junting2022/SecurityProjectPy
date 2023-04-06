import hashlib
import os

from OpenSSL import crypto
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# Hash a message using SHA-256
def hash_message(message):
    hash_object = hashlib.sha256(message.encode())
    return hash_object.hexdigest()


def pad_message(message):
    padder = PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    return padded_message


def unpad_message(padded_message):
    unpadder = PKCS7(128).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message.decode()


# Symmetric encryption using AES
def encrypt_symmetric(key, message):
    padded_message = pad_message(message)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv, ciphertext


# Symmetric decryption using AES
def decrypt_symmetric(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    message = unpad_message(padded_message)
    return message


# Asymmetric encryption using RSA
def encrypt_asymmetric(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


# Asymmetric decryption using RSA
def decrypt_asymmetric(private_key, encrypted_message):
    message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return message.decode()


# Sign a message using RSA and SHA-256
def sign_message(private_key, message):
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(message.encode())
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
def verify_signature(public_key, message, signature):
    message_hash = hashes.Hash(hashes.SHA256())
    message_hash.update(message.encode())
    try:
        public_key.verify(
            signature,
            message_hash.finalize(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


# Verify a certificate
def verify_certificate(cert_pem, ca_cert_pem):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_pem)
    store = crypto.X509Store()
    store.add_cert(ca_cert)
    ctx = crypto.X509StoreContext(store, cert)
    try:
        ctx.verify_certificate()
        return True
    except crypto.X509StoreContextError:
        return False


# Simple tests for each function
if __name__ == "__main__":
    # Test hash_message
    message = "Hello, world!"
    hashed_message = hash_message(message)
    print("Hashed message:", hashed_message)

    # Test symmetric encryption and decryption
    key = os.urandom(32)
    iv, ciphertext = encrypt_symmetric(key, message)
    decrypted_message = decrypt_symmetric(key, iv, ciphertext)
    print("Original message:", message)
    print("Decrypted message:", decrypted_message)

    # Test asymmetric encryption and decryption
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    encrypted_message = encrypt_asymmetric(public_key, message)
    decrypted_message = decrypt_asymmetric(private_key, encrypted_message)
    print("Original message:", message)
    print("Decrypted message:", decrypted_message)

    # Test signing and verifying a message
    signature = sign_message(private_key, message)
    is_valid_signature = verify_signature(public_key, message, signature)
    print("Is signature valid?:", is_valid_signature)

    # Test verify_certificate (using self-signed certificates for testing purposes)
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(1)
    ca_cert.get_subject().CN = "Test CA"
    ca_cert.set_issuer(ca_cert.get_subject())
    ca_cert.set_pubkey(ca_key)
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    ca_cert.add_extensions([crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE")])
    ca_cert.add_extensions([crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert)])
    ca_cert.sign(ca_key, "sha256")

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(2)
    cert.get_subject().CN = "example.com"
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(ca_key)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.sign(ca_key, "sha256")

    ca_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)
    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    is_cert_valid = verify_certificate(cert_pem, ca_cert_pem)
    print("Is certificate valid?:", is_cert_valid)
