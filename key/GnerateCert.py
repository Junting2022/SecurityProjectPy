from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime


class CertificateGenerator:
    def __init__(self, common_name, days_valid):
        self.common_name = common_name
        self.days_valid = days_valid

    def generate_csr_and_key(self):
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Prepare the subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])

        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())

        return csr, private_key

    def sign_csr(self, csr, issuer_cert, issuer_key):
        # Create a self-signed certificate (replace this with a CA-signed certificate)
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            issuer_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=self.days_valid)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(issuer_key, hashes.SHA256(), default_backend())

        return cert

    @staticmethod
    def save_to_file(cert, private_key, cert_file, key_file):
        # Save the certificate to a file
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Save the private key to a file
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))


if __name__ == "__main__":
    entities = ["A", "B", "C", "S"]
    ca_common_name = "Example CA"
    entity_days_valid = 365

    # Generate a CA-signed certificate and private key
    ca_generator = CertificateGenerator(ca_common_name, entity_days_valid)
    ca_cert, ca_key = ca_generator.generate_csr_and_key()

    # Generate and save certificates and private keys for each entity
    for entity in entities:
        generator = CertificateGenerator(f"Chat {entity}", entity_days_valid)
        csr, private_key = generator.generate_csr_and_key()
        cert = generator.sign_csr(csr, ca_cert, ca_key)

        cert_file = f"{entity}_cert.pem"
        key_file = f"{entity}_key.pem"

        generator.save_to_file(cert, private_key, cert_file, key_file)
