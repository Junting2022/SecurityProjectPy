import socket
import threading
import time
from cryptography.hazmat.primitives import serialization
from Cryp import *


class ChatClient:
    def __init__(self, ip, port, client_id, cert_file, key_file, ca_file, server_cert_file):
        self.ip = ip
        self.port = port
        self.client_id = client_id
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.server_cert_file = server_cert_file

    def connect(self):

        self.client.connect((self.ip, self.port))
        time.sleep(0.1)
        self.client.send(self.client_id.encode())  # Send client_id to the server
        print("connecting to server......")
        while True:
            try:
                msg = self.client.recv(1)  # Receive messages from the server
                if msg:
                    print(f"Connected to server at {self.ip}:{self.port}, starting handshake")
                    input()
                    # step 1 send certificate and signature
                    self.step_one()
                    msg = None
                    msg = self.client.recv(1024)
                    if msg:
                        print("step 2 done, certificate and signature are valid")
                        input()
                        # step 3 : read random number and verify signature
                        number_one = self.step_three(msg)
                        input()
                        thread = threading.Thread(target=self.handle_server)
                        thread.start()

                    break
            except Exception as e:
                print(f"Error: {e}")
                self.client.close()
                break

    def handle_server(self):
        while True:
            try:
                msg = self.client.recv(1024).decode("utf-8")  # Receive messages from the server
                if msg:
                    sender_id, message = msg.split(":", 1)  # Extract sender id and message
                    print(f"{sender_id}: {message}")
            except Exception as e:
                print(f"Error: {e}")
                self.client.close()
                break

    def step_one(self):
        # send the CA
        with open(self.cert_file, 'rb') as f:
            # open file in binary mode
            cert_data = f.read()
            # Load the certificate
            cert = load_pem_x509_certificate(cert_data)
            # Convert the certificate to DER format
            der_cert_data = cert.public_bytes(serialization.Encoding.DER)
        # sign the DER formatted certificate
        private_key = load_private_key(self.key_file)
        signature = sign_message(private_key, der_cert_data)
        # Load the server's public key
        server_public_key = load_public_key(self.server_cert_file)
        msg = der_cert_data + signature
        # Encrypt the message using the server's public key and a symmetric key
        encrypted_data = encrypt_asymmetric_with_symmetric_key(msg, server_public_key)
        self.client.send(encrypted_data)
        print("step 1 done, you have send certificate and signature")

    def step_three(self, msg):
        try:
            # split the message into the encrypted number and signature
            encrypt_number = msg[:256]
            signature = msg[256:]

            # decrypt the number using the private key
            private_key = load_private_key(self.key_file)
            number = decrypt_asymmetric(private_key, encrypt_number)

            # verify the signature
            server_public_key = load_public_key(self.server_cert_file)
            is_valid = verify_signature(server_public_key, encrypt_number, signature)

            if not is_valid:
                # Handle the invalid signature case
                raise Exception("Invalid Server signature")
            print("step 3 done, you have read random number and verify signature")
            return number
        except Exception as e:
            print(f"Error: {e}")

    def send_message(self):
        while True:
            recipient_id = input("Enter recipient id (A, B, or C): ")
            message = input("Enter your message: ")
            self.client.send(f"{recipient_id}:{message}".encode("utf-8"))  # Send message to the server


if __name__ == "__main__":
    while True:
        try:
            IP_ADDRESS = "127.0.0.1"
            PORT = 20002
            CLIENT_ID = input("Enter your client id (A, B, or C): ")
            CLIENT_CERT = f"key/{CLIENT_ID}_cert.pem"
            CLIENT_KEY = f"key/{CLIENT_ID}_key.pem"
            CLIENT_CA = f"key/ca_cert.pem"
            SERVER_CERT = f"key/S_cert.pem"

            client = ChatClient(IP_ADDRESS, PORT, CLIENT_ID, CLIENT_CERT, CLIENT_KEY, CLIENT_CA, SERVER_CERT)
            client.connect()
        except Exception as e:
            print(f"Error: {e}, please try again")
            continue
