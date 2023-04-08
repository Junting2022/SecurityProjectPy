import socket
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

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
                    self.client.send(self.step_one())
                    print("step 1 done, you have send certificate and signature")
                    msg = None
                    msg = self.client.recv(1)
                    if msg:
                        print("step 2 done, certificate and signature are valid")
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
        with open(self.key_file, 'rb') as f:
            key_data = f.read()
            private_key = load_pem_private_key(key_data, password=None)
            signature = sign_message(private_key, der_cert_data)
        # Load the server's certificate
        with open(self.server_cert_file, 'rb') as f:
            server_cert_data = f.read()
            server_cert = load_pem_x509_certificate(server_cert_data)

        # Extract the server's public key
        server_public_key = server_cert.public_key()
        msg = der_cert_data + signature
        # Encrypt the message using the server's public key and a symmetric key
        encrypted_data = encrypt_asymmetric_with_symmetric_key(msg, server_public_key)
        return encrypted_data

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
