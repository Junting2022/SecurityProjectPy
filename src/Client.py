import socket
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
        self.number = {}
        self.stats = 0

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
                    msg = self.client.recv(2048)
                    if msg:
                        self.stats = 2
                        print("step 2 done, certificate and signature are valid")
                        input()
                        # step 3 : read random number and verify signature
                        self.step_three(msg)
                        input()
                        # step 4 : send another random number and signature
                        self.step_four()
                        input()
                        # step 5 : read number two and verify signature
                        msg = self.client.recv(2048)
                        if msg:
                            self.step_five(msg)
                            if self.stats == 5:
                                print("handshake done, start establishing symmetric key")
                                input()
                                # step 6 : establish symmetric key
                                self.establish_symmetric_key()

                break
            except Exception as e:
                print(f"Error: {e}")
                self.client.close()
                break

    def establish_symmetric_key(self):
        # step 6 : establish symmetric key
        key_numbers = {self.client_id: os.urandom(16)}
        # send symmetric number to server
        first_chat_member_id = "B"  # input("Enter the first chat member's ID: ")
        second_chat_member_id = "C"  # input("Enter the second chat member's ID: ")
        self.send_symmetric_number(first_chat_member_id, key_numbers[self.client_id])
        self.send_symmetric_number(second_chat_member_id, key_numbers[self.client_id])
        # receive symmetric number from server
        # receive symmetric number from server
        while len(key_numbers) < 2:
            # Receive the length of the sender_id
            sender_id_len = int.from_bytes(self.client.recv(2), 'big')
            # Receive the sender_id using the received length
            sender_id = self.client.recv(sender_id_len).decode("utf-8")
            encrypted_number = self.client.recv(256)
            signature = self.client.recv(256)

            # Verify the signature
            server_public_key = load_public_key(self.server_cert_file)
            is_valid = verify_signature(server_public_key, encrypted_number, signature)
            if not is_valid:
                raise Exception("Invalid signature")
            private_key = load_private_key(self.key_file)
            number = decrypt_asymmetric(private_key, encrypted_number)
            key_numbers[sender_id] = number
            print(f"Received {number} from {sender_id}")
        # start chat
        symmetric_key = hashlib.sha256(sum(key_numbers.values())).digest()
        print(f"Symmetric key: {symmetric_key}")
        self.handle_server()

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
        self.stats = 1
        print("step 1 done, you have send certificate and signature")

    def step_three(self, msg):
        try:
            # split the message into the encrypted number and signature
            encrypt_number = msg[:256]
            signature = msg[256:]

            # decrypt the number using the private key
            private_key = load_private_key(self.key_file)
            number_one = decrypt_asymmetric(private_key, encrypt_number)

            # verify the signature
            server_public_key = load_public_key(self.server_cert_file)
            is_valid = verify_signature(server_public_key, encrypt_number, signature)

            if not is_valid:
                # Handle the invalid signature case
                raise Exception("Invalid Server signature")
            self.number[1] = number_one
            self.stats = 3
            print("step 3 done, you have read random number and verify signature")
        except Exception as e:
            print(f"Error: {e}")

    def step_four(self):
        try:
            # generate a random number
            number_two = os.urandom(16)
            self.number[2] = number_two

            # encrypt the two numbers using the server's public key
            numbers = self.number[1] + self.number[2]
            server_public_key = load_public_key(self.server_cert_file)
            encrypt_numbers = encrypt_asymmetric(server_public_key, numbers)

            # sign the numbers
            private_key = load_private_key(self.key_file)
            signature = sign_message(private_key, encrypt_numbers)

            # send the encrypted number and signature
            msg = encrypt_numbers + signature
            self.client.send(msg)
            self.stats = 4
            print("step 4 done, you have send random number and signature")
        except Exception as e:
            print(f"Error: {e}")

    def step_five(self, msg):
        try:
            # split the message into the encrypted number and signature
            encrypt_number = msg[:256]
            signature = msg[256:]

            # decrypt the number using the private key
            private_key = load_private_key(self.key_file)
            number_two = decrypt_asymmetric(private_key, encrypt_number)

            # verify the signature
            server_public_key = load_public_key(self.server_cert_file)
            is_valid = verify_signature(server_public_key, encrypt_number, signature)

            if not is_valid:
                # Handle the invalid signature case
                raise Exception("Invalid Server signature")
            if number_two != self.number[2]:
                raise Exception("Invalid number")
            self.stats = 5
            print("step 5 done, you have verify number two signature")
        except Exception as e:
            print(f"Error: {e}")

    def send_symmetric_number(self, recipient_id, number):
        # Encrypt and sign the number, then send it to the specified recipient
        server_public_key = load_public_key(self.server_cert_file)
        # Encrypt the number using the server's public key
        encrypted_number = encrypt_asymmetric(server_public_key, number)
        # Sign the encrypted number
        private_key = load_private_key(self.key_file)
        signature = sign_message(private_key, encrypted_number)
        # Send the recipient_id and the encrypted number and signature to the recipient as separate messages
        self.client.send(recipient_id.encode("utf-8"))
        self.client.send(encrypted_number + signature)

    def send_message(self):
        while True:
            recipient_id = input("Enter recipient id (A, B, or C): ")
            message = input("Enter your message: ")
            self.client.send(f"{recipient_id}:{message}".encode("utf-8"))  # Send message to the server


if __name__ == "__main__":
    IP_ADDRESS = "127.0.0.1"
    PORT = 20002
    CLIENT_ID = input("Enter your client id (A, B, or C): ")
    CLIENT_CERT = f"key/{CLIENT_ID}_cert.pem"
    CLIENT_KEY = f"key/{CLIENT_ID}_key.pem"
    CLIENT_CA = f"key/ca_cert.pem"
    SERVER_CERT = f"key/S_cert.pem"

    client = ChatClient(IP_ADDRESS, PORT, CLIENT_ID, CLIENT_CERT, CLIENT_KEY, CLIENT_CA, SERVER_CERT)
    client.connect()

