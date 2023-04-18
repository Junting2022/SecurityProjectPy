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
        self.handshake_number = {}
        self.stats = 0
        self.symmetric_key_number = {}
        self.symmetric_key = None
        self.group_members = []

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
                                # step 6 : establish symmetric key
                                # start a thread to receive key numbers
                                receiveThread = threading.Thread(target=self.receive_symmetric_number)
                                receiveThread.start()
                                self.establish_symmetric_key()

                break
            except Exception as e:
                print(f"Error: {e}")
                self.client.close()
                break

    def receive_symmetric_number(self):
        self.symmetric_key_number[self.client_id] = os.urandom(16)
        while len(self.symmetric_key_number) < 3:
            # Receive the sender_id using the received length
            sender_id = self.client.recv(1024).decode("utf-8")
            encrypted_number_msg = self.client.recv(1024)
            # split the message into the encrypted number and signature
            encrypted_number = encrypted_number_msg[:256]
            signature = encrypted_number_msg[256:]

            # Verify the signature
            sender_cert = f"key/{sender_id}_cert.pem"
            server_public_key = load_public_key(sender_cert)
            is_valid = verify_signature(server_public_key, encrypted_number, signature)
            if not is_valid:
                raise Exception("Invalid signature")
            private_key = load_private_key(self.key_file)
            number = decrypt_asymmetric(private_key, encrypted_number)
            self.symmetric_key_number[sender_id] = number
            print(f"Received {number} from {sender_id}")
        # start chat
        # Sort the bytes in ascending order
        sorted_bytes = sorted(self.symmetric_key_number.values())
        # Concatenate the sorted bytes to form a single bytes object
        bytes_object = b''.join(sorted_bytes)
        self.symmetric_key = hashlib.sha256(bytes_object).digest()
        print(f"Symmetric key: {self.symmetric_key}")
        self.stats = 8

    def establish_symmetric_key(self):
        # step 6 : establish symmetric key
        # send symmetric number to server
        input()
        first_chat_member_id = input("Enter the first chat member's ID: ")
        second_chat_member_id = input("Enter the second chat member's ID: ")
        self.send_symmetric_number(first_chat_member_id, self.symmetric_key_number[self.client_id])
        self.send_symmetric_number(second_chat_member_id, self.symmetric_key_number[self.client_id])
        self.group_members.append(first_chat_member_id)
        self.group_members.append(second_chat_member_id)
        print(self.group_members)
        while self.stats != 8:
            time.sleep(1)
        # start chat with symmetric key
        thread = threading.Thread(target=self.handle_server)
        thread.start()
        self.broadcast()

    def handle_server(self):
        print("ready to receive messages")
        while True:
            try:
                sender_id = self.client.recv(1024).decode("utf-8")  # Receive messages from the server
                print(f"receive encrypt message from {sender_id}")
                if sender_id:
                    encrypted_msg = self.client.recv(2048)
                    iv = self.client.recv(16)
                    msg = decrypt_symmetric(encrypted_msg, self.symmetric_key, iv).decode("utf-8")
                    print(f"{sender_id}: {msg}")
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
            self.handshake_number[1] = number_one
            self.stats = 3
            print(f"step 3 done, you have read random number{number_one} and verify signature")
        except Exception as e:
            print(f"Error: {e}")

    def step_four(self):
        try:
            # generate a random number
            number_two = os.urandom(16)
            self.handshake_number[2] = number_two

            # encrypt the two numbers using the server's public key
            numbers = self.handshake_number[1] + self.handshake_number[2]
            server_public_key = load_public_key(self.server_cert_file)
            encrypt_numbers = encrypt_asymmetric(server_public_key, numbers)

            # sign the numbers
            private_key = load_private_key(self.key_file)
            signature = sign_message(private_key, encrypt_numbers)

            # send the encrypted number and signature
            msg = encrypt_numbers + signature
            self.client.send(msg)
            self.stats = 4
            print(
                f"step 4 done, you have send random number {self.handshake_number[1]} {self.handshake_number[2]} and "
                f"signature")
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
            if number_two != self.handshake_number[2]:
                raise Exception("Invalid number")
            self.stats = 5
            print(f"step 5 done, you have verify number {number_two} signature")
        except Exception as e:
            print(f"Error: {e}")

    def send_symmetric_number(self, recipient_id, number):
        # Encrypt and sign the number, then send it to the specified recipient
        recipient_cert = f"key/{recipient_id}_cert.pem"
        # Load the recipient's public key
        recipient_public_key = load_public_key(recipient_cert)
        # Encrypt the number using the recipient public key
        encrypted_number = encrypt_asymmetric(recipient_public_key, number)
        # Sign the encrypted number
        private_key = load_private_key(self.key_file)
        signature = sign_message(private_key, encrypted_number)
        # Send the recipient_id and the encrypted number and signature to the recipient as separate messages
        self.client.send(recipient_id.encode("utf-8"))
        self.client.send(encrypted_number + signature)

    def broadcast(self):
        try:
            while True:
                message = input("Enter your message: ")
                self.send_message(self.group_members[0], message)
                time.sleep(0.1)
                self.send_message(self.group_members[1], message)
        except Exception as e:
            print(f"Error: {e}")

    def send_message(self, recipient_id, message):
        try:
            iv, encrypt_message = encrypt_symmetric(message.encode("utf-8"), self.symmetric_key)
            self.client.send(recipient_id.encode("utf-8"))  # Send recipient id to the server
            time.sleep(0.1)
            self.client.send(
                len(encrypt_message).to_bytes(4, byteorder='big'))  # Send encrypted message length to the server
            time.sleep(0.1)
            self.client.send(encrypt_message)  # Send message to the server
            time.sleep(0.1)
            self.client.send(iv)  # Send iv to the server
            time.sleep(0.1)
            print(f"Message sent to {recipient_id}")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    IP_ADDRESS = "127.0.0.1"
    PORT = 20005
    CLIENT_ID = input("Enter your client id (A, B, or C): ")
    CLIENT_CERT = f"key/{CLIENT_ID}_cert.pem"
    CLIENT_KEY = f"key/{CLIENT_ID}_key.pem"
    CLIENT_CA = f"key/ca_cert.pem"
    SERVER_CERT = f"key/S_cert.pem"

    client = ChatClient(IP_ADDRESS, PORT, CLIENT_ID, CLIENT_CERT, CLIENT_KEY, CLIENT_CA, SERVER_CERT)
    client.connect()
