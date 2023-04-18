import socket
import threading
import time

from Cryp import *


class Server:
    def __init__(self, ip, port, cert_file, key_file, ca_file):
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Set the SO_REUSEADDR option
        self.clients = {}  # Dictionary to store clients
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file

    def start(self):
        self.server.bind((self.ip, self.port))
        self.server.listen(3)
        print(f"Secure Chat Server started at {self.ip}:{self.port}")

        while True:
            conn = None  # Initialize conn to None
            try:
                conn, addr = self.server.accept()  # Accept incoming connections
                print(f"Connected to {addr}")
                msg = conn.recv(1024)
                client_id = msg.decode()  # Receive client id (A, B, or C)
                print(f"Received client id: {client_id}")
                self.clients[client_id] = {}  # Dictionary to store clients data
                self.clients[client_id]["conn"] = conn  # Store connection object
                self.clients[client_id]["stats"] = 0  # Initialize client stats, it will change in each handshake step
                conn.send(b'1')
                # start a thread to handle the handshake
                shackThread = threading.Thread(target=self.handshake, args=(client_id, conn,))
                shackThread.start()
                print(f"{client_id} starting handshake")
            except Exception as e:
                print(f"Error: {e}")
                if conn:
                    conn.close()
                continue

    def handshake(self, client_id, conn):
        while True:
            try:
                # step 2 : Check certificate and signature
                msg = conn.recv(2048)
                if msg:
                    self.clients[client_id]["stats"] = 1
                    self.step_two(client_id, msg)
                    if self.clients[client_id]["stats"] == 2:
                        # step 3 : send random number and signature
                        self.step_three(client_id, conn)
                        # step 4 : receive random number and signature
                        msg = conn.recv(2048)
                        if msg:
                            self.step_four(client_id, msg)
                            if self.clients[client_id]["stats"] == 4:
                                # step 5 : send number two and signature
                                self.step_five(client_id, conn)
                                print(f"{client_id} handshake done")
                                # step 6 : establish symmetric key
                                self.establish_symmetric_key(client_id, conn)

                break

            except Exception as e:
                print(f"Error: {e}")
                conn.close()
                break

    def establish_symmetric_key(self, client_id, conn):
        # Receive and forward encrypted numbers between clients
        count = 0
        while count < 2:
            try:
                recipient_id = conn.recv(1024).decode("utf-8")  # Receive recipient_id from client
                encrypted_number_msg = conn.recv(1024)  # Receive encrypted_number_msg from client
                print(f"Encrypted number message from {client_id} to {recipient_id}")
                if recipient_id in self.clients:
                    self.clients[recipient_id]["conn"].send(
                        client_id.encode("utf-8"))  # Forward recipient_id to the recipient
                    self.clients[recipient_id]["conn"].send(
                        encrypted_number_msg)  # Forward encrypted_number_msg to the recipient
                    count += 1
            except Exception as e:
                print(f"Error: {e}")
                break

        thread = threading.Thread(target=self.handle_client, args=(client_id, conn,))
        thread.start()

    def handle_client(self, client_id, conn):
        try:
            print(f"{client_id} is now joined the chat")
            # Receive and forward encrypted numbers between clients
            while True:
                print(f"waiting message from {client_id}")
                recipient_id = conn.recv(1024).decode("utf-8")  # Receive recipient_id from client

                # Receive the length of the encrypted message
                encrypted_msg_len = int.from_bytes(conn.recv(4), byteorder='big')

                encrypted_number_msg = conn.recv(encrypted_msg_len)  # Receive encrypted_number_msg from client
                iv = conn.recv(16)
                print(f"Encrypted message from {client_id} to {recipient_id}")
                if recipient_id in self.clients:
                    self.clients[recipient_id]["conn"].send(
                        client_id.encode("utf-8"))  # Forward recipient_id to the recipient
                    time.sleep(0.1)
                    self.clients[recipient_id]["conn"].send(
                        encrypted_number_msg)  # Forward encrypted_number_msg to the recipient
                    time.sleep(0.1)
                    self.clients[recipient_id]["conn"].send(iv)
        except Exception as e:
            print(f"Error while handling client {client_id}: {e}")
            conn.close()

    def step_two(self, client_id, msg):
        try:
            # Load the server's private key
            server_private_key = load_private_key(self.key_file)
            # Decrypt the message
            decrypted_message = decrypt_asymmetric_with_symmetric_key(msg, server_private_key)
            # Split the message into DER certificate data and signature
            der_cert_data = decrypted_message[:720]
            signature = decrypted_message[720:]
            client_public_key = verify_certificate(der_cert_data, self.ca_file)
            is_valid = verify_signature(client_public_key, der_cert_data, signature)
            if not is_valid:
                raise Exception("Invalid Client signature")
            self.clients[client_id]["public_key"] = client_public_key
            self.clients[client_id]["stats"] = 2
            print("step 2 done, certificate and signature are valid")
        except Exception as e:
            print(f"Error: {e}")

    def step_three(self, client_id, conn):
        # Generate a random 16-byte number
        try:
            number_one = os.urandom(16)
            self.clients[client_id]["numbers"] = {}
            self.clients[client_id]["numbers"][1] = number_one
            # Encrypt the random number using the client's public key
            encrypt_number = encrypt_asymmetric(self.clients[client_id]["public_key"], number_one)
        except Exception as e:
            # Print the error message if encryption fails
            print(f"Error encrypting number_one: {e}")
            return

        # Load the server's private key
        try:
            server_private_key = load_private_key(self.key_file)
            # Sign the random number using the server's private key
            signature = sign_message(server_private_key, encrypt_number)
        except Exception as e:
            # Print the error message if signing fails
            print(f"Error signing number_one: {e}")
            return

        # Send the encrypted random number and its signature to the client
        try:
            conn.send(encrypt_number + signature)
            self.clients[client_id]["stats"] = 3
            print(f"step 3 done, you have send random number{number_one} and signature")
        except Exception as e:
            # Print the error message if sending fails
            print(f"Error sending encrypted data and signature: {e}")
            return

    def step_four(self, client_id, msg):
        try:
            # split the message into the encrypted number and signature
            encrypt_number = msg[:256]
            signature = msg[256:]

            # decrypt the number using the private key
            private_key = load_private_key(self.key_file)
            numbers = decrypt_asymmetric(private_key, encrypt_number)

            # verify the signature
            client_public_key = self.clients[client_id]["public_key"]
            is_valid = verify_signature(client_public_key, encrypt_number, signature)

            if not is_valid:
                # Handle the invalid signature case
                raise Exception("Invalid Server signature")
            number_one = numbers[:16]
            number_two = numbers[16:]
            if number_one != self.clients[client_id]["numbers"][1]:
                raise Exception("Invalid number")
            self.clients[client_id]["numbers"][2] = number_two
            self.clients[client_id]["stats"] = 4
            print(f"step 4 done, you have verify number {number_one} and signature, get number {number_two}")
        except Exception as e:
            print(f"Error: {e}")

    def step_five(self, client_id, conn):
        try:
            number_two = self.clients[client_id]["numbers"][2]
            # Encrypt the random number using the client's public key
            encrypt_number = encrypt_asymmetric(self.clients[client_id]["public_key"], number_two)
        except Exception as e:
            # Print the error message if encryption fails
            print(f"Error encrypting number_one: {e}")
            return

        # Load the server's private key
        try:
            server_private_key = load_private_key(self.key_file)
            # Sign the random number using the server's private key
            signature = sign_message(server_private_key, encrypt_number)
        except Exception as e:
            # Print the error message if signing fails
            print(f"Error signing number_one: {e}")
            return

        # Send the encrypted random number and its signature to the client
        try:
            conn.send(encrypt_number + signature)
            self.clients[client_id]["stats"] = 5
            print(f"step 5 done, you have send number {number_two} and signature")
        except Exception as e:
            # Print the error message if sending fails
            print(f"Error sending encrypted data and signature: {e}")
            return


if __name__ == "__main__":
    IP_ADDRESS = "127.0.0.1"
    PORT = 20005
    SERVER_CERT = "key/S_cert.pem"
    SERVER_KEY = "key/S_key.pem"
    SERVER_CA = f"key/ca_cert.pem"

    server = Server(IP_ADDRESS, PORT, SERVER_CERT, SERVER_KEY, SERVER_CA)
    server.start()
