import socket
import threading
from cryptography.hazmat.primitives.serialization import load_pem_private_key
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
                conn.send(b'1')  # Send 1 to the client to indicate that the connection is established
                # start a thread to handle the handshake
                shackThread = threading.Thread(target=self.handshake, args=(client_id, conn,))
                shackThread.start()
                print(f"{client_id} starting handshake")
            except:
                if conn:
                    conn.close()
                continue

    def handshake(self, client_id, conn):
        while True:
            try:
                # step 2 : Check certificate and signature
                msg = conn.recv(2048)
                self.clients[client_id]["stats"] = 1
                self.step_two(client_id, msg)
                if self.clients[client_id]["stats"] == 2:
                    conn.send(b'1')
                    print("step 2 done, certificate and signature are valid")
                    thread = threading.Thread(target=self.handle_client, args=(client_id, conn,))
                    thread.start()
                break

            except Exception as e:
                print(f"Error: {e}")
                conn.close()
                break

    def handle_client(self, client_id, conn):

        while True:
            try:
                msg = conn.recv(1024).decode("utf-8")  # Receive message from client
                recipient_id, message = msg.split(":", 1)  # Extract recipient id and message
                print(f"Message from {client_id} to {recipient_id}: {message}")
                if recipient_id in self.clients:
                    self.clients[recipient_id]["conn"].send(
                        f"{client_id}: {message}".encode("utf-8"))  # Forward message to the recipient

            except Exception as e:
                print(f"Error: {e}")
                conn.close()
                del self.clients[client_id]
                break

    def step_two(self, client_id, msg):
        try:
            # Load the server's private key
            with open(self.key_file, "rb") as key_file:
                server_private_key_data = key_file.read()
                server_private_key = load_pem_private_key(server_private_key_data, password=None)

            # Decrypt the message
            decrypted_message = decrypt_asymmetric_with_symmetric_key(msg, server_private_key)
            # Split the message into DER certificate data and signature
            der_cert_data = decrypted_message[:720]
            signature = decrypted_message[720:]
            client_public_key = verify_certificate(der_cert_data, self.ca_file)
            verify_signature(client_public_key, der_cert_data, signature)
            self.clients[client_id]["public_key"] = client_public_key
            self.clients[client_id]["stats"] = 2
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    IP_ADDRESS = "127.0.0.1"
    PORT = 20002
    SERVER_CERT = "key/S_cert.pem"
    SERVER_KEY = "key/S_key.pem"
    SERVER_CA = f"key/ca_cert.pem"

    server = Server(IP_ADDRESS, PORT, SERVER_CERT, SERVER_KEY, SERVER_CA)
    server.start()
