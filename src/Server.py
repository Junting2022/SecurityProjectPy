import socket
import ssl
import threading


class Server:
    def __init__(self, ip, port, cert_file, key_file):
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Set the SO_REUSEADDR option
        self.clients = {}  # Dictionary to store clients
        self.cert_file = cert_file
        self.key_file = key_file

    def start(self):
        self.server.bind((self.ip, self.port))
        self.server.listen(3)
        print(f"Secure Chat Server started at {self.ip}:{self.port}")

        # Wrap the server socket with TLS
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        self.server = context.wrap_socket(self.server, server_side=True)

        while True:
            conn, addr = self.server.accept()  # Accept incoming connections
            print(f"Connected to {addr}")
            client_id = conn.recv(1024).decode("utf-8")  # Receive client id (A, B, or C)
            self.clients[client_id] = conn
            thread = threading.Thread(target=self.handle_client, args=(client_id, conn,))
            thread.start()

    def handle_client(self, client_id, conn):

        while True:
            try:
                msg = conn.recv(1024).decode("utf-8")  # Receive message from client
                if msg:
                    if msg.startswith("GET_CERT:"):
                        requested_entity = msg.split(":")[1].strip()
                        self.send_entity_cert(conn, requested_entity)

                    else:
                        recipient_id, message = msg.split(":", 1)  # Extract recipient id and message
                        print(f"Message from {client_id} to {recipient_id}: {message}")
                        if recipient_id in self.clients:
                            self.clients[recipient_id].send(
                                f"{client_id}: {message}".encode("utf-8"))  # Forward message to the recipient

            except Exception as e:
                print(f"Error: {e}")
                conn.close()
                del self.clients[client_id]
                break

    @staticmethod
    def send_entity_cert(client_socket, requested_entity):
        try:
            with open(f"{requested_entity}_cert.pem", "rb") as f:
                cert_data = f.read()
            client_socket.send(cert_data)
        except FileNotFoundError:
            client_socket.send(b"Certificate not found.")


if __name__ == "__main__":
    IP_ADDRESS = "127.0.0.1"
    PORT = 20000
    SERVER_CERT = "server_cert.pem"
    SERVER_KEY = "server_key.pem"

    server = Server(IP_ADDRESS, PORT, SERVER_CERT, SERVER_KEY)
    server.start()
