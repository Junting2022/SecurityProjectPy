import socket
import threading


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}  # Dictionary to store clients

    def start(self):
        self.server.bind((self.ip, self.port))
        self.server.listen(3)  # Listen for up to 3 connections
        print(f"Server started at {self.ip}:{self.port}")

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


if __name__ == "__main__":
    IP_ADDRESS = "127.0.0.1"
    PORT = 12345
    server = Server(IP_ADDRESS, PORT)
    server.start()
