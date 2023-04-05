import socket
import threading


class ChatClient:
    def __init__(self, ip, port, client_id):
        self.ip = ip
        self.port = port
        self.client_id = client_id
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        self.client.connect((self.ip, self.port))
        self.client.send(self.client_id.encode("utf-8"))  # Send client_id to the server
        print(f"Connected to server at {self.ip}:{self.port}")

        input_thread = threading.Thread(target=self.send_message)
        input_thread.start()

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

    def send_message(self):
        while True:
            recipient_id = input("Enter recipient id (A, B, or C): ")
            message = input("Enter your message: ")
            self.client.send(f"{recipient_id}:{message}".encode("utf-8"))  # Send message to the server


if __name__ == "__main__":
    IP_ADDRESS = "127.0.0.1"
    PORT = 20000
    CLIENT_ID = input("Enter your client id (A, B, or C): ")

    client = ChatClient(IP_ADDRESS, PORT, CLIENT_ID)
    client.connect()
