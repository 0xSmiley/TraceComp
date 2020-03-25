
import socket

HOST = 'localhost'  # Standard loopback interface address (localhost)
PORT = 8081        # Port to listen on (non-privileged ports are > 1023)

server_socket = socket.socket()
server_socket.bind((HOST, PORT))
server_socket.listen(2)

while True:
    conn, address = server_socket.accept()  # accept new connection
    data = conn.recv(1024).decode()
    if not data:
        # if data is not received break
        break
    print("Received: " + str(data))


#python3 server.py