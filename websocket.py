import socket
from socket import create_connection

ws = socket.create_connection(("127.168.1.168/ws/", 3456))