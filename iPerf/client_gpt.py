import socket

# Client configuration
server_ip = '127.0.0.1'
server_port = 12345
buffer_size = 1024

# Create a UDP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
data_to_send = b'X' * 102400  # 100 kilobytes of data

# Send data to the server
client_socket.sendto(data_to_send, (server_ip, server_port))

# Receive throughput from the server
response, _ = client_socket.recvfrom(buffer_size)

if response:
    throughput = float(response.decode())
    print(f"Throughput: {throughput} KB/s")

# Close the client socket
client_socket.close()
