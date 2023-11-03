import socket
import time

# Server configuration
server_ip = '127.0.0.1'
server_port = 12345
buffer_size = 1024

# Create a UDP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((server_ip, server_port))

while True:
    data, client_address = server_socket.recvfrom(buffer_size)
    if data:
        start_time = time.time()  # Measure the start time
        total_data_received = len(data)

        # Receive data until it's all received
        while total_data_received < 102400:  # 100 kilobytes
            data, _ = server_socket.recvfrom(buffer_size)
            total_data_received += len(data)

        end_time = time.time()  # Measure the end time
        elapsed_time = end_time - start_time

        if elapsed_time == 0:
            throughput = 0.0  # Avoid division by zero
        else:
            throughput = total_data_received / elapsed_time / 1024  # Throughput in kilobytes per second

        server_socket.sendto(str(throughput).encode(), client_address)
