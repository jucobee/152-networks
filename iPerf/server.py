import socket
import time

# specify host and port to receive messages on
HOST = '127.0.0.1'
PORT = 5500

# create a new datagram socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
    # bind this socket to OS
    server_socket.bind((HOST, PORT))

    while True:
        print("UDP server listening on {}:{}".format(HOST, PORT))
        # data -> message, addr -> (client_addr, client_port)
        data, addr = server_socket.recvfrom(1024)
        data_size = len(data)
        
        if data:
            start_time = time.time()
            end_time = time.time()

            # receive data until size exceeds 100 kb
            while data_size < 102400:
                data, addr = server_socket.recvfrom(1024)
                data_size += len(data)
                print(f"Received {len(data)} bytes from {addr}")
            
            end_time = time.time()

            # throughput = bytes / duration
            throughput = data_size / (end_time - start_time) / 1024 # [KB/sec]
            server_socket.sendto(str(throughput).encode(), addr)  
            print("Sent throughput to client")

server_socket.close()
