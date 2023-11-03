import socket
import time

# specify server host and port to connect to
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5500

# maximum transmission unit
MTU = 1024

# open a new datagram socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    client_socket.settimeout(5) # set timeout to 5 seconds
    # craft message body
    message = "a" * 102400 # 100 KB string

    # send message
    for i in range(0, len(message), MTU):
        # .encode() converts to bytes
        segment = message[i:i + MTU]
        client_socket.sendto(segment.encode(), (SERVER_HOST, SERVER_PORT))

    time.sleep(1)
    
    # receive return message
    response, addr = client_socket.recvfrom(MTU)
    print("{:.2f} KB/sec".format(float(response.decode())))

client_socket.close()