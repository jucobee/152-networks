import dpkt
import sys
import socket

def part1b(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    currentsecret = 1
    secret = []

    sourcearray = []
    destarray = []

    packetinfo = []
    packetnum = 0



    # iterate over packets
    for timestamp, data in pcap:

        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
            print('yo')
            continue
        
        # extract network layer data
        ip = eth.data

        if pcap_file == 'ass1_1.pcap':
        # do not proceed if there is no transport layer data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                print('yo2')
                continue

        # extract transport layer data
        tcp = ip.data

        # do not proceed if there is no application layer data
        # here we check length because we don't know protocol yet
        #if not len(tcp.data) > 0:
            #print('yo3')
            #continue

        if pcap_file == 'ass1_1.pcap':  
            
            if tcp.dport == 80 and len(tcp.data) > 0:
                http = dpkt.http.Request(tcp.data)

                if currentsecret == 1:
                    secret.append((http.method, http.uri, http.version))

                if currentsecret == 2:
                    secret.append(http.headers)

                if currentsecret == 3: 
                    secret.append(http.body)
                    
                currentsecret += 1

        packetnum += 1       
        if pcap_file == 'ass1_1.pcap':
            packetinfo.append((packetnum, socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)))
        else:
            packetinfo.append((packetnum, socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)))
        
        if ip.src in sourcearray:
            continue
        else:
            sourcearray.append(ip.src)

        if ip.dst in destarray:
            continue
        else:
            destarray.append(ip.dst)        



    print('\n')
    
    # Secrets
    if pcap_file == 'ass1_1.pcap':  
    
        print('Secrets: ')
        print("Secret 1: ", secret[0]) 
        print("Secret 2: ", secret[1]) 
        print("Secret 3: ", secret[2]) 

        print('\n')

    #1. List the unique source and destination IP addresses do you see in each pcap file?
        #Make two arrays for source and destination IP addresses, in each packet check if already in array

    print("Source IPs: ")
    for ip in sourcearray:
        if pcap_file == 'ass1_1.pcap':
            print(socket.inet_ntop(socket.AF_INET6, ip))
        else:
            print(socket.inet_ntoa(ip))

    
    print("Destination IPs: ")
    for ip in destarray:
        if pcap_file == 'ass1_1.pcap':
            print(socket.inet_ntop(socket.AF_INET6, ip))
        else:
            print(socket.inet_ntoa(ip))

    print('\n')
    #2. For both pcaps, iterate over the packets and print the packet number, source ip address and destination ip
    #address for each packet. The list you print should be sorted in ascending order of packet number.
    
    print('packet_number, source ip, destination ip')
    for packet in packetinfo:
        
        print(packet[0], ',', packet[1], ',', packet[2]) 

    print('\n')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        part1b(sys.argv[1])