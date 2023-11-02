
import dpkt
import sys
import datetime
import socket

def part1a(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    #variables for question 1 of part a
    numssh = 0 
    numftp = 0
    numdns = 0

    #variables for question 2 of part a (numhttp also used in question 1)
    numhttp = 0     
    numhttps = 0

    #q3
    ipdest = []

    #q4
    cantell = 'false'

    # iterate over packets
    for timestamp, data in pcap:

        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        # extract network layer data
        ip = eth.data

        # remove unrelated ARP data
        if isinstance(ip.data, dpkt.arp.ARP):
            continue

        # extract transport layer data
        tcp = ip.data

        # do not proceed if there is no application layer data
        # here we check length because we don't know protocol yet
        #if not len(tcp.data) > 0:
            #continue

        #1
        if not isinstance(ip.data, dpkt.icmp.ICMP) and not isinstance(ip.data, dpkt.igmp.IGMP) and not isinstance(ip.data, dpkt.icmp.ICMP) and len(tcp.data) > 0:
            if tcp.dport == 22 or tcp.sport == 22:  
                numssh += 1
            if tcp.dport == 21 or tcp.sport == 21:
                numftp += 1
            if tcp.dport == 53 or tcp.sport == 53:
                numdns += 1
        
        
        #2
            if tcp.dport == 80 or tcp.sport == 80:
                numhttp += 1
            if tcp.dport == 443 or tcp.sport == 443:
                numhttps += 1


        #3
        ipdest.append((socket.inet_ntoa(ip.dst), str(datetime.datetime.fromtimestamp(timestamp, datetime.UTC))))

        #4

        if pcap_file == 'httpforever.pcap':
            if tcp.dport == 80 and cantell=='false':
                http = dpkt.http.Request(tcp.data)
                browser = http.headers["user-agent"]
                cantell = 'true'

        #if pcap_file == 'example.pcap':
             #if tcp.dport == 1900:
                 #print(tcp.data)
                 #no way to access ssdp headers


    print('\n')

    #Q1
    print('Question 1:')
    if numhttp > 0:
        print('Number of HTTP packets: ', numhttp)
    if numftp > 0:
        print('Number of FTP packets: ', numftp)
    if numdns > 0:
        print('Number of DNS packets: ', numdns)
    if numssh > 0:
        print('Number of SSH packets: ', numssh)

    print('\n')

    #Q2
    if pcap_file == 'example.pcap' or pcap_file == 'httpforever.pcap':
        print('Question 2:')
        print('Number of HTTP packets: ', numhttp)
        print('Number of HTTPS packets: ', numhttps)    
        print('\n')

    #Q3
    print('Question 3:')
    for packet in ipdest:
        print('IP: ', packet[0], '  Timestamp: ', packet[1])
        #print('Timestamp: ', packet[1])

    print('\n')

    #Q4
    
    if pcap_file == 'example.pcap' or pcap_file == 'httpforever.pcap':
        print('Question 4:')
        if cantell == 'true':
            print('Browser: ', browser)
        else:
            print("Browser cannot be found")
        print('\n')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        part1a(sys.argv[1])