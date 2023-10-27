
import dpkt
import sys
import datetime

def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    #variables for question 1 of part a
    #numsecureshell = 0 ????
    numftp = 0
    numdns = 0

    #variables for question 2 of part a (numhttp also used in question 1)
    numhttp = 0     
    numhttps = 0

    #q3
    ipdest = []

    #q4
    cantell

    # iterate over packets
    for timestamp, data in pcap:

        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        # extract network layer data
        ip = eth.data

        # do not proceed if there is no transport layer data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        # extract transport layer data
        tcp = ip.data

        # do not proceed if there is no application layer data
        # here we check length because we don't know protocol yet
        if not len(tcp.data) > 0:
            continue

        #1
        if ip.dport == 21 or ip.sport == 21:
            numftp += 1
        if ip.dport == 53 or ip.sport == 53:
            numdns += 1
        
        
        #2
        if tcp.dport == 80 or tcp.sport == 80:
            numhttp += 1
        if tcp.dport == 443 or tcp.sport == 443:
            numhttps += 1


        #3
        ipdest.append((ip.dst, str(datetime.datetime.utcfromtimestamp(timestamp))))

        #4

        if tcp.dport == 80:
            try:
                http = dpkt.http.Request(tcp.data)
                #print(http.headers)
                browser = http.headers["user-agent"]
                cantell = 'true'
            except:
                cantell = 'false'
        

        # extract application layer data
        ## if destination port is 80, it is a http request
#        if tcp.dport == 80:
#            try:
#                http = dpkt.http.Request(tcp.data)
#                print(http.headers)
#            except:
#                print("Malformed HTTP Request packet")
        ## if source port is 80, it is a http response
#        elif tcp.sport == 80:
#            try:
#                http = dpkt.http.Response(tcp.data)
#                print(http.headers)
#            except:
#                print("Malformed HTTP Response packet")
    

    #Q1
    print('Number of HTTP packets: ', numhttp)

    if pcap_file == 'example.pcap' or pcap_file == 'httpforever.pcap':
        print('Number of HTTPS packets: ', numhttps)    #Q2

    print('Number of FTP packets: ', numftp)
    print('Number of DNS packets: ', numdns)

    #Q3
    for packet in ipdest:
        print('IP: ', packet[0])
        print('Timestamp: ', packet[1])


    #Q4
    if pcap_file == 'example.pcap' or pcap_file == 'httpforever.pcap':
        if cantell == 'true':
            print('Browser: ', browser)
        else:
            print("Browser cannot be found")

    


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        parse_pcap(sys.argv[1])