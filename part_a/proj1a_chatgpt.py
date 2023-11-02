#THIS VERSION OF THE CODE IS MADE ENTIRELY FROM CHATGPT WITH ONLY MINOR TWEAKS
# https://chat.openai.com/share/42a45071-dd66-4e84-a04c-1ec5bd26e781

import dpkt
import socket
import struct
import sys

def format_ip_address(ip_address):
    return socket.inet_ntoa(ip_address)

def parse_pcap(pcap):

    protocol_counts = {
        "HTTP": 0,
        "HTTPS": 0,
        "DNS": 0,
        "FTP": 0,
        "SMTP": 0,
        "POP3": 0,
        "SSH": 0,
        "Other": 0
    }

    activity_records = []

    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            if isinstance(ip, dpkt.ip.IP) and ip.data.__class__.__name__ == 'TCP':
                    timestamp = str(ts)
                    dest_ip = format_ip_address(ip.dst)
                    if ip.data.dport == 80 or ip.data.sport == 80:
                        protocol_counts["HTTP"] += 1
                    elif ip.data.dport == 443 or ip.data.sport == 443:
                        protocol_counts["HTTPS"] += 1
                    elif ip.data.dport == 53 or ip.data.sport == 53:
                        protocol_counts["DNS"] += 1
                    elif ip.data.dport == 21 or ip.data.sport == 21:
                        protocol_counts["FTP"] += 1
                    elif ip.data.dport == 25 or ip.data.sport == 25:
                        protocol_counts["SMTP"] += 1
                    elif ip.data.dport == 110 or ip.data.sport == 110:
                        protocol_counts["POP3"] += 1
                    elif ip.data.dport == 22 or ip.data.sport == 22:
                        protocol_counts["SSH"] += 1
            elif isinstance(ip, dpkt.ip.IP):
                timestamp = str(ts)
                dest_ip = format_ip_address(ip.dst)
                print(f"Timestamp: {timestamp}, Destination IP: {dest_ip}")

        except dpkt.dpkt.UnpackError:
            pass

    for protocol, count in protocol_counts.items():
        if count > 0:
            print(f"Protocol: {protocol}, Count: {count}")


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        with open(sys.argv[1], 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            activity_records = parse_pcap(pcap)

