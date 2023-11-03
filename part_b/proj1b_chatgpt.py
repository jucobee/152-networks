#THIS VERSION OF THE CODE IS MADE ENTIRELY FROM CHATGPT WITH ONLY MINOR TWEAKS
# https://chat.openai.com/share/64cf53b1-2462-48fc-82b4-f6f767ef2c68

import dpkt
import sys

def list_unique_ips_and_packet_info(file_path):
    unique_src_ips = set()
    unique_dst_ips = set()
    packets = []

    with open(file_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        packet_num = 1
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                src_ip = '.'.join(map(str, map(int, ip.src)))
                dst_ip = '.'.join(map(str, map(int, ip.dst)))
                unique_src_ips.add(src_ip)
                unique_dst_ips.add(dst_ip)
                packets.append((packet_num, src_ip, dst_ip))
                packet_num += 1
            except Exception as e:
                print(f"Error processing packet: {e}")

    unique_src_ips = sorted(unique_src_ips)
    unique_dst_ips = sorted(unique_dst_ips)
    packets.sort(key=lambda x: x[0])

    print("Unique source IP addresses:")
    for ip in unique_src_ips:
        print(ip)

    print("\nUnique destination IP addresses:")
    for ip in unique_dst_ips:
        print(ip)

    print("\nPacket Information:")
    for packet in packets:
        print(f"Packet Number: {packet[0]}, Source IP: {packet[1]}, Destination IP: {packet[2]}")



if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("No pcap file specified!")
    else:
        list_unique_ips_and_packet_info(sys.argv[1])
