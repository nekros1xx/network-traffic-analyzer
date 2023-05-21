import socket
import struct
import pcapy

def analyze_network_traffic(interface, packet_count):
    # open the network interface in promiscuous mode
    capture = pcapy.open_live(interface, 65536, True, 0)

    print(f"Capturing network traffic on interface {interface}...\n")

    packet_num = 0
    try:
        while packet_num < packet_count:
            # single packet
            header, packet = capture.next()
            
            # ethernet header information
            eth_length = 14
            eth_header = packet[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)
            source_mac = ':'.join(['{:02x}'.format(x) for x in eth[0]])
            dest_mac = ':'.join(['{:02x}'.format(x) for x in eth[1]])
            protocol = socket.htons(eth[2])

            print(f"Packet #{packet_num + 1}")
            print(f"Source MAC: {source_mac}")
            print(f"Destination MAC: {dest_mac}")
            print(f"Protocol: {protocol}")

            packet_num += 1
    except pcapy.PcapError as e:
        print(f"An error occurred while capturing packets: {e}")

    capture.close()

if __name__ == "__main__":
    interface = input("Enter the network interface to capture traffic from: ")
    packet_count = int(input("Enter the number of packets to capture: "))

    analyze_network_traffic(interface, packet_count)
