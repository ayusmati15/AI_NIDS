from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import csv
from datetime import datetime


csv_file = "network_traffic.csv"


with open(csv_file, mode="w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "packet_size"
    ])


def process_packet(packet):

    if packet.haslayer(IP):

        timestamp = datetime.now()

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        protocol = packet[IP].proto

        packet_size = len(packet)

        print(
            f"{timestamp} | "
            f"{src_ip} -> {dst_ip} | "
            f"Protocol: {protocol} | "
            f"Size: {packet_size}"
        )

        with open(csv_file, mode="a", newline="") as file:

            writer = csv.writer(file)

            writer.writerow([
                timestamp,
                src_ip,
                dst_ip,
                protocol,
                packet_size
            ])


print("Starting packet capture...\n")

sniff(prn=process_packet, store=False)