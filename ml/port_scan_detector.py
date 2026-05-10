from collections import defaultdict
import time

from scapy.all import sniff
from scapy.layers.inet import IP, TCP


port_activity = defaultdict(set)

TIME_WINDOW = 20

PORT_THRESHOLD = 15


start_time = time.time()


def detect_scan(packet):

    global start_time


    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src

        dst_port = packet[TCP].dport


        port_activity[src_ip].add(dst_port)


        current_time = time.time()


        if current_time - start_time > TIME_WINDOW:


            print("\n--- Port Scan Analysis ---\n")


            for ip, ports in port_activity.items():


                print(f"{ip} accessed {len(ports)} ports")


                if len(ports) > PORT_THRESHOLD:


                    print(
                        f"ALERT: Possible port scan from {ip}"
                    )


            port_activity.clear()

            start_time = current_time


print("Monitoring for port scans...\n")


sniff(

    prn=detect_scan,
    store=False
)