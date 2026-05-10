import pandas as pd
import time
import random
import os

from scapy.all import sniff
from scapy.layers.inet import IP


dataset = []


OUTPUT_FILE = r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\datasets\training_dataset.csv"


print("Generating training dataset...\n")


while True:

    packet_window = []


    def capture(packet):

        if packet.haslayer(IP):

            packet_window.append({

                "protocol": packet[IP].proto,
                "packet_size": len(packet)

            })


    sniff(

        prn=capture,
        timeout=10,
        store=False
    )


    df = pd.DataFrame(packet_window)


    if len(df) == 0:
        continue


    packets_per_window = len(df)

    avg_packet_size = df[
        "packet_size"
    ].mean()

    tcp_count = (
        df["protocol"] == 6
    ).sum()

    udp_count = (
        df["protocol"] == 17
    ).sum()


    # Basic labeling logic

    label = 0


    if packets_per_window > 1200:

        label = 1


    if tcp_count > 1000:

        label = 1


    if avg_packet_size > 1300:

        label = 1


    dataset.append({

        "packets_per_window":
        packets_per_window,

        "avg_packet_size":
        avg_packet_size,

        "tcp_count":
        tcp_count,

        "udp_count":
        udp_count,

        "label":
        label
    })


    dataset_df = pd.DataFrame(dataset)


    dataset_df.to_csv(

        OUTPUT_FILE,
        index=False
    )


    print("\nWindow Captured")

    print(dataset_df.tail())


    print(
        f"\nTotal Samples: {len(dataset_df)}"
    )


    if label == 1:

        print(
            "Suspicious traffic pattern recorded."
        )

    else:

        print(
            "Normal traffic recorded."
        )


    print("-" * 60)


    time.sleep(1)