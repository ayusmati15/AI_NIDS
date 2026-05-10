import os
import pandas as pd
import time

from scapy.all import sniff
from scapy.layers.inet import IP

from sklearn.ensemble import IsolationForest


packet_data = []


def process_packet(packet):

    if packet.haslayer(IP):

        protocol = packet[IP].proto
        packet_size = len(packet)

        packet_data.append({

            "protocol": protocol,
            "packet_size": packet_size
        })


print("Collecting baseline traffic...\n")


sniff(

    prn=process_packet,
    timeout=30,
    store=False
)


baseline_df = pd.DataFrame(packet_data)


features = pd.DataFrame([{

    "packets_per_window": len(baseline_df),

    "avg_packet_size":
    baseline_df["packet_size"].mean(),

    "tcp_count":
    (baseline_df["protocol"] == 6).sum(),

    "udp_count":
    (baseline_df["protocol"] == 17).sum()

}])


model = IsolationForest(

    contamination=0.1,
    random_state=42
)


model.fit(features)


print("\nBaseline learned.")
print("Starting real-time detection...\n")


output_file = r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\datasets\live_traffic.csv"

pd.DataFrame(columns=[

    "packets_per_window",
    "avg_packet_size",
    "tcp_count",
    "udp_count",
    "anomaly"

]).to_csv(output_file, index=False)


while True:

    live_packets = []


    def live_capture(packet):

        if packet.haslayer(IP):

            live_packets.append({

                "protocol": packet[IP].proto,
                "packet_size": len(packet)

            })


    sniff(

        prn=live_capture,
        timeout=10,
        store=False
    )


    live_df = pd.DataFrame(live_packets)


    if len(live_df) == 0:
        continue


    live_features = pd.DataFrame([{

        "packets_per_window": len(live_df),

        "avg_packet_size":
        live_df["packet_size"].mean(),

        "tcp_count":
        (live_df["protocol"] == 6).sum(),

        "udp_count":
        (live_df["protocol"] == 17).sum()

    }])


    prediction = model.predict(live_features)[0]


    live_features["anomaly"] = prediction
    print(live_features.columns)
    live_features.to_csv(

        output_file,
        mode="a",
        header=False,
        index=False
    )


    print("\nTraffic Window Analysis")

    print(live_features)


    if prediction == -1:

        print("\nALERT: Suspicious traffic detected!")

    else:

        print("\nTraffic appears normal.")


    print("-" * 60)

    time.sleep(1)