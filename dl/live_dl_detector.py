import sys
import os

sys.path.append(

    os.path.abspath(

        os.path.join(
            os.path.dirname(__file__),
            ".."
        )
    )
)

from database.log_threat import log_threat
import pandas as pd
import numpy as np
import time

from sklearn.preprocessing import MinMaxScaler

import torch
import torch.nn as nn

from scapy.all import sniff
from scapy.layers.inet import IP


# =========================
# AUTOENCODER MODEL
# =========================

class Autoencoder(nn.Module):

    def __init__(self):

        super().__init__()


        self.encoder = nn.Sequential(

            nn.Linear(4, 8),

            nn.ReLU(),

            nn.Linear(8, 2)
        )


        self.decoder = nn.Sequential(

            nn.Linear(2, 8),

            nn.ReLU(),

            nn.Linear(8, 4),

            nn.Sigmoid()
        )


    def forward(self, x):

        encoded = self.encoder(x)

        decoded = self.decoder(encoded)

        return decoded


# =========================
# LOAD TRAINED MODEL
# =========================

model = Autoencoder()


model.load_state_dict(

    torch.load(

        r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\dl\autoencoder_model.pth"
    )
)


model.eval()


print("\nDeep Learning Model Loaded.\n")


# =========================
# LOAD DATASET FOR SCALER
# =========================

df = pd.read_csv(

    r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\datasets\training_dataset.csv"
)


X = df[[

    "packets_per_window",
    "avg_packet_size",
    "tcp_count",
    "udp_count"

]].values


scaler = MinMaxScaler()

scaler.fit(X)


# =========================
# LIVE MONITORING
# =========================

print("Starting live DL traffic analysis...\n")


while True:

    live_packets = []


    def capture(packet):

        if packet.haslayer(IP):

            live_packets.append({

                "protocol": packet[IP].proto,
                "packet_size": len(packet)

            })


    sniff(

        prn=capture,
        timeout=10,
        store=False
    )


    live_df = pd.DataFrame(live_packets)


    if len(live_df) == 0:
        continue


    live_features = np.array([[

        len(live_df),

        live_df["packet_size"].mean(),

        (live_df["protocol"] == 6).sum(),

        (live_df["protocol"] == 17).sum()

    ]])


    # Normalize

    live_scaled = scaler.transform(live_features)


    # Tensor

    live_tensor = torch.FloatTensor(live_scaled)


    # Reconstruction

    with torch.no_grad():

        reconstructed = model(live_tensor)


        error = torch.mean(

            (live_tensor - reconstructed) ** 2
        ).item()


    print("\n======================")

    print(f"Reconstruction Error: {error:.6f}")


    # Threshold logic
    if error > 0.20:

        print("ALERT: Suspicious traffic detected!")


        log_threat(

          threat_level="HIGH",

           packets_per_window=len(live_df),

           avg_packet_size=live_df[
               "packet_size"
           ].mean(),

           tcp_count=(
               live_df["protocol"] == 6
           ).sum(),

           reconstruction_error=error,

            reason="Deep Learning anomaly detected"
         )

    else:

       print("Traffic appears normal.")

    print("======================\n")


    time.sleep(1)