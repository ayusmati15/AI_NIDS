import pandas as pd
import numpy as np

from sklearn.preprocessing import MinMaxScaler

import torch
import torch.nn as nn
import torch.optim as optim


# =========================
# LOAD DATASET
# =========================

df = pd.read_csv(

    r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\datasets\training_dataset.csv"
)


print("\nDataset Loaded Successfully.\n")

print(df.head())


# =========================
# SELECT FEATURES
# =========================

X = df[[

    "packets_per_window",
    "avg_packet_size",
    "tcp_count",
    "udp_count"

]].values


# =========================
# NORMALIZE DATA
# =========================

scaler = MinMaxScaler()

X_scaled = scaler.fit_transform(X)


# Convert to tensor

X_tensor = torch.FloatTensor(X_scaled)


# =========================
# AUTOENCODER MODEL
# =========================

class Autoencoder(nn.Module):

    def __init__(self):

        super().__init__()


        # Encoder

        self.encoder = nn.Sequential(

            nn.Linear(4, 8),

            nn.ReLU(),

            nn.Linear(8, 2)
        )


        # Decoder

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
# INITIALIZE MODEL
# =========================

model = Autoencoder()


criterion = nn.MSELoss()


optimizer = optim.Adam(

    model.parameters(),
    lr=0.001
)


# =========================
# TRAIN MODEL
# =========================

epochs = 100


print("\nStarting Training...\n")


for epoch in range(epochs):

    output = model(X_tensor)

    loss = criterion(output, X_tensor)


    optimizer.zero_grad()

    loss.backward()

    optimizer.step()


    if epoch % 10 == 0:

        print(

            f"Epoch [{epoch}/{epochs}] "
            f"Loss: {loss.item():.6f}"
        )


print("\nTraining Complete.")


# =========================
# RECONSTRUCTION ERRORS
# =========================

with torch.no_grad():

    reconstructed = model(X_tensor)

    errors = torch.mean(

        (X_tensor - reconstructed) ** 2,
        dim=1
    )


# =========================
# THRESHOLD
# =========================

threshold = errors.mean() + 2 * errors.std()


print(f"\nAnomaly Threshold: {threshold}")


# =========================
# DETECT ANOMALIES
# =========================

anomalies = errors > threshold


print("\nDetected Anomalies:\n")


for i, anomaly in enumerate(anomalies):

    if anomaly:

        print(

            f"Row {i} appears suspicious "
            f"(Error: {errors[i]:.6f})"
        )


# =========================
# SAVE MODEL
# =========================

torch.save(

    model.state_dict(),

    r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\dl\autoencoder_model.pth"
)


print("\nModel saved successfully.")