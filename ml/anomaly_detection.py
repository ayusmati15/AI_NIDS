import pandas as pd

from sklearn.ensemble import IsolationForest


df = pd.read_csv("../datasets/window_features.csv")


features = df[[
    "packets_per_window",
    "avg_packet_size",
    "tcp_count",
    "udp_count"
]]


model = IsolationForest(

    contamination=0.1,
    random_state=42
)


model.fit(features)


predictions = model.predict(features)


df["anomaly"] = predictions


print(df[[
    "packets_per_window",
    "avg_packet_size",
    "tcp_count",
    "udp_count",
    "anomaly"
]].head(20))


df.to_csv("../datasets/anomaly_results.csv", index=False)


print("\nAnomaly detection complete.")
print("Results saved to datasets/anomaly_results.csv")