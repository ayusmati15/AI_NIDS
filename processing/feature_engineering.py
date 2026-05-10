import pandas as pd


df = pd.read_csv("../network_traffic.csv")


df["timestamp"] = pd.to_datetime(df["timestamp"])


df = df.sort_values("timestamp")


df.set_index("timestamp", inplace=True)


window_features = df.resample("10s").agg({

    "packet_size": ["count", "mean"],
    "protocol": lambda x: (x == 6).sum(),
})


window_features.columns = [

    "packets_per_window",
    "avg_packet_size",
    "tcp_count"
]


udp_counts = df.resample("10s")["protocol"].apply(
    lambda x: (x == 17).sum()
)

window_features["udp_count"] = udp_counts


window_features = window_features.fillna(0)


print(window_features.head())


window_features.to_csv("../datasets/window_features.csv")


print("\nFeature engineering complete.")
print("Saved to datasets/window_features.csv")