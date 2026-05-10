import pandas as pd
import time


LIVE_FILE = r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\datasets\live_traffic.csv"


print("Threat Intelligence Engine Started...\n")


while True:

    try:

        df = pd.read_csv(LIVE_FILE)


        if len(df) == 0:

            time.sleep(5)
            continue


        latest = df.iloc[-1]


        threat_score = 0

        reasons = []


        # ML anomaly

        if latest["anomaly"] == -1:

            threat_score += 40

            reasons.append(
                "ML anomaly detected"
            )


        # Packet spike

        if latest["packets_per_window"] > 1000:

            threat_score += 25

            reasons.append(
                "High packet volume"
            )


        # Large packet sizes

        if latest["avg_packet_size"] > 1200:

            threat_score += 15

            reasons.append(
                "Large packet sizes"
            )


        # Heavy TCP traffic

        if latest["tcp_count"] > 900:

            threat_score += 20

            reasons.append(
                "Heavy TCP activity"
            )


        # Severity

        if threat_score >= 80:

            level = "CRITICAL"

        elif threat_score >= 50:

            level = "HIGH"

        elif threat_score >= 25:

            level = "MEDIUM"

        else:

            level = "LOW"


        print("\n==========================")

        print(f"Threat Score : {threat_score}")

        print(f"Threat Level : {level}")


        print("\nReasons:")


        if len(reasons) == 0:

            print("No major threats detected.")

        else:

            for r in reasons:

                print(f"- {r}")


        print("==========================\n")


    except Exception as e:

        print(f"Error: {e}")


    time.sleep(10)