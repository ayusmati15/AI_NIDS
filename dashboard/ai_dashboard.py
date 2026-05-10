import streamlit as st
import pandas as pd
import time
import os

st.set_page_config(

    page_title="AI NIDS Dashboard",
    layout="wide"
)


st.title("AI-Powered Network Intrusion Detection System")


DATA_FILE = r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\datasets\live_traffic.csv"


placeholder = st.empty()


while True:

    with placeholder.container():

        st.subheader("Live Traffic Monitoring")


        if os.path.exists(DATA_FILE):

            df = pd.read_csv(DATA_FILE)


            if len(df) > 0:

                latest = df.iloc[-1]


                col1, col2, col3 = st.columns(3)


                with col1:

                    st.metric(

                        "Packets/Window",

                        int(latest[
                            "packets_per_window"
                        ])
                    )


                with col2:

                    st.metric(

                        "Average Packet Size",

                        round(
                            latest[
                                "avg_packet_size"
                            ],
                            2
                        )
                    )


                with col3:

                    st.metric(

                        "TCP Count",

                        int(latest[
                            "tcp_count"
                        ])
                    )


                # Threat logic

                threat_score = 0


                if latest["anomaly"] == -1:

                    threat_score += 40


                if latest[
                    "packets_per_window"
                ] > 1000:

                    threat_score += 25


                if latest[
                    "tcp_count"
                ] > 900:

                    threat_score += 20


                st.subheader("Threat Intelligence")


                if threat_score >= 50:

                    st.error(

                        f"HIGH THREAT DETECTED "
                        f"(Score: {threat_score})"
                    )

                elif threat_score >= 25:

                    st.warning(

                        f"MEDIUM THREAT "
                        f"(Score: {threat_score})"
                    )

                else:

                    st.success(

                        f"LOW THREAT "
                        f"(Score: {threat_score})"
                    )


                st.subheader("Traffic History")


                st.line_chart(

                    df[
                        "packets_per_window"
                    ]
                )


                st.subheader(
                    "Recent Traffic Windows"
                )


                st.dataframe(

                    df.tail(10)
                )


            else:

                st.warning(
                    "No traffic data yet."
                )

        else:

            st.warning(
                "live_traffic.csv not found."
            )


    time.sleep(5)