import pandas as pd
import streamlit as st
import plotly.express as px


st.set_page_config(

    page_title="AI Network IDS",
    layout="wide"
)


st.title(
    "AI-Powered Network Intrusion Detection System"
)


LIVE_FILE = r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\datasets\live_traffic.csv"


try:

    df = pd.read_csv(LIVE_FILE)


    if len(df) == 0:

        st.warning("No traffic data yet.")


    else:

        latest = df.iloc[-1]


        col1, col2, col3 = st.columns(3)


        col1.metric(

            "Packets / Window",

            int(latest[
                "packets_per_window"
            ])
        )


        col2.metric(

            "Average Packet Size",

            round(
                latest[
                    "avg_packet_size"
                ],
                2
            )
        )


        col3.metric(

            "Anomaly Status",

            "Suspicious"

            if latest["anomaly"] == -1

            else "Normal"
        )


        st.subheader(
            "Traffic History"
        )


        fig1 = px.line(

            df,

            y="packets_per_window",

            title="Packets Over Time"
        )


        st.plotly_chart(

            fig1,

            use_container_width=True
        )


        fig2 = px.line(

            df,

            y="avg_packet_size",

            title="Average Packet Size"
        )


        st.plotly_chart(

            fig2,

            use_container_width=True
        )


        protocol_df = pd.DataFrame({

            "Protocol": ["TCP", "UDP"],

            "Count": [

                latest["tcp_count"],

                latest["udp_count"]
            ]
        })


        fig3 = px.pie(

            protocol_df,

            names="Protocol",

            values="Count",

            title="Protocol Distribution"
        )


        st.plotly_chart(

            fig3,

            use_container_width=True
        )


        if latest["anomaly"] == -1:

            st.error(
                "ALERT: Suspicious traffic detected!"
            )

        else:

            st.success(
                "Traffic appears normal."
            )


except Exception as e:

    st.error(f"Error: {e}")


st.caption(
    "Refresh page manually to update live data."
)