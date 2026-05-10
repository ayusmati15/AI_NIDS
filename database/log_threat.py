import sqlite3
from datetime import datetime


def log_threat(

    threat_level,
    packets_per_window,
    avg_packet_size,
    tcp_count,
    reconstruction_error,
    reason
):

    connection = sqlite3.connect(

        r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\database\threats.db"
    )


    cursor = connection.cursor()


    cursor.execute("""

    INSERT INTO threats (

        timestamp,
        threat_level,
        packets_per_window,
        avg_packet_size,
        tcp_count,
        reconstruction_error,
        reason

    )

    VALUES (?, ?, ?, ?, ?, ?, ?)

    """, (

        str(datetime.now()),

        threat_level,

        packets_per_window,

        avg_packet_size,

        tcp_count,

        reconstruction_error,

        reason
    ))


    connection.commit()

    connection.close()


    print("Threat logged to database.")