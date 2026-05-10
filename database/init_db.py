import sqlite3


connection = sqlite3.connect(

    r"C:\Users\AYUSMATI PANDA\OneDrive\Desktop\AI_NIDS\database\threats.db"
)


cursor = connection.cursor()


cursor.execute("""

CREATE TABLE IF NOT EXISTS threats (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp TEXT,

    threat_level TEXT,

    packets_per_window INTEGER,

    avg_packet_size REAL,

    tcp_count INTEGER,

    reconstruction_error REAL,

    reason TEXT
)

""")


connection.commit()

connection.close()


print("Threat database initialized successfully.")