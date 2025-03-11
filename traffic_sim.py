import subprocess
import pandas as pd
import joblib
from flask import jsonify
import sqlite3
import os
import numpy as np

# 🔹 Load trained Random Forest model
model = joblib.load("random_forest_model.pkl")  # Ensure this model exists

# 🔹 Define the required features (must match training)
FEATURES = [
    'Total Length of Fwd Packets', 'Fwd Packet Length Max', 'Subflow Fwd Packets',
    'Fwd Packet Length Mean', 'Avg Bwd Segment Size', 'Fwd IAT Std',
    'Subflow Fwd Bytes', 'Bwd Packet Length Min', 'Fwd IAT Mean',
    'Destination Port', 'Avg Fwd Segment Size', 'Fwd IAT Total',
    'Fwd Header Length.1', 'Fwd Header Length', 'Total Length of Bwd Packets',
    'Fwd Packet Length Std', 'Bwd Header Length', 'Average Packet Size', 'Destination IP'
]

# 🔹 Fields to extract using TShark
tshark_fields = {
    "frame.time_epoch": "timestamp",
    "ip.dst": "Destination IP",
    "tcp.dstport": "Destination Port",
    "ip.len": "Total Length of Fwd Packets",
    "frame.len": "Fwd Packet Length Max",
    "tcp.window_size_value": "Avg Bwd Segment Size",
    "tcp.hdr_len": "Fwd Header Length"
}

DATABASE_PATH = "network.db"  # Path to SQLite database

def analyze_pcap(pcap_file, user_id):
    """
    Process the uploaded PCAP file and return anomaly predictions as JSON.
    """
    benign_count = ddos_count = bots_count = webatt_count = portscan_count = 0

    try:
        # 🔹 Run TShark to extract raw network data
        tshark_command = [
            "tshark", "-r", pcap_file, "-T", "fields",
            "-e", "frame.time_epoch", "-e", "ip.dst", "-e", "tcp.dstport",
            "-e", "ip.len", "-e", "frame.len", "-e", "tcp.window_size_value",
            "-e", "tcp.hdr_len",
            "-E", "separator=,", "-E", "quote=d"
        ]

        # Run TShark and capture output
        result = subprocess.run(tshark_command, capture_output=True, text=True)
        
        if result.returncode != 0:
            return jsonify({"error": "Failed to process PCAP file with TShark"}), 500


        # Convert to Pandas DataFrame
        data = [line.split(",") for line in result.stdout.splitlines()]
        df = pd.DataFrame(data, columns=tshark_fields.values())
        string_cols = ["timestamp","Destination Port", "Total Length of Fwd Packets", "Fwd Packet Length Max", "Avg Bwd Segment Size", "Fwd Header Length"]
        df[string_cols] = df[string_cols].applymap(lambda x: x.strip('"') if isinstance(x, str) else x)
       
        # Step 1: Store Destination IP column
        destination_ip_values = df["Destination IP"].copy()
        # 🔹 Fill missing values and convert to numeric
        df.fillna(0, inplace=True)
        df = df.apply(pd.to_numeric, errors="coerce")
        df["Destination IP"] = destination_ip_values
        # 🔹 Compute additional features required for prediction
        df["Fwd Packet Length Mean"] = df["Fwd Packet Length Max"] / 2  # Approximation
        df["Fwd IAT Std"] = df["timestamp"].diff().std()
        df["Fwd IAT Mean"] = df["timestamp"].diff().mean()
        df["Fwd IAT Total"] = df["timestamp"].diff().sum()
        df["Subflow Fwd Packets"] = df.groupby("Destination IP")["timestamp"].transform("count")
        df["Subflow Fwd Bytes"] = df.groupby("Destination IP")["Total Length of Fwd Packets"].transform("sum")
        df["Bwd Packet Length Min"] = df["Total Length of Fwd Packets"].rolling(3).min()
        df["Avg Fwd Segment Size"] = df["Fwd Packet Length Max"] / df["Subflow Fwd Packets"]
        df["Total Length of Bwd Packets"] = df["Total Length of Fwd Packets"] * 0.8  # Approximation
        df["Fwd Packet Length Std"] = df["Fwd Packet Length Mean"].std()
        df["Bwd Header Length"] = df["Avg Bwd Segment Size"] / 2  # Approximation
        df["Average Packet Size"] = df["Fwd Packet Length Mean"] + df["Bwd Header Length"]
        df["Fwd Header Length.1"] = df["Fwd Header Length"] * 1.1  # Adjust multiplier as needed

        # 🔹 Select only required features for prediction
        df_features = df[FEATURES].copy()

        # Ensure only expected features are used
        df_features = df_features.loc[:, model.feature_names_in_]
        # 🔹 Predict anomalies
        df["Anomaly Prediction"] = model.predict(df_features)
        columns_to_replace = [col for col in df.columns if col != "Destination IP"]
        df[columns_to_replace] = df[columns_to_replace].replace({np.nan: None})
        # 🔹 Return results as JSON
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO network_analysis (user_id) VALUES (?)", (user_id,))
        analysis_id = cursor.lastrowid

        for _, row in df.iterrows():
            # Step 2: Insert network traffic data
            cursor.execute(
                """INSERT INTO network_traffic (analysis_id, destination_ip, destination_port)
                   VALUES (?, ?, ?)""",
                (analysis_id, row["Destination IP"][1:len(row["Destination IP"])-1], row["Destination Port"]),
            )
            traffic_id = cursor.lastrowid 
            if(row["Anomaly Prediction"] == 'BENIGN'):
                benign_count+=1
            elif(row["Anomaly Prediction"] == 'PortScan'):
                portscan_count+=1
            elif(row["Anomaly Prediction"] == 'Bots'):
                bots_count+=1
            elif(row["Anomaly Prediction"] == 'DDoS'):
                ddos_count+=1
            else:
                webatt_count+=1
            # Step 3: Insert extracted features
            cursor.execute(
                """INSERT INTO extracted_features (
                       traffic_id, total_fwd_packet_length, fwd_packet_length_max,
                       subflow_fwd_packets, fwd_packet_length_mean, avg_bwd_segment_size,
                       fwd_iat_std, subflow_fwd_bytes, bwd_packet_length_min,
                       fwd_iat_mean, avg_fwd_segment_size, 
                       fwd_iat_total, fwd_header_length1, fwd_header_length,
                       total_bwd_packet_length, fwd_packet_length_std, 
                       bwd_header_length, avg_packet_size)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    traffic_id, row["Total Length of Fwd Packets"], row["Fwd Packet Length Max"],
                    row["Subflow Fwd Packets"], row["Fwd Packet Length Mean"], row["Avg Bwd Segment Size"],
                    row["Fwd IAT Std"], row["Subflow Fwd Bytes"], row["Bwd Packet Length Min"],
                    row["Fwd IAT Mean"], row["Avg Fwd Segment Size"],
                    row["Fwd IAT Total"], row["Fwd Header Length.1"], row["Fwd Header Length"],
                    row["Total Length of Bwd Packets"], row["Fwd Packet Length Std"],
                    row["Bwd Header Length"], row["Average Packet Size"]
                ),
            )
            feature_id = cursor.lastrowid or 1
            # Step 4: Store detection results
            cursor.execute(
                "INSERT INTO detection_results (extracted_feature_id, prediction) VALUES (?, ?)",
                (feature_id, row["Anomaly Prediction"]),
            )
        total_packets_count = benign_count+ddos_count+bots_count+portscan_count+webatt_count
        cursor.execute(
            """INSERT INTO report_logs (detection_id, benign_count, ddos_count, bot_count, portscan_count, webattack_count, total_packets_count)
            VALUES (?,?,?,?,?,?,?)
            """,
            (analysis_id,benign_count,ddos_count,bots_count,portscan_count,webatt_count,total_packets_count)
        )
        # Commit and close DB connection
        conn.commit()
        a = cursor.execute(
            """SELECT na.id AS analysis_id, na.timestamp AS analysis_timestamp, nt.id AS traffic_id, nt.timestamp AS traffic_timestamp, nt.destination_ip, nt.destination_port,    
            ef.id AS feature_id, ef.total_fwd_packet_length, ef.fwd_packet_length_max, ef.subflow_fwd_packets, ef.fwd_iat_std, ef.subflow_fwd_bytes, ef.bwd_packet_length_min, ef.fwd_iat_total,    
            ef.fwd_header_length1, ef.fwd_header_length,  ef.fwd_iat_mean,  ef.total_bwd_packet_length,  ef.fwd_packet_length_std,  ef.bwd_header_length,  ef.avg_packet_size, ef.fwd_packet_length_mean, ef.avg_fwd_segment_size, ef.avg_bwd_segment_size,
            dr.id AS detection_id, dr.prediction, dr.detected_at, rl.id AS report_id, rl.benign_count, rl.ddos_count, rl.bot_count, rl.portscan_count, rl.webattack_count, rl.total_packets_count, rl.generated_at FROM network_analysis na JOIN network_traffic nt ON nt.analysis_id = na.id 
            JOIN extracted_features ef ON ef.traffic_id = nt.id LEFT JOIN detection_results dr ON dr.extracted_feature_id = ef.id LEFT JOIN report_logs rl ON rl.detection_id = na.id WHERE na.user_id = ?  AND na.id = (SELECT MAX(id) FROM network_analysis WHERE user_id = ?) ORDER BY nt.timestamp DESC;
            """,(user_id,user_id)
        )
        rows = a.fetchall()
        result = []
        for i in rows:
            result.append({
                "analysis_id": i[0],
                "analysis_timestamp": i[1],
                "traffic_id": i[2],
                "traffic_timestamp": i[3],
                "destination_ip": i[4],
                "destination_port": i[5],
                "feature_id": i[6],
                "tot_fwd_packetlength":i[7],
                "fwd_packet_length_max":i[8],
                "subflow_fwd_packets":i[9],
                "fwd_iat_std":i[10],
                "subflow_fwd_bytes":i[11],
                "bwd_packet_length_min":i[12],
                "fwd_iat_total":i[13],
                "fwd_header_length1": i[14],
                "fwd_header_length": i[15],
                "fwd_iat_mean": i[16],
                "total_bwd_packet_length": i[17],
                "fwd_packet_length_std": i[18],
                "bwd_header_length": i[19],
                "avg_packet_size": i[20],
                "fwd_packet_length_mean": i[21],
                "avg_fwd_segment_size": i[22],
                "avg_bwd_segment_size": i[23],
                "detection_id": i[24],
                "prediction": i[25],
                "detected_at": i[26],
                "report_id": i[27],
                "benign_count": i[28],
                "ddos_count": i[29],
                "bot_count": i[30],
                "portscan_count": i[31],
                "webattack_count": i[32],
                "total_packets": i[33],
                "generated_at": i[34]
            })
        conn.close()
        
        return jsonify({"analysis_id": analysis_id,"analysis": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
