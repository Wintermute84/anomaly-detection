from flask import Flask, request, jsonify
import os
import sqlite3
from traffic_sim import analyze_pcap  # Import function from analyze_pcap.py
from anomaly_sim import analyze_csv
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow all origins (for development)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect("network.db")
    conn.row_factory = sqlite3.Row  # Enable column access by name
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Create tables if they don't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS network_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS network_traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        analysis_id INTEGER,
        destination_ip TEXT,
        destination_port INTEGER,
        FOREIGN KEY (analysis_id) REFERENCES network_analysis(id) ON DELETE SET NULL
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS extracted_features (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        traffic_id INTEGER,
        total_fwd_packet_length REAL,
        fwd_packet_length_max REAL,
        subflow_fwd_packets REAL,
        fwd_iat_std REAL,
        subflow_fwd_bytes REAL,
        bwd_packet_length_min REAL,
        fwd_iat_total REAL,
        fwd_header_length1 REAL,
        fwd_header_length REAL,
        fwd_iat_mean REAL,
        total_bwd_packet_length REAL,
        fwd_packet_length_std REAL,
        bwd_header_length REAL,
        avg_packet_size REAL,
        fwd_packet_length_mean REAL,
        avg_fwd_segment_size REAL,
        avg_bwd_segment_size REAL,
        FOREIGN KEY (traffic_id) REFERENCES network_traffic(id) ON DELETE CASCADE
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS detection_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        extracted_feature_id INTEGER,
        prediction TEXT,
        detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (extracted_feature_id) REFERENCES extracted_features(id) ON DELETE CASCADE
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS report_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detection_id INTEGER,
        benign_count INTEGER,
        ddos_count INTEGER,
        bot_count INTEGER,
        portscan_count INTEGER,
        webattack_count INTEGER,
        total_packets_count INTEGER,
        generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(detection_id) REFERENCES network_analysis(id) ON DELETE CASCADE
    )''')
    
    conn.commit()
    conn.close()

init_db()

@app.route("/upload", methods=["POST"])
def upload_file():
    
    user_id = request.form.get('userId')
    file = request.files.get('file')

    if not file:
        return jsonify({"message": "No file uploaded!"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    print(filepath)
    print(user_id)
    # Call the analyze function
    if file.filename.endswith(".csv"):
        return analyze_csv(filepath,user_id)
    else:
        return analyze_pcap(filepath,user_id)

@app.route("/getprevactivity", methods=["POST"])
def prevactivity():
    try:
        user = request.json
        user_id = int(user.get("user"))  

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT rl.id, rl.detection_id, rl.benign_count, rl.ddos_count, rl.bot_count, 
                   rl.portscan_count, rl.webattack_count, rl.total_packets_count, rl.generated_at
            FROM report_logs rl
            JOIN network_analysis na ON rl.detection_id = na.id
            WHERE na.user_id = ?
            ORDER BY rl.generated_at DESC
            LIMIT 5;
        """, (user_id,))

        rows = c.fetchall()
        conn.close()

        if not rows:
            return jsonify({"message": "Empty"})

        columns = ["id", "detection_id", "benign_count", "ddos_count", "bot_count", 
                   "portscan_count", "webattack_count", "total_packets_count", "generated_at"]
        result = [dict(zip(columns, row)) for row in rows]

        return jsonify({"message":"ok","output": result})

    except ValueError:  
        return jsonify({"error": "Invalid user ID"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")  
        print(email,password)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT id from users where email = ? and password_hash = ?;
        """, (email,password))

        rows = c.fetchone()
        conn.close()

        if not rows:
            return jsonify({"message": "Empty"})

        return jsonify({"message":"ok","output": rows[0]})

    except ValueError:  
        return jsonify({"error": "Invalid user ID"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/signin", methods=["POST"])
def signin():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")  

        if not email or not password:
            return jsonify({"message": "Email and password required"}), 400

        print(email, password)
        conn = get_db_connection()
        c = conn.cursor()

        # Insert new user
        c.execute("""
            INSERT INTO users (email, password_hash) VALUES (?, ?);
        """, (email, password))
        conn.commit()

        user_id = c.lastrowid  # Get inserted user's ID

        conn.close()

        return jsonify({"message": "ok", "user_id": user_id})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
