"""
Flask Cybersecurity Web App - CodeAlpha Task 1
Includes Live Packet Sniffer Dashboard, Mock Traffic Generator, AES Vault & User Auth API.
"""

import os
import base64
import json
import time
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'codealpha_secret_cyber_key_2026')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybersecurity.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

class PacketLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False)
    src_ip = db.Column(db.String(50), nullable=False)
    dst_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(20), nullable=False)
    length = db.Column(db.Integer, nullable=False)
    summary = db.Column(db.String(255), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/packets/mock')
def get_mock_packets():
    packets = [
        {"id": 1, "timestamp": "12:00:01.102", "srcIp": "192.168.1.105", "dstIp": "142.250.190.46", "protocol": "TCP", "srcPort": 54120, "dstPort": 443, "length": 64, "summary": "TLS Client Hello [SYN, ACK]", "payloadHex": "16 03 01 02 00 01 00 01", "alerts": []},
        {"id": 2, "timestamp": "12:00:02.340", "srcIp": "10.0.0.15", "dstIp": "10.0.0.1", "protocol": "HTTP", "srcPort": 49152, "dstPort": 80, "length": 128, "summary": "POST /api/login payload: admin' OR '1'='1", "payloadHex": "50 4f 53 54 20 2f 61 70 69 2f 6c 6f 67 69 6e", "alerts": [{"severity": "critical", "type": "SQL Injection", "description": "SQLi syntax detected in HTTP payload."}]},
        {"id": 3, "timestamp": "12:00:03.890", "srcIp": "192.168.1.50", "dstIp": "8.8.8.8", "protocol": "DNS", "srcPort": 61234, "dstPort": 53, "length": 78, "summary": "Standard query A api.github.com", "payloadHex": "01 00 00 01 00 00 00 00 00 00 03 61 70 69", "alerts": []},
        {"id": 4, "timestamp": "12:00:05.120", "srcIp": "185.220.101.5", "dstIp": "192.168.1.1", "protocol": "TCP", "srcPort": 38412, "dstPort": 22, "length": 54, "summary": "SSH Brute Force Attempt [SYN]", "payloadHex": "53 53 48 2d 32 2e 30 2d 4f 70 65 6e 53 53 48", "alerts": [{"severity": "high", "type": "SSH Brute Force", "description": "High rate of SYN packets on port 22."}]},
        {"id": 5, "timestamp": "12:00:06.450", "srcIp": "203.0.113.195", "dstIp": "192.168.1.100", "protocol": "ICMP", "srcPort": 0, "dstPort": 0, "length": 84, "summary": "Echo (ping) request ttl=64", "payloadHex": "08 00 4d 5b 00 01 00 01 61 62 63 64 65 66", "alerts": []}
    ]
    return jsonify({"packets": packets})

@app.route('/api/encrypt', methods=['POST'])
@limiter.limit("10 per minute")
def encrypt_data():
    data = (request.json or {}).get('plaintext', '')
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return jsonify({
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce": base64.b64encode(cipher.nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "key_hex": key.hex()
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
