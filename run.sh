#!/bin/bash
echo "=== Starting CodeAlpha Task 1 Network Sniffer ==="
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
