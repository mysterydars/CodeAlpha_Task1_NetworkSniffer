# CodeAlpha Task 1: Basic Network Sniffer & Traffic Analyzer

## Overview
This standalone repository contains the complete implementation of **Task 1: Basic Network Sniffer** for the CodeAlpha Cybersecurity Internship.

## Project Structure
- `index.html` - Standalone Web UI (can be run with any web server or opened directly)
- `package.json` - NPM package scripts & configuration
- `static/css/styles.css` - Custom styling & theme tokens
- `static/js/app.js` - Interactive client controller & packet injector
- `sniffer.py` - Scapy raw socket packet sniffer CLI
- `app.py` - Flask REST backend & AES-256 GCM encryption API
- `tests/test_sniffer.py` - Pytest unit tests
- `requirements.txt` - Python dependencies

## Quick Start Guide
```bash
# 1. Start Python Web Server
pip install -r requirements.txt
python3 app.py

# 2. Or run CLI Sniffer (requires sudo/admin)
sudo python3 sniffer.py -i eth0
```
