@echo off
echo === Starting CodeAlpha Task 1 Network Sniffer ===
python -m venv venv
call venv\Scripts\activate
pip install -r requirements.txt
python app.py
pause
