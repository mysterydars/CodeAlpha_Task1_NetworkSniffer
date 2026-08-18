"""
Unit tests for Task 1: Network Sniffer & Payload Analyzer
"""
import pytest
from sniffer import analyze_payload

def test_sqli_payload_detection():
    payload = b"GET /login?user=admin' UNION SELECT password FROM users"
    alerts = analyze_payload(payload)
    assert len(alerts) >= 1
    assert "UNION" in alerts[0] or "SELECT" in alerts[0]

def test_clean_payload():
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
    alerts = analyze_payload(payload)
    assert len(alerts) == 0

def test_script_tag_xss_detection():
    payload = b"POST /comment payload=<script>alert(1)</script>"
    alerts = analyze_payload(payload)
    assert len(alerts) >= 1
    assert "<script>" in alerts[0]
