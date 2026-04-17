#!/usr/bin/env python3
"""
Real-time Suricata log sender.
Tails eve.json and streams new log entries to the TCP receiver.
"""

import socket
import json
import time
import os

HOST = "127.0.0.1"  # Receiver IP
PORT = 5001         # Receiver port
EVE_FILE = "/var/log/suricata/eve.json"  # Update path if needed
RETRY_DELAY = 5      # Seconds to wait before reconnecting if connection fails

def tail_eve_file(file_path):
    """Generator that yields new lines added to a file (like tail -f)."""
    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)  # Go to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Wait for new data
                continue
            yield line.strip()

def send_eve_logs(host=HOST, port=PORT, eve_file=EVE_FILE):
    """Continuously send new Suricata eve.json log entries to the receiver."""
    if not os.path.exists(eve_file):
        print(f"[Sender] Log file not found: {eve_file}")
        return

    while True:
        try:
            with socket.create_connection((host, port)) as sock:
                print(f"[Sender] Connected to {host}:{port}")
                for line in tail_eve_file(eve_file):
                    if not line:
                        continue
                    try:
                        log_entry = json.loads(line)
                        msg = json.dumps(log_entry) + "\n"
                        sock.sendall(msg.encode("utf-8"))
                        print(f"[Sender] Sent log: {log_entry.get('event_type', 'unknown')} from {log_entry.get('src_ip', '')} to {log_entry.get('dest_ip', '')}")
                    except json.JSONDecodeError:
                        print(f"[Sender] Skipping invalid JSON line: {line[:80]}...")
        except ConnectionRefusedError:
            print(f"[Sender] Could not connect to {host}:{port}. Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)
        except Exception as e:
            print(f"[Sender] Error: {e}. Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)

if __name__ == "__main__":
    send_eve_logs()

