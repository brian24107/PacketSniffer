from scapy.all import sniff, Raw
from scapy.layers.inet import TCP, IP
import datetime

LOG_FILE = "packet_sniffer_log.txt"

def log_to_file(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

def analyze_payload(payload, protocol):
    try:
        data = payload.decode(errors="ignore")
        if protocol == "FTP" and ("USER" in data or "PASS" in data):
            creds = f"🚨 Potential FTP Credentials Found: {data.strip()}"
            print(creds)
            log_to_file(creds)
        elif protocol == "Telnet":
            creds = f"🚨 Telnet Payload Captured (potential credentials): {data.strip()}"
            print(creds)
            log_to_file(creds)
        elif protocol == "SMTP" and ("AUTH" in data or "LOGIN" in data):
            creds = f"🚨 SMTP Authentication Data Captured: {data.strip()}"
            print(creds)
            log_to_file(creds)
    except Exception:
        pass  # Ignore decoding errors silently

def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        sport = tcp_layer.sport
        dport = tcp_layer.dport

        info = f"From: {src_ip} --> To: {dst_ip} | Protocol: TCP | Src Port: {sport} | Dst Port: {dport}"
        print(f"\n📡 {info}")
        log_to_file(info)

        # Protocol Detection and Warnings
        if dport == 80:
            warning = "⚠️  Insecure HTTP traffic detected!"
            print(warning)
            log_to_file(warning)

        elif dport == 21:
            warning = "⚠️  FTP traffic detected! Checking for clear-text credentials..."
            print(warning)
            log_to_file(warning)

        elif dport == 23:
            warning = "⚠️  Telnet traffic detected! This is highly insecure!"
            print(warning)
            log_to_file(warning)

        elif dport == 25:
            warning = "⚠️  SMTP traffic detected! Checking for authentication data..."
            print(warning)
            log_to_file(warning)

        # Try to Analyze Payload for Credentials or Sensitive Data
        if packet.haslayer(Raw):
            if dport == 21:
                analyze_payload(packet[Raw].load, "FTP")
            elif dport == 23:
                analyze_payload(packet[Raw].load, "Telnet")
            elif dport == 25:
                analyze_payload(packet[Raw].load, "SMTP")

def start_sniffing():
    print("🔎 Listening for TCP packets... Logs will be saved to 'packet_sniffer_log.txt'. Press Ctrl+C to stop.")
    sniff(filter="tcp", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
