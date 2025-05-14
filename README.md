# PacketSniffer

A Python-based network packet sniffer that captures TCP traffic, identifies insecure protocols, and attempts to extract potential credentials from clear-text communications. This tool provides real-time monitoring and logging of network activity, helping identify poor security practices like the use of FTP, Telnet, and unencrypted SMTP.

---

## 📌 Features

- Captures live TCP packets on the network.
- Detects insecure protocols:
  - HTTP (Port 80)
  - FTP (Port 21)
  - Telnet (Port 23)
  - SMTP (Port 25)
- Attempts to extract clear-text credentials from FTP, Telnet, and SMTP payloads.
- Logs all activity and findings to `packet_sniffer_log.txt`.
- Lightweight and easy to extend.

---

## 🚀 Usage

1. **Install Dependencies**
   ```bash
   pip install scapy
   
2. Run the Tool (Needs Admin/Root Permissions)
   ```bash
  python packet_sniffer.py
  
3. Example Output
📡 From: 192.168.1.5 --> To: 192.168.1.10 | Protocol: TCP | Src Port: 49320 | Dst Port: 21
⚠️  FTP traffic detected! Checking for clear-text credentials...
🚨 Potential FTP Credentials Found: USER admin
🚨 Potential FTP Credentials Found: PASS password123

4. Log file
   All detected events and traffic are logged to packet_sniffer_log.txt for later review.
