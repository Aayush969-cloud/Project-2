import logging
import json
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import sniff, IP, TCP

# Set up logging to a file
logging.basicConfig(
    filename="intrusion_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Load detection rules from a configuration file
def load_config():
    with open('config.json', 'r') as file:
        config = json.load(file)
    return config

# Default configuration if no config file is provided
default_config = {
    "whitelist_ips": ["127.0.0.1"],
    "monitored_ports": [80, 443],  # HTTP and HTTPS
    "alert_threshold": 10  # Threshold for alerts
}

config = load_config() if 'config.json' in globals() else default_config

# Initialize list for storing alerts
alerts = []

# Function to detect intrusion
def detect_intrusion(packet):
    global alerts
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # Ignore whitelisted IPs
        if src_ip in config["whitelist_ips"]:
            return

        # Port scan detection (SYN packets)
        if flags == "S":  # SYN flag
            alert = {
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Destination Port": dst_port,
                "Alert Type": "TCP SYN Packet"
            }
            print(f"Alert: {alert}")
            logging.info(f"Alert: {alert}")
            alerts.append(alert)

# Function to plot data after running IDS
def plot_alerts():
    if alerts:
        df = pd.DataFrame(alerts)
        df["Count"] = 1
        df_grouped = df.groupby(["Source IP", "Destination Port"]).sum()
        df_grouped.plot(kind="bar", figsize=(10, 6))
        plt.title("Alerts by Source IP and Port")
        plt.xlabel("Source IP & Port")
        plt.ylabel("Alert Count")
        plt.tight_layout()
        plt.savefig("alert_plot.png")
        plt.show()

# Start sniffing network packets
def start_sniffing():
    print("Starting IDS...")
    sniff(prn=detect_intrusion, store=0)

# Run IDS and then plot alerts
if __name__ == "__main__":
    start_sniffing()
    plot_alerts()
