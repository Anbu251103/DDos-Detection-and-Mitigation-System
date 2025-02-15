import logging
from collections import defaultdict
import time
import threading
from scapy.all import sniff, IP, send, Ether
import os

# Configurable Parameters
REQUEST_THRESHOLD = 10
TIME_WINDOW = 30
BLOCK_DURATION = 60

ip_request_count = defaultdict(int)  # Dictionary to store request counts per IP
blocked_ips = {}  # Dictionary to store blocked IPs and the time they were blocked

# Logging configuration
logging.basicConfig(filename='ddos_mitigation.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def block_ip(ip_address):
    if ip_address not in blocked_ips:
        logging.info(f"Blocking IP: {ip_address}")
        blocked_ips[ip_address] = time.time()
        print(f"🚨 Blocking IP due to high traffic: {ip_address}")
        os.system(f"sudo pfctl -t blocked -T add {ip_address}")

# Function to unblock IP after block duration
def unblock_ip(ip_address):
    logging.info(f"Unblocking IP: {ip_address}")
    os.system(f"sudo pfctl -t blocked -T delete {ip_address}")
    print(f"✅ IP Unblocked: {ip_address}")

# Function to handle incoming packets and detect DDoS attacks
def ddos_detection(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src

        # Ignore packets from already blocked IPs
        if ip_src in blocked_ips:
            if time.time() - blocked_ips[ip_src] > BLOCK_DURATION:
                print(f"⏳ Block duration expired for {ip_src}, unblocking...")
                unblock_ip(ip_src)
                del blocked_ips[ip_src]
            return

        # Count the number of requests from each IP
        ip_request_count[ip_src] += 1
        print(f"🌐 Detected packet from IP: {ip_src} | Count: {ip_request_count[ip_src]}")

        # Check if the request count exceeds the threshold
        if ip_request_count[ip_src] > REQUEST_THRESHOLD:
            print(f"⚠️ High traffic detected from IP: {ip_src} - Possible DDoS attack!")
            block_ip(ip_src)

# Function to reset IP request counters periodically
def reset_counters():
    global ip_request_count
    while True:
        time.sleep(TIME_WINDOW)
        ip_request_count.clear()  # Clear request counters for all IPs
        print("🔄 IP request counters reset for a new time window.")

# Function to generate synthetic traffic from a specified IP
def generate_synthetic_traffic(target_ip, packet_count, interval):
    print(f"📈 Generating synthetic traffic from IP {target_ip}...")
    for _ in range(packet_count):
        packet = Ether() / IP(src=target_ip, dst="127.0.0.1")
        send(packet, verbose=0)
        time.sleep(interval)
    print(f"🛑 Synthetic traffic generation from IP {target_ip} completed.")

# Function to initialize packet sniffing
def start_sniffing(interface=None):
    print(f"📡 Starting packet sniffing on interface: {interface}")
    sniff(prn=ddos_detection, store=0, iface=interface)

# Main function to run the mitigation system
if __name__ == "__main__":
    print("🚀 Starting DDoS Mitigation System...")

    # Create pfctl table for blocking IPs if it doesn't exist
    os.system("sudo pfctl -t blocked -T show || sudo pfctl -t blocked -T create")

    # Start the thread to reset request counters periodically
    reset_thread = threading.Thread(target=reset_counters, daemon=True)
    reset_thread.start()

    # Specify network interface
    network_interface = "lo0"

    # Start sniffing for traffic in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, args=(network_interface,), daemon=True)
    sniff_thread.start()

    # Generate synthetic traffic from a specific IP to simulate an attack
    attacker_ip = "192.168.1.100"  # IP used to simulate the attacker
    packet_count = 20  # Number of packets sent to simulate high traffic
    interval = 0.5  # Time interval between packets

    # Start traffic generation in a separate thread
    traffic_thread = threading.Thread(target=generate_synthetic_traffic, args=(attacker_ip, packet_count, interval))
    traffic_thread.start()

    # Keep the main thread alive
    sniff_thread.join()
    traffic_thread.join()
