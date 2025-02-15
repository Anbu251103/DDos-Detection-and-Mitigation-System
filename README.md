# DDos-Detection-and-Mitigation-System
The system employs real-time packet inspection and a rule-based approach to identify potential DDoS attacks and block malicious IP addresses while allowing legitimate traffic to pass without disruption.
# DDoS Detection and Mitigation System

## Problem Statement

Existing security solutions often struggle to provide effective DDoS detection and mitigation in real time, especially in small-scale environments where resources are limited. This project focuses on designing a system capable of monitoring network traffic, detecting potential DDoS attacks based on predefined thresholds, and dynamically blocking malicious IP addresses while allowing legitimate traffic to pass uninterrupted.

## Novelty

The proposed system combines simplicity and efficiency by leveraging lightweight, real-time packet inspection and a rule-based approach to detect and mitigate attacks. A key feature is the ability to simulate traffic patterns for testing, ensuring reliability in various scenarios.

## Dataset

Real-time traffic was generated using a synthetic traffic generation module included in the system. This approach allowed testing under controlled attack scenarios, replicating conditions such as high traffic from specific IPs to simulate DDoS attacks effectively.
4.2 Setup Instructions
markdown
Copy
Edit
## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/ddos-detection-mitigation.git
Install the required dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Run the synthetic traffic generator to simulate attack scenarios:

bash
Copy
Edit
python src/traffic_generator/generate_traffic.py
Start the packet inspection and detection system:

bash
Copy
Edit
python src/packet_inspection/monitor_traffic.py
Test the system with attack simulation:

bash
Copy
Edit
python tests/test_rule_based_detection.py
perl
Copy
Edit

### 5. **Push the Code to GitHub**

After setting up your project, you can push your local changes to GitHub:

```bash
git add .
git commit -m "Initial commit: Add DDoS detection and mitigation system"
git push origin main
