\# CodeAlpha Network Sniffer



A Python-based network packet sniffer developed as part of the CodeAlpha Cyber Security Internship.



The application captures live network traffic and displays packet information through a graphical desktop dashboard. It also supports exporting captured packets into PCAP files for further analysis.



\## Features



\- Live network packet capture

\- Graphical desktop dashboard built with Tkinter

\- Network interface selection

\- Packet filtering (IP, TCP, UDP and ICMP)

\- Source and destination IP address identification

\- Source and destination port identification

\- Packet size and timestamp display

\- Live packet statistics

\- PCAP file export for further analysis

\- Command-line packet analysis mode



\## Technologies Used



\- Python

\- Scapy

\- Tkinter

\- Npcap

\- PCAP



\## Project Structure



```text

CodeAlpha\_NetworkSniffer/

│

├── src/

│   ├── main.py

│   ├── capture.py

│   ├── analyzer.py

│   └── dashboard.py

│

├── captures/

├── reports/

├── screenshots/

├── requirements.txt

├── README.md

└── .gitignore

```



\## Requirements



\- Windows 10/11

\- Python 3.13 or compatible Python version

\- Npcap

\- Scapy



\## Installation



\### 1. Clone the repository



```bash

git clone YOUR\_GITHUB\_REPOSITORY\_URL

cd CodeAlpha\_NetworkSniffer

```



\### 2. Create a virtual environment



```bash

python -m venv .venv

```



\### 3. Activate the virtual environment



```bash

.venv\\Scripts\\activate

```



\### 4. Install dependencies



```bash

pip install -r requirements.txt

```



\### 5. Install Npcap



Install Npcap from:



https://npcap.com/



Npcap is required for packet capture on Windows.



\## How to Run



\### Graphical Dashboard



```bash

python src/dashboard.py

```



\### Command-Line Version



```bash

python src/main.py

```



For live packet capture, select an available network interface and configure the packet filter and packet limit.



Captured PCAP files are stored in the `captures/` directory.



\## Project Purpose



This project demonstrates fundamental network monitoring and packet analysis concepts, including IP addressing, transport-layer protocols, packet inspection and network traffic capture.



It is intended for educational purposes and cybersecurity learning.



\## Author



Developed as part of the CodeAlpha Cyber Security Internship.



\## Disclaimer



Use this application only on networks and devices you own or have explicit permission to monitor. Do not inspect network traffic without proper authorization.

