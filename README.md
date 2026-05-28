# NMAP Scanning Tool & SSH Auditor

**Live Demo:** [nmaptest.streamlit.app](https://nmaptest.streamlit.app)

> **Legal & Ethical Notice:** This tool is for **educational and authorized use only**. Do not scan networks or systems you do not own or have explicit written permission to test. The SSH module is fully mocked — it performs no real intrusion attempts.

A Streamlit-based GUI for network reconnaissance and educational security auditing, featuring a hacker-themed UI.

## Features

- **Network Reconnaissance (Nmap)**
  - Fast Scan: Top 100 ports with service version detection (`nmap -F -sV`)
  - In-Depth Scan: Ports 1-100 with detailed service info
  - Real-time output in a cyber-themed console
- **SSH Credential Audit (Mock)**
  - Simulates dictionary attack logic using randomly generated weak credentials
  - Demonstrates automated credential testing concepts safely
  - No actual SSH connections are made
- **Educational Resources**: Built-in documentation tab and downloadable materials

## Prerequisites

```bash
# Ubuntu/Debian
sudo apt install nmap python3-pip -y

# Fedora/RHEL
sudo dnf install nmap python3-pip -y

pip3 install streamlit paramiko
```

## Run Locally

```bash
streamlit run pyres.py
```

For Nmap to work without permission errors on Linux:
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## File Structure

```
├── pyres.py       # Main application
├── Php.txt        # Presentation/documentation file
└── README.md
```

## License
Open-source. Free to use for cybersecurity education.
