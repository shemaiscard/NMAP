NMAP SCANNING TOOL & SSH AUDITOR (EDUCATIONAL)
==============================================

A Streamlit-based web application designed for network reconnaissance and educational security auditing. This tool provides a graphical interface for running Nmap scans and demonstrates the logic behind SSH Dictionary Attacks (Brute Force) in a safe, simulated environment.

FEATURES
--------
* Network Reconnaissance (Nmap):
    - Fast Scan: Scans the top 100 most common ports using "nmap -F -sV".
    - In-Depth Scan: Targeted scan of ports 1-100 with service version detection.
    - Real-time output display in a "Cyber" themed console.
* SSH Credential Audit (Mock):
    - Simulates a dictionary attack logic.
    - Generates random weak username/password pairs.
    - Demonstrates how automated tools test credentials against a target.
    - Note: This module is mocked for safety and does not make actual external SSH connections.
* Educational Resources: Includes a built-in documentation tab and downloadable presentation materials.
* Modern UI: Custom CSS implementation for a dark, "Hacker/Cyber" aesthetic.

PREREQUISITES
-------------
Since this application is deployed on a Linux Web Server, ensure the following dependencies are met:

1. System Dependencies:
   You must have Nmap installed on the server backend for the scanner to function.

   For Ubuntu/Debian:
     sudo apt update
     sudo apt install nmap python3-pip -y

   For Fedora/CentOS/RHEL:
     sudo dnf install nmap python3-pip -y

2. Python Dependencies:
   The application requires Python 3. Install the required libraries:
     pip3 install streamlit paramiko

INSTALLATION
------------
1. Clone or Upload the Repository:
   Upload "pyres.py" and any accompanying files (like "Php.txt") to your server directory (e.g., /var/www/nmap-tool or /home/user/app).

2. Verify Directory Structure:
   /app-directory
   
   |-- pyres.py         # Main application file
   
   |-- Php.txt          # Presentation file (Required for Tab 4)
   
   |-- readme.txt       # This file

USAGE
-----
1. Running Locally (Development):
   To run the app on your local machine:
     streamlit run pyres.py

2. Running on Linux Web Server:
   For the Nmap functionality to work without permission errors, you may need to run the application with elevated privileges or configure Nmap capabilities.

   Method A: Running with Sudo (Simplest for Nmap access)
     sudo streamlit run pyres.py --server.port 8501 --server.address 0.0.0.0

   Method B: Standard User (Requires Nmap Capabilities)
   If you do not want to run Streamlit as root, give the Nmap binary raw socket capabilities:
     sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
     streamlit run pyres.py --server.port 8501 --server.address 0.0.0.0

3. Accessing the App:
   Open your web browser and navigate to:
   http://<YOUR_SERVER_IP>:8501

CONFIGURATION
-------------
* Port: Default is 8501. To change it, add "--server.port <PORT>" to the run command.
* Headless Mode: Streamlit automatically detects server environments, but you can force it with "--server.headless true".

* Firewall Note:
  Ensure your Linux firewall allows traffic on the specified port.
  Example for UFW (Ubuntu): sudo ufw allow 8501/tcp

LEGAL & ETHICAL DISCLAIMER
--------------------------
This tool is for EDUCATIONAL PURPOSES ONLY.

1. Authorization: Do not run Nmap scans against IP addresses, domains, or networks that you do not own or have explicit written permission to test.
2. Liability: The author is not responsible for any misuse of this tool or any damage caused by the use of this software.
3. Mock Functionality: The SSH module is a simulation meant to teach concepts. It does not perform actual intrusion attempts.

LICENSE
-------
This project is open-source. Feel free to modify and use it for your cybersecurity studies.
