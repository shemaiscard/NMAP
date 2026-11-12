# NetAudit: Nmap Scanner and SSH Audit Demo

**Live demo:** [nmaptest.streamlit.app](https://nmaptest.streamlit.app)

> **Use it legally.** Scan only machines you own or have written permission to test. The SSH part is a simulation and never opens a connection.

A Streamlit app for learning network reconnaissance. It runs real Nmap scans, shows the results in a terminal-style console, and includes a simulated SSH dictionary audit that explains how credential testing works without attacking anything.

## Features

- **Nmap scans** (run through `subprocess`):
  - Fast scan: the top 100 ports with service detection (`nmap -T4 -F -sV`)
  - Port range scan: ports 1 to 100 with service detection (`nmap -T4 -p 1-100 -sV`)
  - Output shown live in the console view
- **SSH audit (simulated):** generates weak username and password pairs and checks them against a fake target. The Paramiko login code is in the source as comments, so you can see what a real check looks like, but it never runs.
- **Learning material:** a documentation tab and a downloadable handout.

## Tech stack

| Part | Technology |
| --- | --- |
| Language | Python |
| UI | Streamlit with custom CSS |
| Scanning | Nmap (`-sV` service detection) |
| SSH | Paramiko (imported; connection code shown but disabled) |

## Run locally

```bash
# Install Nmap
sudo apt install nmap        # Ubuntu or Debian
sudo dnf install nmap        # Fedora or RHEL

pip install -r requirements.txt
streamlit run pyres.py
```

If Nmap complains about permissions on Linux:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## Files

```text
pyres.py           main app
requirements.txt   Python packages
packages.txt       system packages for Streamlit Cloud (nmap)
Php.txt            presentation notes
```

## License

See [LICENSE](LICENSE).
