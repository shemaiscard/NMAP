import streamlit as st
import subprocess
import re
import time
import streamlit.components.v1 as components 
import random
import os

# Paramiko is imported to demonstrate the structure, even if the connection is mocked.
try:
    import paramiko
except ImportError:
    paramiko = None
    # st.warning("Paramiko library not installed. SSH functionality will be mocked.")


# --- CONFIGURATION ---
ST_ICON = ""
APP_TITLE = "NMAP SCANNING TOOL."

# --- EMBEDDED CSS: Dark Theme and Cyber Style ---
EMBEDDED_CSS = """
/* Custom Dark Theme Styles */
[data-testid="stAppViewContainer"] {
    background-color: #1e1e1e; /* Deep Dark Gray */
    color: #f0f0f0;
}
[data-testid="stHeader"] {
    background-color: #1e1e1e;
}
.stApp {
    color: #f0f0f0; /* Light Gray Text */
    font-family: 'Inter', sans-serif;
}

/* Rounded Corners on all elements */
.stButton>button, .stTextInput>div>div>input, .stSelectbox>div>div, .stTabs [data-baseweb="tab"] {
    border-radius: 8px;
}

/* Titles and Headings */
h1, h2, h3 {
    color: #FF5733; /* Audit Orange for visual punch */
    text-shadow: 1px 1px 3px #581845;
}

/* Streamlit Tabs Styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 20px;
    padding-bottom: 5px;
}
.stTabs [data-baseweb="tab"] {
    height: 40px;
    width: 250px;
    background-color: #333333; /* Darker tab background */
    border-radius: 8px 8px 0 0;
    justify-content: center;
    border-top: 3px solid transparent;
    transition: all 0.2s ease-in-out;
    color: #f0f0f0;
    font-weight: 500;
}
.stTabs [aria-selected="true"] {
    background-color: #2c2c2c; /* Active tab background */
    border-top: 3px solid #FF5733; /* Audit Orange highlight */
    color: #FF5733;
    font-weight: bold;
}

/* Button Styling (Action Buttons) */
.stButton>button {
    background-color: #900C3F; /* Dark Red/Maroon */
    color: white !important;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 16px;
    font-weight: bold;
    border: none;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.4);
}
.stButton>button:hover:not(:disabled) {
    background-color: #FF5733; /* Hover effect */
    box-shadow: 0 0 12px #FF5733;
    transform: translateY(-2px);
}

/* Input Fields */
div.stTextInput>div>div>input {
    background-color: #333333;
    color: #f0f0f0;
    border: 1px solid #555555;
    padding: 10px;
}

/* Custom Text Highlights */
.success-text {
    color: #4cd964; /* Vibrant Green for success */
    font-weight: bold;
    font-size: 1.1em;
}
.error-text {
    color: #FF5733; /* Audit Orange for warnings/errors */
    font-weight: bold;
    font-size: 1.1em;
}

/* Code Blocks for Nmap Output */
.stCodeBlock {
    background-color: #2c2c2c;
    border: 1px solid #581845;
    border-radius: 8px;
    padding: 15px;
}
"""

def load_css(css):
    """Loads the embedded CSS."""
    st.markdown(f'<style>{css}</style>', unsafe_allow_html=True)

# --- NMAP SCANNER LOGIC ---

def run_nmap_scan(target, scan_type):
    """Executes a safe, non-intrusive Nmap scan."""
    if not target:
        st.error("Please enter a target IP address or domain.")
        return "N/A"

    if scan_type == "Fast Scan (Top Ports)":
        # -F: Fast mode (top 100 ports), -sV: Service version detection
        command = ["nmap", "-T4", "-F", "-sV", target]
    else: # In-Depth Scan (Ports 1-100)
        # -p 1-100: Scans a specific port range, -sV: Service version detection
        command = ["nmap", "-T4", "-p", "1-100", "-sV", target]

    st.info(f"Running command (safe educational use): `{' '.join(command)}`")

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False, 
            timeout=180 # Timeout after 3 minutes
        )
        return process.stdout
    except FileNotFoundError:
        return "Error: Nmap command not found. Please ensure Nmap is installed and in your system PATH."
    except subprocess.TimeoutExpired:
        return "Error: Nmap scan timed out (max 3 minutes)."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

# --- CREDENTIAL AUDIT (SSH BRUTE FORCE MOCK) LOGIC ---

def generate_weak_credentials(num_pairs):
    """Generates simple, weak username/password pairs for educational demonstration."""
    usernames = ["admin", "test", "user", "guest", "root", "dev", "pi", "student"]
    passwords = ["1234", "password", "test", "admin", "qwert", "welcome", "raspberry"]
    
    generated_list = []
    
    # Generate random, but predictable weak pairs
    for i in range(num_pairs):
        user = random.choice(usernames)
        password = random.choice(passwords)
        generated_list.append((user, password))
        
    return list(set(generated_list)) # Ensure unique pairs

def attempt_ssh_login(host, port, username, password):
    """
    Mocks the SSH login attempt using the structure of the Paramiko library.
    This function demonstrates the structure only and does NOT connect externally.
    """
    time.sleep(0.01) # Simulate network latency/delay

    # --- MOCK SUCCESS CONDITION for classroom demo ---
    TARGET_USER = "admin"
    TARGET_PASS = "password" 
    
    if username == TARGET_USER and password == TARGET_PASS:
        # In a real Paramiko script, success would look like this:
        # try:
        #     client = paramiko.SSHClient()
        #     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        #     client.connect(host, port=port, username=username, password=password, timeout=5)
        #     client.close()
        #     return True # Login Success
        # except paramiko.AuthenticationException:
        #     return False # Login Failed
        return True

    return False # Mocked failure

def perform_ssh_audit(host, port, credential_list):
    """Simulates an SSH Brute Force Audit."""
    attempts = []
    found = False
    
    # Ensure port is an integer
    try:
        port = int(port)
    except ValueError:
        return attempts, False, "Invalid port number."

    for user, password in credential_list:
        status = "FAILED"
        if attempt_ssh_login(host, port, user, password):
            status = "SUCCESS"
            found = True
        
        attempts.append((user, password, status))
        
        if found:
            break
            
    return attempts, found, None

# --- STREAMLIT APP ---

def app():
    st.set_page_config(page_title=APP_TITLE, page_icon=ST_ICON, layout="wide")
    load_css(EMBEDDED_CSS)

    st.markdown(f"<h1>{APP_TITLE}</h1>", unsafe_allow_html=True)
    st.markdown(f"<h3>'The only way to defend against a bad guy with a computer is a good guy with a computer.'</h3>", unsafe_allow_html=True)

    st.markdown("---")

    # --- TABBED LAYOUT ---
    tab1, tab2, tab3, tab4 = st.tabs(["Nmap Scanner", "SSH Credential Audit (Mock)", "Documentation", "Presentation Slides"])

    # --- TAB 1: NMAP SCANNER ---
    with tab1:
        st.subheader("Network Reconnaissance (Nmap) 🔎")
        st.warning("🚨 **Ethical Reminder:** Only scan targets you own or have explicit permission to test (e.g., your local lab VM). Running with `sudo` is required.")

        target_host = st.text_input("Target IP/Domain:", 
                                     placeholder="192.168.1.1 or example.com", 
                                     key="nmap_target")
        
        scan_option = st.selectbox(
            "Select Scan Depth:",
            ("Fast Scan (Top Ports)", "In-Depth Scan (Ports 1-100)"),
            key="scan_option"
        )
        
        st.markdown("---")
        
        if st.button(f"RUN {scan_option.upper()} SCAN"):
            with st.spinner(f"Scanning {target_host} with {scan_option} profile..."):
                scan_output = run_nmap_scan(target_host, scan_option)
                st.session_state['nmap_output'] = scan_output
        
        if 'nmap_output' in st.session_state:
            st.markdown("#### Nmap Scan Results")
            st.info(f"Scan Profile: {scan_option}. Result analysis helps identify open ports and service versions.")
            st.code(st.session_state['nmap_output'], language="text")
            
            # Classroom emphasis
            if "Service detection" in st.session_state['nmap_output']:
                st.markdown("<p class='success-text'>✅ Service version data retrieved. Compare versions against public CVE databases for known vulnerabilities.</p>", unsafe_allow_html=True)
            elif "Failed to resolve" in st.session_state['nmap_output']:
                 st.markdown("<p class='error-text'>❌ Target resolution failed. Check the IP/Domain or connectivity.</p>", unsafe_allow_html=True)


    # --- TAB 2: CREDENTIAL AUDIT (MOCK) ---
    with tab2:
        st.subheader("SSH Credential Audit (Dictionary Attack Concept) 🗝️")
        st.info("This demonstration uses Python to mock the logic of a real SSH brute-force tool. **No actual external connections are made.**")
        
        col_host, col_port = st.columns(2)
        with col_host:
            target_host_bf = st.text_input("Target Host (Mock):", value="192.168.1.100 (Simulated SSH Server)", key="bf_host")
        with col_port:
            target_port_bf = st.text_input("Target Port (Mock):", value="22", key="bf_port")
        
        st.markdown("---")
        
        if st.button("Generate/View Weak Credential Dictionary"):
            st.session_state.cred_list = generate_weak_credentials(20) # Generate 20 unique pairs
            
            st.markdown("##### Generated Weak Dictionary (User:Password Pairs):")
            display_list = [f"{user}:{password}" for user, password in st.session_state.cred_list]
            st.code("\n".join(display_list))
            st.success(f"{len(st.session_state.cred_list)} unique weak credential pairs generated.")
            
        st.markdown("---")
        
        if st.button("RUN MOCK SSH AUDIT (Brute Force Simulation)"):
            if 'cred_list' not in st.session_state:
                st.error("Please generate the weak credential dictionary first.")
            else:
                with st.spinner(f"Simulating {len(st.session_state.cred_list)} SSH login attempts on {target_host_bf}:{target_port_bf}..."):
                    attempts, found, error = perform_ssh_audit(
                        target_host_bf, 
                        target_port_bf, 
                        st.session_state.cred_list
                    )
                    
                    st.session_state['ssh_attempts'] = attempts
                    st.session_state['ssh_found'] = found
                    st.session_state['ssh_error'] = error
        
        if 'ssh_attempts' in st.session_state:
            st.markdown("##### Simulation Log (Showing first 20 attempts):")
            
            log_lines = []
            for user, password, status in st.session_state['ssh_attempts'][:20]:
                color = "success-text" if status == "SUCCESS" else "error-text"
                log_lines.append(f"[{status:<7}] User:{user:<10} | Pass:{password:<10}")
            
            st.code("\n".join(log_lines))

            if st.session_state['ssh_found']:
                # Find the successful credential (hardcoded in the mock for demonstration)
                successful_cred = next(((u, p) for u, p, s in st.session_state['ssh_attempts'] if s == "SUCCESS"), ("N/A", "N/A"))
                
                st.markdown(f"<p class='success-text'>🔑 **Audit SUCCESS!** Weak Credential Found: **{successful_cred[0]}/{successful_cred[1]}**</p>", unsafe_allow_html=True)
                st.markdown("This highlights the risk of using default or common passwords on services like SSH.")
            elif st.session_state['ssh_error']:
                st.error(f"Error during audit: {st.session_state['ssh_error']}")
            else:
                st.markdown("<p class='error-text'>❌ Audit Failed: The mock credential was not found in this dictionary.</p>", unsafe_allow_html=True)

    # --- TAB 3: DOCUMENTATION ---
    with tab3:
        st.subheader("Project Documentation and Setup")
        st.markdown("""
        ### Project Name: CypherAudit Toolkit
        
        This tool is an educational resource for Computer Science students to understand the principles of network reconnaissance and credential auditing.

        #### Setup and Execution
        
        1.  **Prerequisites:** Python 3, Streamlit, Paramiko, and Nmap must be installed on a Linux/Unix system.
            ```bash
            pip install streamlit paramiko
            ```
        2.  **Run with Sudo (Required for Nmap):**
            ```bash
            sudo streamlit run cypheraudit_toolkit.py
            ```
            
        #### Nmap Scanner Usage
        
        * **Goal:** Identify running services and their versions, a critical first step in penetration testing.
        * **Scan Types:**
            * **Fast Scan (`-F -sV`):** Checks the 100 most common ports quickly.
            * **In-Depth Scan (`-p 1-100 -sV`):** Specifically targets a lower range of ports (1-100) and attempts to fingerprint the service running on each open port.
        
        * **Try for Nmap:**
            ```bash
            scanme.nmap.org
            ```
        #### SSH Credential Audit (Mock) Usage
        
        * **Goal:** Demonstrate how dictionary attacks work against network services like SSH (default port 22).
        * **Logic:** The tool runs a simulation where it attempts to log in to the specified mock host/port using a small list of common passwords. The underlying function uses the structure of a real `paramiko` connection attempt but is *hardcoded to find a specific weak credential* for educational demonstration purposes.
        * **Key Takeaway:** If a service uses default or easily guessed credentials, it will be compromised quickly by automated tools.
        """)


    # --- TAB 4: PRESENTATION SLIDES ---
    with tab4:
        st.subheader("Project Presentation 📽️")
        st.info("Click the button below to open the interactive slides in a new browser tab.")

        # This URL path works because the file is in the 'static' folder
        presentation_file = "php.txt"
        
        try:
            # Open and read the HTML file
            with open(presentation_file, "r", encoding="utf-8") as f:
                html_content = f.read()
            
            st.download_button(
                label="📥 Download Presentation ",
                data=html_content,
                file_name="php.txt",
                mime="text/html"
            )
        except FileNotFoundError:
            st.error(f"Error: '{presentation_file}' not found.")

if __name__ == '__main__':
    app()
