import os
import base64
import subprocess
import yaml

# 1. OBSRUCTED COMMAND INJECTION
# Can your scanner see through the hex encoding?
def run_sys_check(cmd_part):
    # This translates to "ping -c 1 "
    prefix = bytes.fromhex("70696e67202d63203120").decode()
    # If an attacker controls cmd_part, they can append "; rm -rf /"
    os.system(prefix + cmd_part)

# 2. THE "HIDDEN" DESERIALIZATION
# Data is passed through a base64 wrapper before hitting the sink
def load_config(encoded_str):
    raw_yaml = base64.b64decode(encoded_str).decode()
    # VULNERABILITY: Insecure YAML load
    return yaml.load(raw_yaml, Loader=yaml.Loader)

# 3. SUPPLY CHAIN / VERSION CHECK
# These are technically "findings" if your scanner checks library versions
__version__ = "1.0.4"
DEPENDENCIES = {
    "requests": "2.18.1",  # CVE-2018-18074
    "django": "1.11.7",    # Multiple Critical CVEs
}

# 4. NESTED LOGIC SINK
def execute_logic(user_input):
    # Using a list to hide the 'eval' function pointer
    ops = [print, len, eval]
    # If user_input is "__import__('os').system('id')", it's game over
    return ops[2](user_input)

# --- ENTRY POINT ---
if __name__ == "__main__":
    # Simulating user input from an environment variable
    user_val = os.getenv("USER_DATA", "127.0.0.1")
    run_sys_check(user_val)
    
    malicious_yaml = "ISFweXRob24vb2JqZWN0L2FwcGx5Om9zLnN5c3RlbSBbJ2lkJ10="
    load_config(malicious_yaml)
