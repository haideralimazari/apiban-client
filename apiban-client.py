#!/usr/bin/env python3
"""
Production-Grade APIban Threat Intelligence Client for Asterisk / Linux Firewalls
Automatically fetches malicious threat IPs from apiban.org and populates 
an ipset list to drop malicious traffic efficiently at the iptables firewall layer.
"""

import os
import sys
import time
import json
import logging
import ipaddress
import subprocess
import urllib.request
import urllib.error
import signal
from pathlib import Path

# Load environment variables from .env file if present
from dotenv import load_dotenv
env_path = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=env_path)

# Configuration Constants
API_KEY = os.getenv("APIBAN_API_KEY")
IPSET_NAME = "apiban"
FETCH_INTERVAL = 3600  # Sync interval (1 hour)

# Configure Professional Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("APIbanClient")

def signal_handler(sig, frame):
    """Handle graceful shutdown on system termination signals."""
    logger.info("Received shutdown signal. Exiting gracefully...")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def init_ipset():
    """Initialize the ipset hash set and ensure the corresponding iptables drop rule exists."""
    try:
        # Create ipset hash:ip set if it does not already exist
        subprocess.run(
            ["ipset", "create", IPSET_NAME, "hash:ip", "-exist"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Check if iptables rule exists
        check_rule = subprocess.run(
            ["iptables", "-C", "INPUT", "-m", "set", "--match-set", IPSET_NAME, "src", "-j", "DROP"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Append rule if missing
        if check_rule.returncode != 0:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-m", "set", "--match-set", IPSET_NAME, "src", "-j", "DROP"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            logger.info(f"Successfully created iptables drop rule for ipset '{IPSET_NAME}'.")
        else:
            logger.info(f"Iptables drop rule for ipset '{IPSET_NAME}' is already active.")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to initialize ipset/iptables rules: {e.stderr.decode().strip()}")
        sys.exit(1)

def is_valid_ip(ip_str):
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def fetch_and_block():
    """Fetch threat list from APIban and sync into local ipset."""
    url = f"https://apiban.org/api/{API_KEY}/json"
    req = urllib.request.Request(
        url, 
        headers={
            'User-Agent': 'APIban-Production-Client/2.0',
            'Accept': 'application/json'
        }
    )
    
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status != 200:
                logger.warning(f"APIban server returned HTTP status {response.status}")
                return
            
            data = json.loads(response.read().decode('utf-8'))
            ips = data.get('ip', [])
            
            if ips and isinstance(ips, list):
                added_count = 0
                for ip in ips:
                    if is_valid_ip(ip):
                        res = subprocess.run(
                            ["ipset", "add", IPSET_NAME, ip, "-exist"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE
                        )
                        if res.returncode == 0:
                            added_count += 1
                    else:
                        logger.warning(f"Ignored invalid IP: {ip}")
                        
                logger.info(f"Successfully synchronized. Blocked {added_count} threat IPs via APIban.")
            else:
                logger.info("Received empty IP list or invalid JSON response.")
                
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error during fetch: {e.code} - {e.reason}")
    except urllib.error.URLError as e:
        logger.error(f"Network error during fetch: {e.reason}")
    except json.JSONDecodeError:
        logger.error("Failed to parse JSON response from APIban.")
    except Exception as e:
        logger.error(f"Unexpected error in fetch_and_block: {str(e)}")

if __name__ == "__main__":
    if not API_KEY or API_KEY == "YOUR_API_KEY":
        logger.critical("API key is not configured inside .env file!")
        sys.exit(1)
        
    logger.info("Starting production APIban threat-intelligence client daemon...")
    init_ipset()
    
    while True:
        fetch_and_block()
        logger.info(f"Sleeping for {FETCH_INTERVAL} seconds until next sync...")
        time.sleep(FETCH_INTERVAL)