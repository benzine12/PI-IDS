#!/usr/bin/env python3
"""
Beacon Spam Test Script - Generates multiple beacon frames to test WIDS detection

This script sends a large number of beacon frames with different SSIDs from the same 
MAC address to simulate a beacon flooding attack and trigger the BeaconSpamDetector 
in your WIDS.

Usage:
  sudo python3 beacon_spam_test.py <interface> [number_of_beacons] [delay]

Requirements:
  - Scapy
  - Root/sudo privileges
  - Wireless interface in monitor mode
"""

import os
import sys
import time
import random
import subprocess
import shutil
from scapy.all import sendp, RadioTap, Dot11, Dot11Beacon, Dot11Elt

# Some fake network names to use in beacon frames
FAKE_NETWORKS = [
    "FreeWiFi", "PublicHotspot", "Guest_Network", "Airport_WiFi", 
    "CoffeeShop", "Hotel_Guest", "Default_SSID", "OpenNetwork", 
    "PublicAccess", "FreeInternet", "WebConnect", "WiFi-Hotspot",
    "Connect_Here", "Internet_Access", "PublicWLAN", "WiFi_Zone",
    "Network", "Wireless", "WiFi", "Hotspot", "Free_WiFi", 
    "Public_WiFi", "Open_WiFi", "WiFi_Access", "Internet"
]

def generate_random_mac():
    """Generate a random MAC address."""
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

def send_beacon_frames(interface, num_beacons=100, delay=0.05):
    """
    Send multiple beacon frames to simulate a beacon flooding attack.
    
    Args:
        interface: Wireless interface in monitor mode
        num_beacons: Number of beacon frames to send
        delay: Delay between beacon frames in seconds
    """
    # Use the same source MAC for all beacons to trigger detection
    src_mac = generate_random_mac()
    
    # Randomly select SSIDs for the beacons
    if num_beacons > len(FAKE_NETWORKS):
        # If we need more beacons than network names, we'll reuse some names
        networks = []
        for _ in range(num_beacons):
            networks.append(random.choice(FAKE_NETWORKS))
    else:
        networks = FAKE_NETWORKS[:num_beacons]
    
    print(f"Sending {num_beacons} beacon frames from MAC {src_mac}...")
    
    for i, network in enumerate(networks[:num_beacons]):
        # Calculate random channel between 1 and 11
        channel = random.randint(1, 11)
        
        # Create a beacon frame
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", 
                      addr2=src_mac, addr3=src_mac)
        
        # Create beacon layer
        beacon = Dot11Beacon(cap='ESS')
        
        # Add SSID, supported rates, and channel
        essid = Dot11Elt(ID='SSID', info=network, len=len(network))
        rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        dsset = Dot11Elt(ID='DSset', info=chr(channel).encode())
        
        # Create the frame
        frame = RadioTap()/dot11/beacon/essid/rates/dsset
        
        # Send the packet
        sendp(frame, iface=interface, verbose=0)
        
        # Print progress every 10 beacons
        if (i+1) % 10 == 0 or i == 0:
            print(f"[{i+1}/{num_beacons}] Sent beacons for: {network} on channel {channel}")
        
        # Wait a small amount between packets
        time.sleep(delay)
    
    print(f"\nSent {num_beacons} beacon frames from MAC {src_mac}")
    print("Check your WIDS for 'Beacon Spam' detection alerts!")

def setup_virtual_env():
    """Set up a virtual environment with necessary dependencies."""
    # Check if the env folder exists and delete it if present
    if os.path.exists("env"):
        print("Removing existing virtual environment...")
        shutil.rmtree("env")
    else:
        print("No existing virtual environment found. Proceeding...")
    
    # Create a new virtual environment
    print("Creating a new virtual environment...")
    subprocess.run(["python3", "-m", "venv", "env"], check=True)
    
    # Activate the virtual environment and install scapy
    activate_script = os.path.join("env", "bin", "activate")
    print("Activating virtual environment and installing dependencies...")
    subprocess.run(["bash", "-c", f"source {activate_script} && pip install scapy"], check=True)
    
    # Run the script with sudo
    print("Running beacon_spam_test.py with sudo...")
    subprocess.run(["sudo", f"./env/bin/python", "beacon_spam_test.py"] + sys.argv[1:], check=True)

if __name__ == "__main__":
    # If not run with sudo, set up virtual environment and re-run with sudo
    if os.geteuid() != 0:
        print("This script requires root privileges. Setting up virtual environment...")
        setup_virtual_env()
        sys.exit(0)

    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface> [number_of_beacons] [delay]")
        sys.exit(1)
        
    interface = sys.argv[1]
    
    num_beacons = 100  # Default number of beacons
    if len(sys.argv) > 2:
        num_beacons = int(sys.argv[2])
        
    delay = 0.05  # Default delay between beacons
    if len(sys.argv) > 3:
        delay = float(sys.argv[3])
    
    send_beacon_frames(interface, num_beacons, delay)