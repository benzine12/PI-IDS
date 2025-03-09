import sys
import time
import random
from scapy.all import sendp, RadioTap, Dot11, Dot11ProbeReq, Dot11Elt

FAKE_NETWORKS = [
    "LinkSys", "Netgear", "TP-Link", "Home_WiFi", "DLink",
    "FreeWiFi", "xfinitywifi", "AndroidAP", "iPhone", "Guest",
    "PublicWiFi", "Airport", "WiFi_Mobile", "Hotspot", "Default",
    "PrettyFlyForAWifi", "HideYoKidsHideYoWifi", "FBIVan",
    "WuTangLAN", "NachoWifi", "TheLANBeforeTime", "BillWiTheScienceFi",
    "TellMyWifiLoveHer", "ItHurtsWhenIP", "WiFi5GHzSecured", "Hidden_Network"
]

def generate_random_mac():
    """Generate a random MAC address."""
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

def send_probe_requests(interface, num_probes=30, delay=0.2):
    """
    Send multiple probe requests with different SSIDs.
    
    Args:
        interface: Wireless interface in monitor mode
        num_probes: Number of probe requests to send
        delay: Delay between probe requests in seconds
    """
    if num_probes > len(FAKE_NETWORKS):
        # If we need more probes than network names, we'll reuse some names
        networks = FAKE_NETWORKS * (num_probes // len(FAKE_NETWORKS) + 1)
    else:
        networks = FAKE_NETWORKS[:num_probes]
    
    # Use the same MAC for all probes to trigger detection
    src_mac = generate_random_mac()
    
    print(f"Sending {num_probes} probe requests from MAC {src_mac}...")
    
    for i, network in enumerate(networks[:num_probes]):
        # Create a probe request
        dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", 
                      addr2=src_mac, addr3="ff:ff:ff:ff:ff:ff")
        probe = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID', info=network, len=len(network))
        rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
        dsset = Dot11Elt(ID='DSset', info=b'\x01')
        
        frame = RadioTap()/dot11/probe/essid/rates/dsset
        
        # Send the packet
        sendp(frame, iface=interface, verbose=0)
        
        # Print progress
        print(f"[{i+1}/{num_probes}] Probing for: {network}")
        
        # Wait a bit between packets
        time.sleep(delay)
    
    print(f"\nSent {num_probes} probe requests from MAC {src_mac}")
    print("Check your WIDS for 'Probe Scanner' detection alerts!")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface> [number_of_probes] [delay]")
        sys.exit(1)
        
    interface = sys.argv[1]
    
    num_probes = 50  # Default number of probes
    if len(sys.argv) > 2:
        num_probes = int(sys.argv[2])
        
    delay = 0.2  # Default delay between probes
    if len(sys.argv) > 3:
        delay = float(sys.argv[3])
    
    send_probe_requests(interface, num_probes, delay)