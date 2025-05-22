#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from biplist import readPlistFromString
import requests
import subprocess
import ipaddress
import re
import time
from scapy.all import sniff, DNS, DNSQR, Ether
import re, netifaces, sys



class Main:
    @staticmethod
    def print_banner():
        print("""
 █████╗ ██╗██████╗ ██████╗ ██╗ ██████╗ ██████╗ ███████╗███████╗██████╗ 
██╔══██╗██║██╔══██╗██╔══██╗██║██╔════╝ ██╔══██╗██╔════╝██╔════╝██╔══██╗
███████║██║██║  ██║██████╔╝██║██║  ███╗██████╔╝█████╗  █████╗  ██████╔╝
██╔══██║██║██║  ██║██╔══██╗██║██║   ██║██╔═══╝ ██╔══╝  ██╔══╝  ██╔═══╝ 
██║  ██║██║██████╔╝██║  ██║██║╚██████╔╝██║     ███████╗███████╗██║     
╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝╚═╝     

                🌐 AirDiscover - Developed by Ali Can Gönüllü
       🔗 LinkedIn: https://www.linkedin.com/in/alicangonullu/

""")
import requests
import subprocess
import re
import ipaddress
import time
from biplist import readPlistFromString

class macOS_Enum:
    # Apple OUI listesi (ilk 3 byte)
    APPLE_OUIS = [
    "00:1C:B3", "00:17:F2", "00:03:93", "FC:25:3F", "AC:87:A3", "28:CF:E9",
    "F4:5C:89", "3C:07:54", "D8:30:62", "BC:65:9F", "A4:5E:60", "D0:11:E5",
    "00:25:00", "00:0A:27", "08:00:07", "00:0B:63", "74:E1:B6", "00:14:51",
    "00:1F:F3", "84:38:35", "A8:20:66", "C4:2C:03", "AC:1B:FB", "00:03:0E",
    "00:1D:4F", "00:1E:C2", "A0:14:3D", "F8:1A:67", "5C:02:72", "C0:EE:FB",
    "5C:96:9D", "38:C9:E0", "00:23:32", "B8:17:C2", "B0:17:C2", "3C:5A:B4",
    "A4:5E:60", "00:26:08", "78:31:C1", "00:26:B0", "60:03:08", "84:7A:88",
    "7C:C3:A1", "D0:03:4B", "3C:22:FB", "74:4D:28"
    ]


    @staticmethod
    def get_info(ip):
        print(f"[INFO] {ip}: Information request is being sent...")
        try:
            url = f"http://{ip}:7000/info"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            print(f"[SUCCESS] {ip}: Information received.")
            return response.content  # Plist binary olarak döner
        except requests.exceptions.Timeout:
            print(f"[TIMEOUT] {ip}: Timeout.")
            return None
        except requests.exceptions.ConnectionError:
            print(f"[CONNECTION ERROR] {ip}: Connection could not be established.")
            return None
        except requests.exceptions.HTTPError as err:
            print(f"[HTTP ERROR] {ip}: {err}")
            return None
        except Exception as e:
            print(f"[ERROR] {ip}: Unknown error -> {e}")
            return None

    @staticmethod
    def parser_data(ip):
        print(f"[INFO] {ip}: Parsing plist data...")
        try:
            plist_raw = macOS_Enum.get_info(ip)
            if not plist_raw:
                print(f"[WARN] {ip}: Data could not be retrieved, parsing is not possible.")
                return
            data = readPlistFromString(plist_raw)

            print(f"[PARSED] {ip}: Device Name: {data.get('name')}")
            print(f"[PARSED] {ip}: Model: {data.get('model')}")
            print(f"[PARSED] {ip}: macAddress: {data.get('macAddress')}")
            print(f"[PARSED] {ip}: OS Version: {data.get('osBuildVersion')}")
            print(f"[PARSED] {ip}: Source Version: {data.get('sourceVersion')}")
            print(f"[PARSED] {ip}: Sender IP and Port: {data.get('senderAddress')}")
            print(f"[PARSED] {ip}: Device ID: {data.get('deviceID')}")
            print(f"[PARSED] {ip}: HDR Support: {data.get('receiverHDRCapability')}")
            print(f"[PARSED] {ip}: Screen Demo Mode: {data.get('screenDemoMode')}")
            print(f"[PARSED] {ip}: Initial Volume: {data.get('initialVolume')}")
            print(f"[PARSED] {ip}: Can Record Screen Stream: {data.get('canRecordScreenStream')}")
            print(f"[PARSED] {ip}: KeepAlive Write to Body: {data.get('keepAliveSendStatsAsBody')}")
            print(f"[PARSED] {ip}: Protocol Version: {data.get('protocolVersion')}")
            print(f"[PARSED] {ip}: Volume Control Type: {data.get('volumeControlType')}")
            print(f"[PARSED] {ip}: Status Flags: {data.get('statusFlags')}")
            print(f"[PARSED] {ip}: FeaturesEx: {data.get('featuresEx')}")
            print(f"[PARSED] {ip}: Features (int): {data.get('features')}")
            print(f"[PARSED] {ip}: psi: {data.get('psi')}")
            print(f"[PARSED] {ip}: pi: {data.get('pi')}")
            pk_val = data.get('pk')
            if pk_val:
                print(f"[PARSED] {ip}: pk (hex): {pk_val.hex()}")
            else:
                print(f"[PARSED] {ip}: pk: None")
            print(f"[PARSED] {ip}: --- Supported Formats ---")
            for k, v in data.get("supportedFormats", {}).items():
                print(f"  {k}: {v}")

            print(f"[PARSED] {ip}: --- Extended Audio Formats ---")
            for k, v in data.get("supportedAudioFormatsExtended", {}).items():
                print(f"  {k}: {v}")

            print(f"[PARSED] {ip}: --- Playback Capabilities ---")
            for k, v in data.get("playbackCapabilities", {}).items():
                print(f"  {k}: {v}")
        except Exception as e:
            print(f"[ERROR] {ip}: Unknown error -> {e}")

    @staticmethod
    def ping_ip(ip):
        print(f"[INFO] {ip}: Ping started...")
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0

    @staticmethod
    def get_mac(ip):
        print(f"[INFO] {ip}: Retrieving MAC address...")
        try:
            arp_result = subprocess.check_output(["arp", "-n", str(ip)], text=True)
            mac_match = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", arp_result, re.I)
            if mac_match:
                mac = mac_match.group(1).upper()
                return mac
            else:
                print(f"[FAIL] {ip}: MAC address not found.")
                return None
        except subprocess.CalledProcessError:
            print(f"[ERROR] {ip}: arp command could not be executed.")
            return None

    @staticmethod
    def is_apple_mac(mac):
        for oui in macOS_Enum.APPLE_OUIS:
            if mac.startswith(oui):
                print(f"[INFO] {mac}: Apple device OUI detected.")
                return True
        return False

    @staticmethod
    def scan_network(network_cidr):
        Main.print_banner()  # Eğer Main sınıfın varsa burayı açabilirsin
        network = ipaddress.ip_network(network_cidr, strict=False)
        found_devices = []
        print(f"[START] Network scanning begins: {network_cidr}")
        for ip in network.hosts():
            if macOS_Enum.ping_ip(ip):
                mac = macOS_Enum.get_mac(ip)
                if mac and macOS_Enum.is_apple_mac(mac):
                    print(f"[FOUND] Apple device found - IP: {ip}, MAC: {mac}\n")
                    macOS_Enum.parser_data(ip)
                    print(f"[INFO] 60 seconds to review the information\n")
                    time.sleep(60)
                    found_devices.append((str(ip), mac))
        if not found_devices:
            print("[RESULT] Apple device not found.")
        else:
            print(f"[RESULT] Total number of Apple devices found : {len(found_devices)}")
        return found_devices

class Apple_iPhone_Enum:
    def find_awdl_interface():
        try:
            output = subprocess.check_output(["ifconfig"], text=True)
        except Exception as e:
            print(f"Hata: {e}")
            return None
        interfaces = []
        for line in output.splitlines():
            if not line.startswith('\t') and line.strip():  # interface adı satırı
                iface = line.split(':')[0]
                interfaces.append(iface)

        for iface in interfaces:
            if iface.lower().startswith("awdl"):
                return iface
        return None
    
    def get_mac_address(interface):
        try:
            addrs = netifaces.ifaddresses(interface)
            mac = addrs[netifaces.AF_LINK][0]['addr']
            return mac
        except (ValueError, KeyError):
            return None
    
    def handle_packet(packet):
        airdrop_pattern = re.compile(r"_airdrop\._tcp\.local", re.IGNORECASE)
        INTERFACE = Apple_iPhone_Enum.find_awdl_interface()
        adapter_mac_addr = Apple_iPhone_Enum.get_mac_address(INTERFACE)
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query_name = packet[DNSQR].qname.decode(errors="ignore")
            if re.search(airdrop_pattern, query_name):
                veri = []
                if packet.haslayer(Ether):
                    if adapter_mac_addr != packet[Ether].src or adapter_mac_addr is not None:
                        if packet[Ether].src not in veri:
                            veri.append(packet[Ether].src)
                            print(f"\n📡 AirDrop Device Discovered!")
                            print(f"   ✳️ Checked: {query_name}")
                            print(f"   🟢 Source MAC : {packet[Ether].src}")
                            print(f"   🔴 Destination MAC  : {packet[Ether].dst}")
                        else:
                            print(f"   🔴 ERROR  : Adapter not found!\n")
                            sys.exit(0)
                else:
                    print("   ⚠️ MAC address information not available (no Ether layer)")

    def main():
        Main.print_banner()
        INTERFACE = Apple_iPhone_Enum.find_awdl_interface()
        if INTERFACE is None:
            print(f"   🔴 ERROR  : Adapter not found!\n")
        else:
            print(f"\n📡 AWDL Adapter Name : " + INTERFACE)
            adapter_mac_addr = Apple_iPhone_Enum.get_mac_address(INTERFACE)
            print("🛰️  listening to mDNS (AirDrop) over " + INTERFACE + " interface...\n")
            try:
                print(f"\n📡 AWDL Receiver MAC : " + adapter_mac_addr)
                sniff(
                    iface=INTERFACE,
                    filter="udp port 5353",  # mDNS port
                    prn=Apple_iPhone_Enum.handle_packet,
                    store=0
                    )
            except PermissionError:
                print("❌ This script must be run with root/sudo.")


