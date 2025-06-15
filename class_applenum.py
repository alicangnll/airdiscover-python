#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from biplist import readPlistFromString
from class_exploit import CVE_2025_24132
import requests
import subprocess
import ipaddress
import re
import time
from scapy.all import sniff, DNS, DNSQR, Ether
import re, netifaces, sys

class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"

    def print_colored(text, color):
        print(f"{color}{text}{Colors.RESET}")

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
              
Disclaimer : This program is for educational and informational purposes only. It is not intended to encourage or support any illegal or unethical activity, including hacking, cyber-attacks, or unauthorized access to computer systems, networks or data in any way.
              
""")


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
    def get_info(ip, port=7000):
        Colors.print_colored(f"[INFO] {ip}: Information request is being sent...", Colors.CYAN)
        try:
            url = f"http://{ip}:{port}/info"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            Colors.print_colored(f"[SUCCESS] {ip}: Information received.", Colors.GREEN)
            return response.content  # Plist binary olarak döner
        except requests.exceptions.Timeout:
            Colors.print_colored(f"[TIMEOUT] {ip}: Timeout.", Colors.RED)
            return None
        except requests.exceptions.ConnectionError:
            Colors.print_colored(f"[CONNECTION ERROR] {ip}: Connection could not be established.", Colors.RED)
            return None
        except requests.exceptions.HTTPError as err:
            Colors.print_colored(f"[HTTP ERROR] {ip}: {err}", Colors.RED)
            return None
        except Exception as e:
            Colors.print_colored(f"[ERROR] {ip}: Unknown error -> {e}", Colors.RED)
            return None

    @staticmethod
    def parser_data(ip):
        Colors.print_colored(f"[INFO] {ip}: Parsing plist data...", Colors.CYAN)
        try:
            plist_raw = macOS_Enum.get_info(ip)
            if not plist_raw:
                Colors.print_colored(f"[WARN] {ip}: Data could not be retrieved, parsing is not possible.", Colors.YELLOW)
                return
            data = readPlistFromString(plist_raw)
            Colors.print_colored(f"[PARSED] {ip}: Device Name: {data.get('name')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Model: {data.get('model')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: macAddress: {data.get('macAddress')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: OS Version: {data.get('osBuildVersion')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Source Version: {data.get('sourceVersion')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Sender IP and Port: {data.get('senderAddress')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Device ID: {data.get('deviceID')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: HDR Support: {data.get('receiverHDRCapability')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Screen Demo Mode: {data.get('screenDemoMode')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Initial Volume: {data.get('initialVolume')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Can Record Screen Stream: {data.get('canRecordScreenStream')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: KeepAlive Write to Body: {data.get('keepAliveSendStatsAsBody')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Protocol Version: {data.get('protocolVersion')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Volume Control Type: {data.get('volumeControlType')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Status Flags: {data.get('statusFlags')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: FeaturesEx: {data.get('featuresEx')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: Features (int): {data.get('features')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: psi: {data.get('psi')}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: pi: {data.get('pi')}", Colors.MAGENTA)
            pk_val = data.get('pk')
            if pk_val:
                Colors.print_colored(f"[PARSED] {ip}: pk (hex): {pk_val.hex()}", Colors.MAGENTA)
            else:
                Colors.print_colored(f"[PARSED] {ip}: pk: None", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: --- Supported Formats ---", Colors.MAGENTA)
            for k, v in data.get("supportedFormats", {}).items():
                Colors.print_colored(f"  {k}: {v}", Colors.MAGENTA)

            Colors.print_colored(f"[PARSED] {ip}: --- Extended Audio Formats ---", Colors.MAGENTA)
            for k, v in data.get("supportedAudioFormatsExtended", {}).items():
                Colors.print_colored(f"  {k}: {v}", Colors.MAGENTA)

            Colors.print_colored(f"[PARSED] {ip}: --- Playback Capabilities ---", Colors.MAGENTA)
            for k, v in data.get("playbackCapabilities", {}).items():
                Colors.print_colored(f"  {k}: {v}", Colors.MAGENTA)
            Colors.print_colored(f"[PARSED] {ip}: --- Vulnerabilities ---", Colors.RED)
            if tuple(int(x) for x in data.get('sourceVersion').split('.'))  < tuple(int(x) for x in "860.7.1".split('.')):
                Colors.print_colored(f"[VULNERABLE] {ip}: Potentially AirPlay RCE (CVE-2025-24132) Detected (AirPlay Version : {data.get('sourceVersion')})", Colors.RED)
                user_input = input("Exploit detected. Do you confirm exploitation? (I will only send the 'whoami' command) [yes/no]: ")
                if user_input.strip().lower() == "yes":
                    CVE_2025_24132.exploit_24132()
                else:
                    print("Exploitation aborted by user.")
                    pass
            else:
                Colors.print_colored(f"[SECURE] {ip}: AirPlay RCE (CVE-2025-24132) Not Found. System Update! (AirPlay Version : {data.get('sourceVersion')})", Colors.GREEN)
        except Exception as e:
            Colors.print_colored(f"[ERROR] {ip}: Unknown error -> {e}", Colors.RED)

    @staticmethod
    def ping_ip(ip):
        Colors.print_colored(f"[INFO] {ip}: Ping started...", Colors.CYAN)
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0

    @staticmethod
    def get_mac(ip):
        Colors.print_colored(f"[INFO] {ip}: Retrieving MAC address...", Colors.CYAN)
        try:
            arp_result = subprocess.check_output(["arp", "-n", str(ip)], text=True)
            mac_match = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", arp_result, re.I)
            if mac_match:
                mac = mac_match.group(1).upper()
                return mac
            else:
                Colors.print_colored(f"[FAIL] {ip}: MAC address not found.", Colors.RED)
                return None
        except subprocess.CalledProcessError:
            Colors.print_colored(f"[ERROR] {ip}: arp command could not be executed.", Colors.RED)
            return None

    @staticmethod
    def is_apple_mac(mac):
        for oui in macOS_Enum.APPLE_OUIS:
            if mac.startswith(oui):
                Colors.print_colored(f"[INFO] {mac}: Apple device OUI detected.", Colors.CYAN)
                return True
        return False

    @staticmethod
    def scan_network(network_cidr):
        Main.print_banner()
        found_devices = []
        if "/" in network_cidr:
            network = ipaddress.ip_network(network_cidr, strict=False)
            Colors.print_colored(f"[START] Network scanning begins: {network_cidr}", Colors.CYAN)
            for ip in network.hosts():
                if macOS_Enum.ping_ip(ip):
                    mac = macOS_Enum.get_mac(ip)
                    if mac and macOS_Enum.is_apple_mac(mac):
                        Colors.print_colored(f"[FOUND] Apple device found - IP: {ip}, MAC: {mac}\n", Colors.GREEN)
                        macOS_Enum.parser_data(ip)
                        Colors.print_colored(f"[INFO] 10 seconds to review the information\n", Colors.GREEN)
                        time.sleep(10)
                        found_devices.append((str(ip), mac))
            if not found_devices:
                Colors.print_colored("[RESULT] Apple device not found.", Colors.CYAN)
            else:
                Colors.print_colored(f"[RESULT] Total number of Apple devices found : {len(found_devices)}", Colors.CYAN)
        else:
            if macOS_Enum.ping_ip(network_cidr):
                mac = macOS_Enum.get_mac(network_cidr)
                if mac and macOS_Enum.is_apple_mac(mac):
                    Colors.print_colored(f"[FOUND] Apple device found - IP: {network_cidr}, MAC: {mac}\n", Colors.GREEN)
                    macOS_Enum.parser_data(network_cidr)
                    Colors.print_colored(f"[INFO] 10 seconds to review the information\n", Colors.GREEN)
                    time.sleep(10)
                    found_devices.append((str(network_cidr), mac))
            if not found_devices:
                Colors.print_colored("[RESULT] Apple device not found.", Colors.CYAN)
            else:
                Colors.print_colored(f"[RESULT] Total number of Apple devices found : {len(found_devices)}", Colors.CYAN)
        

class Apple_iPhone_Enum:
    def find_awdl_interface():
        try:
            output = subprocess.check_output(["ifconfig"], text=True)
        except Exception as e:
            Colors.print_colored(f"Hata: {e}", Colors.RED)
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
                            Colors.print_colored(f"\n📡 AirDrop Device Discovered!", Colors.GREEN)
                            Colors.print_colored(f"   ✳️ Checked: {query_name}", Colors.GREEN)
                            Colors.print_colored(f"   🟢 Source MAC : {packet[Ether].src}", Colors.GREEN)
                            Colors.print_colored(f"   🔴 Destination MAC  : {packet[Ether].dst}", Colors.GREEN)
                        else:
                            Colors.print_colored(f"   🔴 ERROR  : Adapter not found!\n", Colors.RED)
                            sys.exit(0)
                else:
                    Colors.print_colored("   ⚠️ MAC address information not available (no Ether layer)", Colors.RED)

    def main():
        Main.print_banner()
        INTERFACE = Apple_iPhone_Enum.find_awdl_interface()
        if INTERFACE is None:
            Colors.print_colored(f"   🔴 ERROR  : Adapter not found!\n", Colors.RED)
        else:
            Colors.print_colored(f"\n📡 AWDL Adapter Name : " + INTERFACE, Colors.CYAN)
            adapter_mac_addr = Apple_iPhone_Enum.get_mac_address(INTERFACE)
            Colors.print_colored("🛰️  listening to mDNS (AirDrop) over " + INTERFACE + " interface...\n", Colors.CYAN)
            try:
                Colors.print_colored(f"\n📡 AWDL Receiver MAC : " + adapter_mac_addr, Colors.CYAN)
                sniff(
                    iface=INTERFACE,
                    filter="udp port 5353",  # mDNS port
                    prn=Apple_iPhone_Enum.handle_packet,
                    store=0
                    )
            except PermissionError:
                Colors.print_colored("❌ This script must be run with root/sudo.", Colors.RED)


