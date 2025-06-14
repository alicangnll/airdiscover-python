# 🍏 AirDiscover - Apple Device Discovery and Network Scanning Tool 🚀

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ali%20Can%20Gönüllü-blue)](https://www.linkedin.com/in/alicangonullu/)

![banner](https://github.com/user-attachments/assets/45466523-feca-49c6-8395-3875432947d1)

## 📖 About the Project

**AirDiscover** is a Python-based tool designed to discover Apple devices (macOS and iPhone) on your local network and gather detailed information about them.  
It identifies Apple devices by detecting MAC addresses using their OUI (Organizationally Unique Identifier) and retrieves IP addresses along with system details.

> ⚠️ *Note: Software only works on macOS operating system.*

## ⚠️ Disclaimer

This program is for educational and informational purposes only. It is not intended to encourage or support any illegal or unethical activity, including hacking, cyber-attacks, or unauthorized access to computer systems, networks or data in any way.

## 📡 About Apple Wireless Direct Link (AWDL) on macOS

Apple Wireless Direct Link (AWDL) is a proprietary low-latency, high-speed ad-hoc Wi-Fi protocol developed by Apple. It underpins several Apple services such as AirDrop, AirPlay, and Sidecar, enabling peer-to-peer communication between Apple devices without the need for a traditional Wi-Fi network.

On macOS, AWDL operates on a separate virtual network interface (`awdl0`) and dynamically switches Wi-Fi channels and MAC addresses to maintain privacy and efficiency. This interface is not always active; it becomes visible when certain Apple services are invoked (e.g., AirDrop or AirPlay browsing is initiated).

In the context of `airdiscover-python`, AWDL is leveraged for passively discovering nearby Apple devices that announce themselves via multicast DNS (mDNS) over the AWDL interface. Since AWDL frames are not typically forwarded by access points, this discovery is only possible when the scanning host is directly connected to the same channel and capable of parsing traffic from the `awdl0` interface.

**Technical Notes:**

* On macOS, `awdl0` can be monitored using tools like `tcpdump`, `Wireshark`, or `scapy`, provided proper permissions are granted.
* Capturing from `awdl0` may require elevated privileges or SIP (System Integrity Protection) adjustments.
* AWDL traffic uses IPv6 and mDNS (UDP port 5353) heavily to announce services (e.g., `_airplay._tcp.local`, `_raop._tcp.local`).

> 🧪 If you're using `airdiscover-python` on macOS, ensure your system supports monitoring the `awdl0` interface and has the necessary permissions to read AWDL traffic.

## ✨ Features

- 🔍 Scan for macOS and iPhone devices on the network  
- 🍎 Filter devices based on Apple OUI prefixes  
- 📋 Extract detailed plist-based information from devices  
- 🌐 Customizable network range for scanning  
- 🛠️ Command-line interface with argparse support  
- 🛡️ Robust error handling and informative logging  
- 🚨 Detect devices potentially vulnerable to **CVE-2025-24132** (AirPlay version exposure)  


## 🛠️ Installation

```bash
git clone https://github.com/alicangnll/airdiscover-python.git
cd airdiscover-python
pip install -r requirements.txt
````

## ✨ Pictures

### macOS Scanning
![scr1](https://github.com/user-attachments/assets/64bf044a-21c9-42fe-8ce6-02f259d2081b)

### iPhone Scanning
![scr2](https://github.com/user-attachments/assets/7dea57f9-9324-4785-9877-b62d50ed2960)

## 🚀 Usage

### ❓ Help Menu

```bash
python3 main.py -h
```

### 💡 Example Commands

* 📱 Scan for iPhone devices:

```bash
python3 main.py -i iphone
```

* 💻 Scan for macOS devices in a specified network range:

```bash
python3 main.py -i macos -m 192.168.1.0/24
```

* 💻 Scan for macOS devices in a specified network address:

```bash
python3 main.py -i macos -m 192.168.1.42
```

> ⚠️ *Note: The network range parameter (`-m`) is only used in `macos` mode.*


## 👨‍💻 Developer

Ali Can Gönüllü
🔗 [LinkedIn Profile](https://www.linkedin.com/in/alicangonullu/)

## 📄 License

This project is licensed under the Apache 2 License. See the `LICENSE` file for details.
