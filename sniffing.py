from scapy.all import *
from scapy.layers.inet import IP, Ether
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore
import argparse
import requests

# Color Module
init()
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.LIGHTYELLOW_EX
reset = Fore.RESET

# Function to get location information for an IP address


def get_ip_location(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        if response.status_code == 200:
            data = response.json()
            location = data.get("city", "Unknown")
            region = data.get("region", "Unknown")
            country = data.get("country", "Unknown")
            return f"{location}, {region}, {country}"
        else:
            return "Unknown"
    except Exception as e:
        return "Unknown"


def sniff_packets(iface):
    if iface:
        sniff(filter='port 80', prn=process_packet, iface=iface, store=False)
    else:
        sniff(prn=process_packet, store=False)


def process_packet(packet):
    try:
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            # Get geolocation for source and destination IP addresses
            src_location = get_ip_location(src_ip)
            dst_location = get_ip_location(dst_ip)

            # print(f"{blue} [+] {src_mac} from {src_location} is using port {src_port} to connect to {dst_mac} at {dst_location}:{dst_port}{reset}")
            print(
                f"{blue} [+] {src_ip} from {src_location} is using port {src_port} to connect to {dst_ip} at {dst_location}:{dst_port}{reset}")

        if packet.haslayer(HTTPRequest):
            url = packet[HTTPRequest].Host.decode(
            ) + packet[HTTPRequest].Path.decode()
            method = packet[HTTPRequest].Method.decode()
            print(
                f"{green} [+] {packet[IP].src} is making an HTTP Request to {url} with Method {method}{reset}")

            # Extract and format HTTP headers
            headers = packet[HTTPRequest].fields
            print(f"[+] HTTP Headers:")
            for key, value in headers.items():
                # Check if the value is valid UTF-8 before decoding
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8')
                    except UnicodeDecodeError:
                        # If not valid UTF-8, represent as bytes
                        value = repr(value)
                print(f"    {key}: {value}")

            if packet.haslayer(Raw):
                raw_data = packet.getlayer(Raw).load
                try:
                    decoded_raw_data = raw_data.decode('utf-8')
                except UnicodeDecodeError:
                    # Represent non-UTF-8 data as bytes
                    decoded_raw_data = repr(raw_data)
                print(f"{red} [+] Useful Raw data: {decoded_raw_data}{reset}")

    except Exception as e:
        print(f"{red} [!] Error processing packet: {str(e)}{reset}")


def main():
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer")
    parser.add_argument(
        "interface", help="Network interface to sniff packets on")
    args = parser.parse_args()
    sniff_packets(args.interface)


if __name__ == "__main__":
    main()
