from scapy.all import rdpcap
from collections import Counter
import requests
from colorama import init, Fore

init(autoreset=True)

API_KEY = '0d02adbac5c84155a9ee608b7b6c6494629265fc05cf7d3b2b4df95260401b1b'
PCAP_FILE = 'D:\\Virustotal TY PRO\\2024-06-25-Latrodectus-infection-with-BackConnect-and-Keyhole-VNC.pcap' # replace with your .pcap file path

def extract_ips(pcap_file):
    packets = rdpcap(pcap_file)
    ips = [packet[1].src for packet in packets if packet.haslayer('IP')]
    ips += [packet[1].dst for packet in packets if packet.haslayer('IP')]
    return Counter(ips)

def check_ip_safety(ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        stats = result['data']['attributes']['last_analysis_stats']
        malicious_votes = stats['malicious']
        suspicious_votes = stats['suspicious']

        if malicious_votes + suspicious_votes >= 2:
            print(Fore.RED + f"[Malicious] {ip_address}")
        elif malicious_votes > 0 or suspicious_votes > 0:
            print(Fore.YELLOW + f"[Suspicious] {ip_address}")
        else:
            print(Fore.GREEN + f"[Safe] {ip_address}")
    else:
        print(Fore.RED + f"Error checking {ip_address}. Status code: {response.status_code}")

def main(pcap_file):
    unique_ips = extract_ips(pcap_file)
    print(f"Found {len(unique_ips)} unique IP addresses.")
    
    for ip in unique_ips.keys():
        check_ip_safety(ip)

if __name__ == "__main__":
    main(PCAP_FILE)