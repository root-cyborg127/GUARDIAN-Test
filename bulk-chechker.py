import requests
from colorama import init, Fore

# Initialize Colorama
init(autoreset=True)

def check_ip_safety(ip_address):
    api_key = '0d02adbac5c84155a9ee608b7b6c6494629265fc05cf7d3b2b4df95260401b1b'
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        stats = result['data']['attributes']['last_analysis_stats']
        malicious_votes = stats['malicious']
        suspicious_votes = stats['suspicious']
        harmless_votes = stats['harmless']

        # Determine IP safety and print result in color
        if malicious_votes + suspicious_votes >= 2:
            print(Fore.RED + f"[!] The IP {ip_address} might be suspicious or harmful.")
        elif malicious_votes > 0 or suspicious_votes > 0:
            print(Fore.YELLOW + f"[~] The IP {ip_address} has some suspicious characteristics.")
        else:
            print(Fore.GREEN + f"[+] The IP {ip_address} appears to be safe.")
    else:
        print(Fore.RED + "[-] Failed to retrieve information.")

def read_ips_from_file(file_path):
    with open(file_path, 'r') as file:
        for line in file.readlines():
            ip_address = line.strip()
            if ip_address:
                check_ip_safety(ip_address)

if __name__ == "__main__":
    file_path = 'D:\Virustotal TY PRO\ip-list'  # Replace this with your actual file path, if different
    read_ips_from_file(file_path)