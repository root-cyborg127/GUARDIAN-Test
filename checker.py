import requests

def check_ip_safety(ip_address):
    # Replace YOUR_VIRUSTOTAL_API_KEY_HERE with your actual VirusTotal API key
    api_key = '0d02adbac5c84155a9ee608b7b6c6494629265fc05cf7d3b2b4df95260401b1b'
    
    # URL for the VirusTotal API using the provided IP address
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    
    # Headers including the required API key for authentication
    headers = {'x-apikey': api_key}
    
    # Making the GET request to the VirusTotal API
    response = requests.get(url, headers=headers)
    
    # Check if the request was successful (HTTP status code 200)
    if response.status_code == 200:
        # Parsing the JSON response
        result = response.json()
        
        # Extracting the analysis statistics from the response
        stats = result['data']['attributes']['last_analysis_stats']
        malicious_votes = stats['malicious']
        suspicious_votes = stats['suspicious']
        harmless_votes = stats['harmless']
        undetected_votes = stats['undetected']
        
        # Display the retrieved analysis results
        print(f"IP Address: {ip_address}")
        print(f"Analysis Votes - Malicious: {malicious_votes}, Suspicious: {suspicious_votes}, Harmless: {harmless_votes}, Undetected: {undetected_votes}")
        
        # Logic to determine if the IP address is safe, suspicious, or harmful
        if malicious_votes + suspicious_votes >= 2:
            print("The IP might be suspicious or harmful. Exercise caution.")
        elif malicious_votes > 0 or suspicious_votes > 0:
            print("The IP has some suspicious characteristics. Be cautious.")
        else:
            print("The IP appears to be safe.")
    else:
        # Handling unsuccessful API requests
        print("Failed to retrieve information. Please check your API key and the IP address.")

# Example usage
if __name__ == "__main__":
    ip_address = input("Enter an IP address to check: ")
    check_ip_safety(ip_address)