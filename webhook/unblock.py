import requests
import sys

BASE = "http://localhost:8080"

def list_blocked():
    try:
        r = requests.get(f"{BASE}/security",
                         cookies={"session": sys.argv[-1]
                                  if len(sys.argv) > 1 else ""})
        d = r.json()
        blocked = d.get("blocked", [])
        if not blocked:
            print("No blocked IPs right now.")
            return
        print(f"Blocked IPs ({len(blocked)}):")
        for ip in blocked:
            print(f"  - {ip}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    list_blocked()
