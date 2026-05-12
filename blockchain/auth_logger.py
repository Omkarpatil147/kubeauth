from web3 import Web3
import json
from datetime import datetime

w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

def log_auth_event(username, access_result):
    if not w3.is_connected():
        print("ERROR: Blockchain not connected")
        print("Start Ganache in Terminal 2 first")
        return

    account = w3.eth.accounts[0]

    log_data = {
        "user": username,
        "access": access_result,
        "timestamp": str(datetime.now())
    }

    tx_hash = w3.eth.send_transaction({
        "from": account,
        "to": account,
        "value": 0,
        "data": w3.to_hex(text=json.dumps(log_data))
    })

    print("Auth event logged to blockchain!")
    print(f"  User     : {username}")
    print(f"  Access   : {access_result}")
    print(f"  Tx Hash  : {tx_hash.hex()}")
    print(f"  Block No : {w3.eth.block_number}")
    print("-" * 45)

print("Logging 3 auth events to blockchain...")
print()
log_auth_event("devuser", "granted")
log_auth_event("hacker", "denied")
log_auth_event("admin", "granted")
print("Done! Check block number increased above.")
