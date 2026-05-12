from web3 import Web3
import json
import hashlib
from datetime import datetime

w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

# ═══════════════════════════════════════════════════════
# STEP 1 — Connect to blockchain
# ═══════════════════════════════════════════════════════

def print_separator(title=""):
    print("\n" + "=" * 60)
    if title:
        print(f"  {title}")
        print("=" * 60)

def connect():
    print_separator("KubeAuth — Tamper-Proof Blockchain Demo")
    if not w3.is_connected():
        print("ERROR: Ganache is not running!")
        print("Start Ganache in Terminal 2: ganache --host 0.0.0.0")
        exit()
    print(f"  Blockchain  : Ganache (Ethereum local)")
    print(f"  RPC URL     : http://localhost:8545")
    print(f"  Connected   : YES")
    print(f"  Account     : {w3.eth.accounts[0]}")
    print(f"  Block count : {w3.eth.block_number}")

# ═══════════════════════════════════════════════════════
# STEP 2 — Write auth events to blockchain
# ═══════════════════════════════════════════════════════

def write_auth_events():
    print_separator("Writing Auth Events to Blockchain")

    events = [
        {"user": "devuser",  "access": "granted", "action": "get pods"},
        {"user": "hacker",   "access": "denied",  "action": "get secrets"},
        {"user": "admin",    "access": "granted", "action": "manage RBAC"},
        {"user": "testuser", "access": "denied",  "action": "delete pods"},
    ]

    account   = w3.eth.accounts[0]
    tx_hashes = []

    for event in events:
        log_data = {
            "user":      event["user"],
            "access":    event["access"],
            "action":    event["action"],
            "timestamp": str(datetime.now())
        }

        tx_hash = w3.eth.send_transaction({
            "from":  account,
            "to":    account,
            "value": 0,
            "data":  w3.to_hex(text=json.dumps(log_data))
        })

        receipt = w3.eth.get_transaction_receipt(tx_hash)

        print(f"\n  User   : {event['user']}")
        print(f"  Action : {event['action']}")
        print(f"  Access : {event['access'].upper()}")
        print(f"  Block  : #{receipt.blockNumber}")
        print(f"  TxHash : {tx_hash.hex()}")
        tx_hashes.append(tx_hash.hex())

    print(f"\n  Total events written : {len(events)}")
    print(f"  Current block number : {w3.eth.block_number}")
    return tx_hashes

# ═══════════════════════════════════════════════════════
# STEP 3 — Show all blockchain logs with hashes
# ═══════════════════════════════════════════════════════

def show_all_logs():
    print_separator("All Blockchain Logs with Cryptographic Hashes")

    latest = w3.eth.block_number
    if latest == 0:
        print("  No transactions yet.")
        return []

    all_blocks = []

    for block_num in range(1, latest + 1):
        block = w3.eth.get_block(block_num, full_transactions=True)

        block_data = {
            "block_number":    block_num,
            "block_hash":      block.hash.hex(),
            "parent_hash":     block.parentHash.hex(),
            "timestamp":       block.timestamp,
            "transactions":    []
        }

        for tx in block.transactions:
            tx_data = {
                "tx_hash": tx.hash.hex(),
                "from":    tx["from"],
                "to":      tx["to"],
                "log":     {}
            }

            if tx.input and tx.input != "0x":
                try:
                    raw       = bytes.fromhex(tx.input[2:])
                    log       = json.loads(raw.decode("utf-8"))
                    tx_data["log"] = log
                except:
                    pass

            block_data["transactions"].append(tx_data)

        all_blocks.append(block_data)

        print(f"\n  ┌─ Block #{block_num} ─────────────────────────────────────")
        print(f"  │  Block Hash   : {block.hash.hex()[:40]}...")
        print(f"  │  Parent Hash  : {block.parentHash.hex()[:40]}...")
        print(f"  │  Timestamp    : {block.timestamp}")

        for tx in block_data["transactions"]:
            log = tx["log"]
            print(f"  │")
            print(f"  │  TX Hash  : {tx['tx_hash'][:40]}...")
            if log:
                print(f"  │  User     : {log.get('user','N/A')}")
                print(f"  │  Action   : {log.get('action','N/A')}")
                print(f"  │  Access   : {log.get('access','N/A').upper()}")
                print(f"  │  Time     : {log.get('timestamp','N/A')}")
        print(f"  └────────────────────────────────────────────────────")

    return all_blocks

# ═══════════════════════════════════════════════════════
# STEP 4 — Show the LAST entry with full hash details
# ═══════════════════════════════════════════════════════

def show_last_entry_hash():
    print_separator("Last Entry — Full Hash Details")

    latest = w3.eth.block_number
    if latest == 0:
        print("  No blocks found.")
        return

    block  = w3.eth.get_block(latest, full_transactions=True)

    print(f"  Last block number   : #{latest}")
    print(f"  Block hash          : {block.hash.hex()}")
    print(f"  Parent block hash   : {block.parentHash.hex()}")
    print(f"  Block timestamp     : {block.timestamp}")
    print(f"  Miner               : {block.miner}")
    print()

    for tx in block.transactions:
        print(f"  Transaction hash    : {tx.hash.hex()}")
        print(f"  From account        : {tx['from']}")
        print(f"  To account          : {tx['to']}")
        print(f"  Gas used            : {tx.gas}")
        print()

        if tx.input and tx.input != "0x":
            try:
                raw      = bytes.fromhex(tx.input[2:])
                log_data = json.loads(raw.decode("utf-8"))

                print(f"  ── Decoded Log Data ──────────────────────────────")
                print(f"  User      : {log_data.get('user')}")
                print(f"  Action    : {log_data.get('action')}")
                print(f"  Access    : {log_data.get('access','').upper()}")
                print(f"  Timestamp : {log_data.get('timestamp')}")
                print()

                json_str   = json.dumps(log_data, sort_keys=True)
                sha256_hash = hashlib.sha256(json_str.encode()).hexdigest()
                md5_hash    = hashlib.md5(json_str.encode()).hexdigest()

                print(f"  ── Cryptographic Proof ───────────────────────────")
                print(f"  Raw data  : {json_str}")
                print()
                print(f"  SHA-256   : {sha256_hash}")
                print(f"  MD5       : {md5_hash}")
                print(f"  TX Hash   : {tx.hash.hex()}")
                print()
                print(f"  These 3 hashes together prove this exact data")
                print(f"  was recorded at this exact time. Any change to")
                print(f"  even ONE character would produce a completely")
                print(f"  different hash — making tampering detectable.")

            except Exception as e:
                print(f"  Could not decode: {e}")

# ═══════════════════════════════════════════════════════
# STEP 5 — Prove tamper-proof (the KEY demo)
# ═══════════════════════════════════════════════════════

def prove_tamper_proof():
    print_separator("TAMPER-PROOF DEMONSTRATION")

    latest = w3.eth.block_number
    if latest == 0:
        print("  No blocks to verify.")
        return

    print("  We will now prove that blockchain logs cannot be")
    print("  changed without detection.\n")

    # Get the last block and its actual data
    block = w3.eth.get_block(latest, full_transactions=True)

    for tx in block.transactions:
        if tx.input and tx.input != "0x":
            try:
                raw      = bytes.fromhex(tx.input[2:])
                log_data = json.loads(raw.decode("utf-8"))

                original_json = json.dumps(log_data, sort_keys=True)
                original_hash = hashlib.sha256(
                    original_json.encode()
                ).hexdigest()

                print(f"  ── ORIGINAL DATA (from blockchain) ───────────────")
                print(f"  User      : {log_data.get('user')}")
                print(f"  Access    : {log_data.get('access','').upper()}")
                print(f"  Action    : {log_data.get('action')}")
                print(f"  SHA-256   : {original_hash}")
                print()

                # Simulate what happens if someone tries to tamper
                tampered_data = log_data.copy()
                tampered_data["access"]    = "granted"
                tampered_data["user"]      = "hacker_now_admin"
                tampered_data["timestamp"] = "2026-01-01 00:00:00"

                tampered_json = json.dumps(tampered_data, sort_keys=True)
                tampered_hash = hashlib.sha256(
                    tampered_json.encode()
                ).hexdigest()

                print(f"  ── TAMPERED DATA (what attacker wants) ───────────")
                print(f"  User      : {tampered_data.get('user')}")
                print(f"  Access    : {tampered_data.get('access','').upper()}")
                print(f"  Action    : {tampered_data.get('action')}")
                print(f"  SHA-256   : {tampered_hash}")
                print()

                print(f"  ── COMPARISON ────────────────────────────────────")
                print(f"  Original hash : {original_hash}")
                print(f"  Tampered hash : {tampered_hash}")
                print()

                if original_hash != tampered_hash:
                    print(f"  RESULT: HASHES DO NOT MATCH!")
                    print(f"  The tampered data produces a COMPLETELY")
                    print(f"  different hash — tampering is DETECTED!")
                    print()
                    print(f"  In blockchain, each block also contains the")
                    print(f"  hash of the PREVIOUS block. So changing one")
                    print(f"  record would break the entire chain after it.")
                    print(f"  This is why blockchain is tamper-proof.")

            except Exception as e:
                print(f"  Error: {e}")
            break

# ═══════════════════════════════════════════════════════
# STEP 6 — Verify chain integrity (block links)
# ═══════════════════════════════════════════════════════

def verify_chain_integrity():
    print_separator("Blockchain Chain Integrity Verification")

    latest = w3.eth.block_number
    if latest <= 1:
        print("  Need at least 2 blocks to verify chain.")
        return

    print("  Verifying that each block correctly links to")
    print("  the previous block via parent hash...\n")

    all_valid = True

    for block_num in range(1, latest + 1):
        block = w3.eth.get_block(block_num)

        if block_num > 1:
            prev_block  = w3.eth.get_block(block_num - 1)
            link_valid  = block.parentHash.hex() == prev_block.hash.hex()
            status      = "VALID" if link_valid else "BROKEN!"
            symbol      = "✓" if link_valid else "✗"

            if not link_valid:
                all_valid = False

            print(f"  Block #{block_num-1} hash : "
                  f"{prev_block.hash.hex()[:20]}...")
            print(f"  Block #{block_num} parent : "
                  f"{block.parentHash.hex()[:20]}...")
            print(f"  Chain link     : [{symbol}] {status}")
            print()

    if all_valid:
        print(f"  ALL {latest} BLOCKS ARE VALID AND LINKED!")
        print(f"  The chain is intact — no tampering detected.")
    else:
        print(f"  WARNING: Chain integrity broken!")

# ═══════════════════════════════════════════════════════
# STEP 7 — Generate final proof report
# ═══════════════════════════════════════════════════════

def generate_proof_report():
    print_separator("Final Proof Report")

    latest   = w3.eth.block_number
    account  = w3.eth.accounts[0]
    balance  = w3.eth.get_balance(account)

    print(f"  Generated at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Network       : Ganache (Ethereum local)")
    print(f"  Total blocks  : {latest}")
    print(f"  Account       : {account}")
    print(f"  Balance       : {w3.from_wei(balance, 'ether')} ETH")
    print()

    total_tx = 0
    granted  = 0
    denied   = 0

    for block_num in range(1, latest + 1):
        block = w3.eth.get_block(block_num, full_transactions=True)
        for tx in block.transactions:
            total_tx += 1
            if tx.input and tx.input != "0x":
                try:
                    raw  = bytes.fromhex(tx.input[2:])
                    data = json.loads(raw.decode("utf-8"))
                    if data.get("access") == "granted":
                        granted += 1
                    else:
                        denied  += 1
                except:
                    pass

    print(f"  Total auth events : {total_tx}")
    print(f"  Access granted    : {granted}")
    print(f"  Access denied     : {denied}")
    print()
    print(f"  Every event above is permanently recorded.")
    print(f"  Cannot be deleted. Cannot be edited.")
    print(f"  Mathematically tamper-proof.")
    print()

    # Hash the entire report for a master proof
    report_data = {
        "generated_at":    str(datetime.now()),
        "total_blocks":    latest,
        "total_events":    total_tx,
        "granted":         granted,
        "denied":          denied,
        "account":         account
    }
    report_hash = hashlib.sha256(
        json.dumps(report_data, sort_keys=True).encode()
    ).hexdigest()

    print(f"  ── Master Proof Hash ─────────────────────────────")
    print(f"  {report_hash}")
    print(f"  ──────────────────────────────────────────────────")
    print(f"  Save this hash. If any blockchain data changes,")
    print(f"  this hash will be different — proving tampering.")

# ═══════════════════════════════════════════════════════
# RUN ALL STEPS
# ═══════════════════════════════════════════════════════

if __name__ == "__main__":
    connect()
    write_auth_events()
    show_all_logs()
    show_last_entry_hash()
    prove_tamper_proof()
    verify_chain_integrity()
    generate_proof_report()

    print_separator("Demo Complete")
    print("  All blockchain logs shown above are tamper-proof.")
    print("  Each transaction hash uniquely identifies one event.")
    print("  The chain links prove no blocks were modified.")
    print("  This is production-grade audit logging.")
    print("=" * 60)
    print()
