from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

if w3.is_connected():
    print("Blockchain connected successfully")
    print("Current block number:", w3.eth.block_number)
    print("\nAccounts on blockchain:")
    for i, account in enumerate(w3.eth.accounts):
        balance = w3.eth.get_balance(account)
        print(f"  Account {i}: {account}")
        print(f"  Balance: {w3.from_wei(balance, 'ether')} ETH")
        print()
else:
    print("ERROR: Cannot connect to blockchain")
    print("Make sure Ganache is running in Terminal 2")
