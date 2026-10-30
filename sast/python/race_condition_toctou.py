import os
import time

BALANCE_FILE = "/tmp/user_balance.txt"

def deduct_balance(amount: int):
    # VULNERABLE: Time-of-check to time-of-use race condition window (CWE-362)
    with open(BALANCE_FILE, "r") as f:
        balance = int(f.read().strip())
    
    if balance >= amount:
        time.sleep(0.05)  # Simulated processing window enabling double-spend race
        new_balance = balance - amount
        with open(BALANCE_FILE, "w") as f:
            f.write(str(new_balance))
        return True
    return False
