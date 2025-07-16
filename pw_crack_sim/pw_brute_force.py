import hashlib
import bcrypt
import itertools
import string
import time
from typing import Optional, List
import sys
import os

# ----------- Hashing Utilities -----------

def sha256_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def bcrypt_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def bcrypt_check(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# -------- Password Cracking Methods ----------

def brute_force_sha256(target_hash: str, max_length: int, chars: str, show_progress: bool = False) -> Optional[str]:
    total_attempts = sum(len(chars) ** l for l in range(1, max_length+1))
    attempt = 0
    for length in range(1, max_length+1):
        for candidate in itertools.product(chars, repeat=length):
            guess = ''.join(candidate)
            attempt += 1
            if sha256_hash(guess) == target_hash:
                return guess
            if show_progress and attempt % 100000 == 0:
                percent = attempt * 100 / total_attempts
                print(f"  Tried {attempt:,} guesses ({percent:.2f}%)...")
    return None

def brute_force_bcrypt(target_hash: str, max_length: int, chars: str, show_progress: bool = False) -> Optional[str]:
    total_attempts = sum(len(chars) ** l for l in range(1, max_length+1))
    attempt = 0
    for length in range(1, max_length+1):
        for candidate in itertools.product(chars, repeat=length):
            guess = ''.join(candidate)
            attempt += 1
            if bcrypt_check(guess, target_hash):
                return guess
            if show_progress and attempt % 5000 == 0:
                percent = attempt * 100 / total_attempts
                print(f"  Tried {attempt:,} guesses ({percent:.2f}%)...")
    return None

def dictionary_attack_sha256(target_hash: str, wordlist: List[str]) -> Optional[str]:
    for word in wordlist:
        if sha256_hash(word.strip()) == target_hash:
            return word.strip()
    return None

def dictionary_attack_bcrypt(target_hash: str, wordlist: List[str]) -> Optional[str]:
    for word in wordlist:
        if bcrypt_check(word.strip(), target_hash):
            return word.strip()
    return None

def rainbow_table_attack(target_hash: str, rainbow_table: dict) -> Optional[str]:
    """Rainbow Table: dictionary mapping hash -> original password."""
    return rainbow_table.get(target_hash)


# ------------ Time Estimator ------------

def estimate_time_per_attempt(algo: str) -> float:
    import timeit
    if algo == 'sha256':
        stmt = "hashlib.sha256('test123'.encode()).hexdigest()"
        return timeit.timeit(stmt, globals={'hashlib': hashlib}, number=10000) / 10000
    elif algo == 'bcrypt':
        stmt = "bcrypt.checkpw('test123'.encode(), bcrypt.hashpw('test123'.encode(), bcrypt.gensalt()))"
        return timeit.timeit(stmt, globals={'bcrypt': bcrypt}, number=10) / 10
    else:
        return 0.0

# ------------- Loading Utils ---------------

def load_passwords(filepath: str) -> List[str]:
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]

def generate_rainbow_table(wordlist: List[str], algo: str) -> dict:
    table = {}
    for word in wordlist:
        if algo == 'sha256':
            table[sha256_hash(word)] = word
        else:
            # Not practical for bcrypt (hashes have random salts)
            pass
    return table

# ------------- Main CLI App ----------------

def main():
    try:
        print("== Password Cracking Simulator ==")
        print("Select attack method:")
        print("  1. Brute-force (SHA256 or bcrypt)")
        print("  2. Dictionary Attack (SHA256 or bcrypt)")
        print("  3. Rainbow Table (SHA256 only)")
        method = input("Enter number: ").strip()

        algo = input("Hash algorithm? [sha256/bcrypt]: ").lower().strip()
        if algo not in ('sha256', 'bcrypt'):
            print("Invalid algorithm.")
            sys.exit(1)

        chars = string.ascii_letters + string.digits + string.punctuation
        max_length = 5  # Or prompt the user

        if method == '1':
            print("Enter the password to hash and then try to crack (for educational, offline use):")
            password = input("Plain password: ").strip()
            if algo == 'sha256':
                h = sha256_hash(password)
                print(f"SHA256 hash: {h}")
                print("Attempting brute-force attack...")
                start = time.time()
                cracked = brute_force_sha256(h, max_length=max_length, chars=chars, show_progress=True)
                elapsed = time.time() - start
            else:
                h = bcrypt_hash(password)
                print(f"Bcrypt hash: {h}")
                print("Attempting brute-force attack (slow, for demo purposes)...")
                start = time.time()
                cracked = brute_force_bcrypt(h, max_length=3, chars=string.ascii_lowercase, show_progress=True)
                elapsed = time.time() - start
            if cracked is not None:
                print(f"Success! The password is: {cracked}")
            else:
                print("Failed to crack the password within the tested length/charset.")
            print(f"Time taken: {elapsed:.2f} seconds")
            per_attempt = estimate_time_per_attempt(algo)
            print(f"Avg. time per hash ({algo}): {per_attempt:.6f} sec")
        elif method == '2':
            print("Dictionary attack selected.")
            wordlist_path = input("Path to password wordlist (one password per line): ").strip()
            if not os.path.exists(wordlist_path):
                print("File does not exist.")
                sys.exit(1)
            wordlist = load_passwords(wordlist_path)
            target_pwd = input("Password to hash: ").strip()
            if algo == 'sha256':
                h = sha256_hash(target_pwd)
                start = time.time()
                cracked = dictionary_attack_sha256(h, wordlist)
                elapsed = time.time() - start
            else:
                h = bcrypt_hash(target_pwd)
                start = time.time()
                cracked = dictionary_attack_bcrypt(h, wordlist)
                elapsed = time.time() - start
            if cracked:
                print(f"Password found: {cracked}")
            else:
                print("Password not found in wordlist.")
            print(f"Time taken: {elapsed:.2f} seconds")
        elif method == '3':
            if algo != 'sha256':
                print("Rainbow table supported only for SHA256 in this example.")
                sys.exit(1)
            wordlist_path = input("Path to wordlist (one password per line): ").strip()
            if not os.path.exists(wordlist_path):
                print("File does not exist.")
                sys.exit(1)
            wordlist = load_passwords(wordlist_path)
            print("Generating rainbow table (mapping hash -> password)...")
            start = time.time()
            rainbow = generate_rainbow_table(wordlist, algo='sha256')
            elapsed = time.time() - start
            print(f"Rainbow table built in {elapsed:.2f} seconds")
            hash_to_crack = input("Enter hash to lookup: ").strip()
            found = rainbow_table_attack(hash_to_crack, rainbow)
            if found:
                print(f"Password found: {found}")
            else:
                print("No match found in rainbow table.")
        else:
            print("Invalid selection.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting gracefully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
