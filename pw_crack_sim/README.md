# Password Cracking Simulator

A simple **educational simulator** that demonstrates how password cracking works using brute-force, dictionary, and rainbow table attacks on hashed passwords, supporting SHA256 and bcrypt.

---

## Features

- **Brute-force attack**: Tests all possible character combinations for short passwords.
- **Dictionary attack**: Tries passwords from a provided wordlist file.
- **Rainbow table attack**: Instantly looks up SHA256 hashes precomputed from a wordlist.
- **Supports SHA256 and bcrypt**: Demonstrates difference between fast and slow hash algorithms.
- **Time/performance estimator** for each type of algorithm.
- **Graceful interruption**: Safely quits if interrupted (Ctrl+C).
- **Human-readable CLI** with prompts.

---

## Requirements

- Python 3.7 or above
- `bcrypt` library

Install dependencies with:
pip install -r requirements.txt

---

## How To Use

1. **Clone or download this repository**.
2. **(Optional)** Prepare a wordlist file (e.g., `wordlist.txt`) with one password per line.
3. Run the simulator:
python password_cracking_simulator.py
4. **Follow the on-screen menu:**
- Choose attack type (brute-force, dictionary, rainbow table)
- Select hash algorithm
- Enter or provide necessary inputs (plain passwords, wordlist path, or hash to crack)

---

## Notes & Disclaimer

- **For educational and legal use only!**
- Do **not** use this tool to attack systems or data you do not own or have written permission to test.
- For bcrypt brute-force, realistic passwords longer than 3-4 characters are **infeasible to crack** due to intentional slowness.
- To demonstrate dictionary and rainbow attacks, use simple or common passwords within your test wordlist.

---

## License

MIT License


