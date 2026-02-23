# Secure Encrypted Client-Server Messaging (Python)

This project implements a secure TCP client-server messaging system in Python using AES-256-CBC encryption and HMAC-SHA256 integrity verification. It demonstrates how encrypted communication can be built at the application layer without relying on TLS (for educational purposes).

## Features
- AES-256-CBC encryption
- HMAC-SHA256 integrity verification
- Random IV generated per message
- Encrypt-then-MAC design
- Custom TCP message framing (4-byte length header)
- Tampering detection

## How It Works
1. The client encrypts plaintext using AES-CBC with a random 16-byte IV.
2. An HMAC (SHA-256) is generated over the IV and ciphertext.
3. The payload format:
   IV (16 bytes) || Ciphertext || HMAC (32 bytes)
4. The server verifies the HMAC before decrypting and rejects tampered messages.

All messages are framed using a 4-byte big-endian length header to properly handle TCP streaming.

## Project Structure
AES_PROJECT/
├── client.py
├── server.py
├── crypto_utils.py
├── requirements.txt
└── README.md

## Installation
Make sure Python 3.10+ is installed.

Install dependencies:
pip install cryptography

Or:
pip install -r requirements.txt

## Running the Project
Start the server:
python server.py

In a second terminal, start the client:
python client.py

Type messages in the client to send encrypted data to the server.

The server prints the raw encrypted payload and the decrypted message to demonstrate confidentiality and integrity verification.

## Security Notes
- AES-256 for confidentiality
- HMAC-SHA256 for integrity
- Constant-time HMAC comparison
- Pre-shared key for simplicity

NOTE: In real-world systems, TLS or secure key exchange (e.g., Diffie-Hellman) should be used instead of a hardcoded shared key.

## Purpose
Built to understand:
- Symmetric encryption in network systems
- Message authentication and tamper detection
- TCP framing design
- Secure protocol construction fundamentals

Author: Radwan  
Computer Science Student# secure-encrypted-client-server
