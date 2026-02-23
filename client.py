import socket
from crypto_utils import recv_framed, send_framed, verify_mac_then_decrypt, encrypt_then_mac

MASTER_KEY_HEX = "58c1b5a4ac34c6526630e563cb4c3b420a9f6886d2d2bb39f58d06472b1c77b340082ecf62e4c0d337ada6ef77c57ea01d3a2b89a281774bcf2b2dfe781010a9" * 64  # <-- SAME as server.py (replace!)
MASTER_KEY = bytes.fromhex(MASTER_KEY_HEX)

HOST = "127.0.0.1"
PORT = 5000

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Connected!")

        while True:
            text = input("Say something (or 'quit'): ").strip()
            if text.lower() == "quit":
                break

            payload = encrypt_then_mac(MASTER_KEY, text.encode())
            send_framed(s, payload)

            reply_payload = recv_framed(s)
            reply = verify_mac_then_decrypt(MASTER_KEY, reply_payload)
            print("Server reply:", reply.decode(errors="replace"))

if __name__ == "__main__":
    main()