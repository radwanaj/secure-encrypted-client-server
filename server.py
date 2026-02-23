import socket
from crypto_utils import recv_framed, send_framed, verify_mac_then_decrypt, encrypt_then_mac

# 64-byte master key (hex -> bytes). Put the SAME key in client.py.
MASTER_KEY_HEX = "58c1b5a4ac34c6526630e563cb4c3b420a9f6886d2d2bb39f58d06472b1c77b340082ecf62e4c0d337ada6ef77c57ea01d3a2b89a281774bcf2b2dfe781010a9" * 64  # <-- replace with real random hex (128 hex chars = 64 bytes)
MASTER_KEY = bytes.fromhex(MASTER_KEY_HEX)

HOST = "127.0.0.1"
PORT = 5000

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"Server listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)
            while True:
                try:
                    payload = recv_framed(conn)
                    print("Raw encrypted payload:", payload)
                except Exception as e:
                    print("Connection ended:", e)
                    break

                try:
                    msg = verify_mac_then_decrypt(MASTER_KEY, payload)
                except Exception as e:
                    print("Bad message:", e)
                    break

                print("Client says:", msg.decode(errors="replace"))

                reply = f"Got it: {msg.decode(errors='replace')}".encode()
                out_payload = encrypt_then_mac(MASTER_KEY, reply)
                send_framed(conn, out_payload)

if __name__ == "__main__":
    main()