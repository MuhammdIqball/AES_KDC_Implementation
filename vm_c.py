import os
import socket
import threading
from AESmodule import AES_Encrypt, AES_Decrypt

HOST = "0.0.0.0"
KDC_PORT = 6000


def encrypt_blocks(data, key):
    return b"".join(AES_Encrypt(data[i:i + 16], key) for i in range(0, len(data), 16))


def pack_id(name):
    return name.encode().ljust(16, b"\x00")


def unpack_id(data):
    return data.rstrip(b"\x00").decode()


def format_key(key_str):
    b = key_str.encode()
    if len(b) < 16:
        return b.ljust(16, b"\x00")
    return b[:16]


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def send_packet(conn, data):
    conn.sendall(len(data).to_bytes(4, "big") + data)


def recv_packet(conn):
    header = recv_exact(conn, 4)
    if header is None:
        return None
    return recv_exact(conn, int.from_bytes(header, "big"))


def handle_request(conn, addr, master_keys):
    with conn:
        request = recv_packet(conn)
        if request is None or len(request) != 48:
            return

        id_a = unpack_id(request[0:16])
        id_b = unpack_id(request[16:32])
        n1 = request[32:48]
        print(f"\n[Langkah 1] Permintaan dari {addr}: ID_A={id_a}, ID_B={id_b}, N1={n1.hex()}")

        if id_a not in master_keys or id_b not in master_keys:
            print(f"[KDC] ID tidak dikenal: {id_a} / {id_b}")
            print("Pilihan Anda: ", end="", flush=True)
            return

        ks = os.urandom(16)
        print(f"[Langkah 2] Session Key (Ks) dibangkitkan: {ks.hex()}")

        tb = encrypt_blocks(ks + pack_id(id_a), master_keys[id_b])
        print(f"[Langkah 2] Tiket untuk {id_b} (T_B): {tb.hex()}")

        paket = encrypt_blocks(ks + pack_id(id_a) + pack_id(id_b) + n1 + tb, master_keys[id_a])
        print(f"[Langkah 2] Paket untuk {id_a}: {paket.hex()}")

        send_packet(conn, paket)
        print(f"[Langkah 2] Paket dikirim ke {id_a}")
        print("Pilihan Anda: ", end="", flush=True)


def server_thread(master_keys):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, KDC_PORT))
    server.listen(5)
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_request, args=(conn, addr, master_keys), daemon=True).start()
        except OSError:
            break


def main():
    print("Initial Setting KDC")
    ka_str = input("Masukkan Master Key Alice: ")
    kb_str = input("Masukkan Master Key Bob: ")
    master_keys = {"Alice": format_key(ka_str), "Bob": format_key(kb_str)}

    threading.Thread(target=server_thread, args=(master_keys,), daemon=True).start()
    # print(f"KDC berjalan di port {KDC_PORT}.\n")

    while True:
        print("1. Status Server & Master Key")
        print("2. Ubah Master Key")
        print("3. Keluar")
        pilihan = input().strip()

        if pilihan == "1":
            print(f"Port KDC : {KDC_PORT}")
            print(f"Key Alice: {master_keys['Alice'].decode(errors='replace')} (Hex: {master_keys['Alice'].hex()})")
            print(f"Key Bob  : {master_keys['Bob'].decode(errors='replace')} (Hex: {master_keys['Bob'].hex()})")
        elif pilihan == "2":
            target = input("Alice/Bob : ").strip()
            if target in master_keys:
                k_baru = input(f"Masukkan Master Key baru untuk {target}: ")
                master_keys[target] = format_key(k_baru)
                print(f"Master Key {target} berhasil diperbarui.")
            else:
                print("Nama entitas tidak valid!")
        elif pilihan == "3":
            # print("KDC dihentikan.")
            break
        else:
            print("Pilihan tidak valid.")


if __name__ == "__main__":
    main()
