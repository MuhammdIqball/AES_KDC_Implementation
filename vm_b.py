import os
import socket
import threading
from AESmodule import AES_Encrypt, AES_Decrypt

HOST = "0.0.0.0"
BOB_PORT = 5000
ID_BOB = "Bob"


def pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n] * n)


def unpad(data):
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    return data[:-pad_len]


def encrypt_blocks(data, key):
    return b"".join(AES_Encrypt(data[i:i + 16], key) for i in range(0, len(data), 16))


def decrypt_blocks(data, key):
    return b"".join(AES_Decrypt(data[i:i + 16], key) for i in range(0, len(data), 16))


def encrypt_message(message, key):
    return encrypt_blocks(pad(message.encode()), key)


def decrypt_message(ciphertext, key):
    return unpad(decrypt_blocks(ciphertext, key)).decode(errors="replace")


def unpack_id(data):
    return data.rstrip(b"\x00").decode(errors="replace")


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


def handle_alice(conn, addr, state):
    tb = recv_packet(conn)
    if tb is None or len(tb) != 32:
        conn.close()
        return

    plain = decrypt_blocks(tb, state["master_key"])
    ks = plain[0:16]
    id_a = unpack_id(plain[16:32])

    n2 = int.from_bytes(os.urandom(16), "big")
    c_n2 = encrypt_blocks(n2.to_bytes(16, "big"), ks)
    send_packet(conn, c_n2)

    c_resp = recv_packet(conn)
    if c_resp is None or len(c_resp) != 16:
        conn.close()
        return

    resp = int.from_bytes(decrypt_blocks(c_resp, ks), "big")
    expected = (n2 - 1) % (1 << 128)
    if resp != expected:
        print("\n[Error] Verifikasi gagal: kunci tidak sesuai.")
        print("Pilihan Anda: ", end="", flush=True)
        conn.close()
        return

    print("\nHandshake KDC selesai. Session Key siap digunakan.")
    print("Pilihan Anda: ", end="", flush=True)

    if state["conn"] and state["conn"] != conn:
        try:
            state["conn"].close()
        except OSError:
            pass

    state["session_key"] = ks
    state["conn"] = conn
    state["peer"] = id_a
    state["handshake_event"].set()

    while state["conn"] == conn:
        cipher = recv_packet(conn)
        if cipher is None:
            print(f"\n[Info] Koneksi dengan {state['peer']} terputus.")
            print("Pilihan Anda: ", end="", flush=True)
            if state["conn"] == conn:
                state["conn"] = None
                state["session_key"] = None
            break
        plain_text = decrypt_message(cipher, state["session_key"])
        print(f"\n[Ciphertext diterima] {cipher.hex()}")
        print(f"[{state['peer']}] {plain_text}")
        print("Pilihan Anda: ", end="", flush=True)


def server_thread(state):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, BOB_PORT))
    server.listen(5)
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_alice, args=(conn, addr, state), daemon=True).start()
        except OSError:
            break


def main():
    print("Initial Setting VM B (Bob)")
    kb_str = input("Masukkan Master Key Bob: ")
    state = {
        "master_key": format_key(kb_str),
        "session_key": None,
        "conn": None,
        "peer": "Alice",
        "handshake_event": threading.Event()
    }

    threading.Thread(target=server_thread, args=(state,), daemon=True).start()
    print(f"VM B menunggu koneksi di port {BOB_PORT}.\n")

    while True:
        print()
        print("1. Jalankan Protokol KDC (Tukar Kunci Sesi)")
        print("2. Kirim Pesan Terenkripsi")
        print("3. Ubah Master Key / Kunci")
        print("4. Keluar")
        pilihan = input("Pilihan Anda: ").strip()

        if pilihan == "1":
            if state["session_key"]:
                print(f"Session Key saat ini: {state['session_key'].hex()}")
            else:
                print(f"Menunggu koneksi dan tiket dari Alice di port {BOB_PORT}...")
                print("(Silakan jalankan menu 1 pada VM A / Alice)")
                state["handshake_event"].wait(timeout=10)
                if state["session_key"]:
                    print(f"Handshake selesai. Session Key: {state['session_key'].hex()}")
                else:
                    print("Belum ada koneksi dari Alice.")
        elif pilihan == "2":
            if not state["session_key"] or not state["conn"]:
                print("Belum ada sesi aktif. Silakan lakukan pertukaran kunci terlebih dahulu.")
            else:
                pesan = input("Masukkan pesan: ").strip()
                if pesan:
                    cipher = encrypt_message(pesan, state["session_key"])
                    print(f"[Ciphertext dikirim] {cipher.hex()}")
                    send_packet(state["conn"], cipher)
                else:
                    print("Pesan kosong, batal mengirim.")
        elif pilihan == "3":
            kb_baru = input("Masukkan Master Key Bob baru: ")
            state["master_key"] = format_key(kb_baru)
            if state["conn"]:
                try:
                    state["conn"].close()
                except OSError:
                    pass
                state["conn"] = None
            state["session_key"] = None
            state["handshake_event"].clear()
            print(f"Master Key Bob diperbarui: {state['master_key'].decode(errors='replace')} (Hex: {state['master_key'].hex()})")
            print("Sesi lama direset. Silakan lakukan pertukaran kunci ulang.")
        elif pilihan == "4":
            if state["conn"]:
                try:
                    state["conn"].close()
                except OSError:
                    pass
            print("Program dihentikan.")
            break
        else:
            print("Pilihan tidak valid.")


if __name__ == "__main__":
    main()
