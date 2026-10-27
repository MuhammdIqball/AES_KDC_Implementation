import os
import socket
import threading
from AESmodule import AES_Encrypt, AES_Decrypt

KDC_PORT = 6000
BOB_PORT = 5000
ID_ALICE = "Alice"
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


def pack_id(name):
    return name.encode().ljust(16, b"\x00")


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


def receive_loop(conn, state):
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


def run_kdc_handshake(state):
    if state["conn"]:
        try:
            state["conn"].close()
        except OSError:
            pass
        state["conn"] = None
        state["session_key"] = None

    n1 = os.urandom(16)
    request = pack_id(ID_ALICE) + pack_id(ID_BOB) + n1

    try:
        kdc = socket.create_connection((state["kdc_host"], KDC_PORT), timeout=5)
    except OSError as e:
        print(f"[Error] Tidak dapat terhubung ke KDC ({state['kdc_host']}:{KDC_PORT}): {e}")
        return

    send_packet(kdc, request)

    paket = recv_packet(kdc)
    kdc.close()
    if paket is None:
        print("[Error] KDC tidak mengirimkan paket balasan.")
        return

    plain = decrypt_blocks(paket, state["master_key"])
    ks = plain[0:16]
    id_a = unpack_id(plain[16:32])
    id_b = unpack_id(plain[32:48])
    n1_recv = plain[48:64]
    tb = plain[64:96]

    if n1_recv != n1:
        print("[Error] Verifikasi N1 gagal: kunci salah atau terjadi replay attack.")
        return

    try:
        bob = socket.create_connection((state["bob_host"], BOB_PORT), timeout=5)
    except OSError as e:
        print(f"[Error] Tidak dapat terhubung ke Bob ({state['bob_host']}:{BOB_PORT}): {e}")
        return

    send_packet(bob, tb)

    c_n2 = recv_packet(bob)
    if c_n2 is None or len(c_n2) != 16:
        print("[Error] Bob menutup koneksi atau mengirim data tidak valid.")
        bob.close()
        return

    n2 = int.from_bytes(decrypt_blocks(c_n2, ks), "big")
    f_n2 = (n2 - 1) % (1 << 128)

    c_resp = encrypt_blocks(f_n2.to_bytes(16, "big"), ks)
    send_packet(bob, c_resp)
    print("Handshake KDC selesai. Session Key siap digunakan.")

    state["session_key"] = ks
    state["conn"] = bob
    threading.Thread(target=receive_loop, args=(bob, state), daemon=True).start()


def main():
    print("Initial Setting VM A (Alice)")
    ka_str = input("Masukkan Master Key Alice: ")
    kdc_host = input("Masukkan IP KDC (VM C) [default 127.0.0.1]: ").strip() or "127.0.0.1"
    bob_host = input("Masukkan IP Bob (VM B) [default 127.0.0.1]: ").strip() or "127.0.0.1"

    state = {
        "master_key": format_key(ka_str),
        "kdc_host": kdc_host,
        "bob_host": bob_host,
        "session_key": None,
        "conn": None,
        "peer": "Bob"
    }

    while True:
        print()
        print("1. Jalankan Protokol KDC (Tukar Kunci Sesi)")
        print("2. Kirim Pesan Terenkripsi")
        print("3. Ubah Master Key / Kunci")
        print("4. Keluar")
        pilihan = input("Pilihan Anda: ").strip()

        if pilihan == "1":
            run_kdc_handshake(state)
        elif pilihan == "2":
            if not state["session_key"] or not state["conn"]:
                print("Belum ada sesi aktif. Silakan jalankan protokol KDC (Menu 1) terlebih dahulu.")
            else:
                pesan = input("Masukkan pesan: ").strip()
                if pesan:
                    cipher = encrypt_message(pesan, state["session_key"])
                    print(f"[Ciphertext dikirim] {cipher.hex()}")
                    send_packet(state["conn"], cipher)
                else:
                    print("Pesan kosong, batal mengirim.")
        elif pilihan == "3":
            ka_baru = input("Masukkan Master Key Alice baru: ")
            state["master_key"] = format_key(ka_baru)
            if state["conn"]:
                try:
                    state["conn"].close()
                except OSError:
                    pass
                state["conn"] = None
            state["session_key"] = None
            print(f"Master Key Alice diperbarui: {state['master_key'].decode(errors='replace')} (Hex: {state['master_key'].hex()})")
            tanya = input("Ingin ubah IP KDC / Bob juga? (y/n): ").strip().lower()
            if tanya == "y":
                state["kdc_host"] = input(f"Masukkan IP KDC [{state['kdc_host']}]: ").strip() or state["kdc_host"]
                state["bob_host"] = input(f"Masukkan IP Bob [{state['bob_host']}]: ").strip() or state["bob_host"]
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
