# pyshark
# scapy
# wireshark
# tspark
import os
import sys
import pyshark
import platform
import subprocess

# Cek sistem operasi
cek_os = platform.system()

if cek_os == "Linux":
    pass
else:
    print("[-] Sistem operasi Anda tidak mendukung untuk menjalankan program ini.")
    sys.exit(1)

# Cek apakah Tsark sudah terinstal atau belum
perintah_cek_tshark = f"tsark --version"

try:
    cek_tshark = subprocess.run(perintah_cek_tshark, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if cek_tshark.returncode == 0:
        pass
    else:
        print("[-] Tsark belum terinstal.")
        print("[-] Instal dengan menggunakan perintah 'sudo apt-get install tshark'.")
        sys.exit(1)
except KeyboardInterrupt:
    print("[*] KeyboardInterrupt...")
    sys.exit(1)
except Exception as e:
    print(f"[-] Terjadi kesalahan yang tidak terduga: {e}")


# Memasukkan file capture (.cap)
while True:
    file_capture = input("[#] Masukkan nama file capture (.cap): ")
    
    if os.path.isfile(file_capture):
        print("[+] File capture ditemukan.")
        
        cap = pyshark.FileCapture(file_capture, display_filter="eapol")

        # List untuk menyimpan paket handshake
        paket_handshake = []

        for paket in cap:
            if "EAPOL" in paket:
                # Menambahkan paket EAPOL ke dalam list
                paket_handshake.append(paket)
        
        if len(paket_handshake) >= 4:
            print("[+] 4-way handshake ditemukan.")
            sys.exit(0)
        else:
            print("[-] 4-way handshake tidak ditemukan.")
            break
    else:
        print("[-] File capture tidak ditemukan.")
        continue
