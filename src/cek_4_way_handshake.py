# pyshark
# scapy
# wireshark
# tspark
import pyshark

# Memasukkan file capture (.cap)
file_capture = input("[#] Masukkan nama file capture (.cap): ")

cap = pyshark.FileCapture(file_capture, display_filter="eapol")

paket_handshake = []

for paket in cap:
    if "EAPOL" in paket:
        paket_handshake.append(paket)
        
if len(paket_handshake) == 4:
    print("[+] 4-way handshake ditemukan.")
else:
    print("[-] 4-way handshake tidak ditemukan.")
