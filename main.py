from scapy.all import *

def sniff_handshake(packet):
    # Проверьте, является ли пакет EAPOL пакетом (хендшейк WPA)
    if packet.haslayer(EAPOL):
        # Сохраните пакет в файл .pcap для последующего анализа
        wrpcap("handshake.pcap", packet, append=True)
        print("Captured handshake packet")

def main():
    interface = "wlan0mon"  # Ваш беспроводной интерфейс в режиме мониторинга
    print(f"Sniffing on interface {interface}")
    sniff(iface=interface, prn=sniff_handshake, store=0)

if __name__ == "__main__":
    main()
