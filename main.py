from scapy.all import *
from scapy.layers.inet import IP


class App:
    def __init__(self):
        self.packets = rdpcap("./resources/example_export.pcapng")

    def get_packets(self) -> PacketList:
        return self.packets


def main():
    app = App()
    packets = app.get_packets()
    for packet in packets:
        if(packet.haslayer(IP)):
            print(f"{packet[IP].src} -> {packet[IP].dst}")


if __name__ == '__main__':
    main()
