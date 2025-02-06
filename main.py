from scapy.all import *


class App:
    def __init__(self):
        self.packets = rdpcap("./resources/example_export.pcapng")

    def get_packets(self) -> PacketList:
        return self.packets


def main():
    app = App()
    packets = app.get_packets()
    for packet in packets:
        print(packet)


if __name__ == '__main__':
    main()
