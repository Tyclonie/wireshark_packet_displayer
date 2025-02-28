from scapy.all import *
from scapy.layers.inet import IP
import requests
import json


class App:
    def __init__(self):
        self.packets = rdpcap("./resources/tesdt23.pcapng")
        self.ip_addresses = []
        self.ip_addresses_data = {}

    def add_ip_addresses(self):
        for packet in self.packets:
            if (packet.haslayer(IP)):
                if packet[IP].src not in self.ip_addresses:
                    self.ip_addresses.append(packet[IP].src)
                if packet[IP].dst not in self.ip_addresses:
                    self.ip_addresses.append(packet[IP].src)

    def fetch_ip_information(self):
        iterations = len(self.ip_addresses) // 100
        for iteration in range(0, iterations - 1):
            ip_addresses_batch = []
            for ip_address in self.ip_addresses[iteration * 100:(iteration + 1) * 100]:
                ip_addresses_batch.append(ip_address)
            response = requests.post("http://ip-api.com/batch?fields=18548473", data=json.dumps(ip_addresses_batch)).json()
            for data_set in response:
                self.ip_addresses_data[data_set["query"]] = data_set
        ip_addresses_batch = []
        for ip_address in self.ip_addresses[(iterations * 100) + 1:]:
            ip_addresses_batch.append(ip_address)
        response = requests.post("http://ip-api.com/batch?fields=18556665", data=json.dumps(ip_addresses_batch)).json()
        for data_set in response:
            self.ip_addresses_data[data_set["query"]] = data_set

    def get_ip_information(self) -> dict:
        return self.ip_addresses_data



def main():
    app = App()
    app.add_ip_addresses()
    app.fetch_ip_information()
    print(app.get_ip_information())



                


if __name__ == '__main__':
    main()
