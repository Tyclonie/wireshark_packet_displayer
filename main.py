import socket
from scapy.all import *
from scapy.layers.inet import IP
import requests
import json
import customtkinter
import tkinter
from PIL import Image, ImageTk

class GUI(customtkinter.CTk):
    def __init__(self):
        super().__init__()

    def load(self, ip_address_data, ip_map, local_information):
        self.geometry("800x406")
        image = Image.open("resources/map_of_earth.png")
        background_image = ImageTk.PhotoImage(image)
        canvas = customtkinter.CTkCanvas(self, width=800, height=406)
        canvas.pack()
        canvas.create_image(0, 0, image=background_image, anchor=tkinter.NW)
        for ip_set in ip_map:
            try:
                if ip_set[0] == local_information[1]:
                    src_lon, src_lat = local_information[0]['lon'], local_information[0]['lat']
                else:
                    src_lon, src_lat = ip_address_data[ip_set[0]]['lon'], ip_address_data[ip_set[0]]['lat']
                if ip_set[1] == local_information[1]:
                    dst_lon, dst_lat = local_information[0]['lon'], local_information[0]['lat']
                else:
                    dst_lon, dst_lat = ip_address_data[ip_set[1]]['lon'], ip_address_data[ip_set[0]]['lat']
                start_values = (400 + (src_lon * (20/9)) if src_lon > 0 else 400 - (-src_lon * (20/9)),
                                203 + (-src_lat * (203/90)) if src_lat < 0 else 203 - (src_lat * (203/90)))
                end_values = (400 + (dst_lon * (20 / 9)) if dst_lon > 0 else 400 - (-dst_lon * (20 / 9)),
                              203 + (-dst_lat * (203 / 90)) if dst_lat < 0 else 203 - (dst_lat * (203 / 90)))
                canvas.create_line(start_values[0], start_values[1], end_values[0], end_values[1], fill="purple",
                                   width=3)
            except KeyError:
                continue
        self.mainloop()

class App:
    def __init__(self):
        self.user_information = None
        self.local_ip = None
        self.fail_count = None
        self.packets = rdpcap("resources/example_export2.pcapng")
        self.ip_addresses = []
        self.ip_addresses_data = {}
        self.ip_map = []

    def add_ip_addresses(self):
        for packet in self.packets:
            if (packet.haslayer(IP)):
                if packet[IP].src not in self.ip_addresses:
                    self.ip_addresses.append(packet[IP].src)
                if packet[IP].dst not in self.ip_addresses:
                    self.ip_addresses.append(packet[IP].dst)
                if (packet[IP].src, packet[IP].dst) not in self.ip_map:
                    self.ip_map.append((packet[IP].src, packet[IP].dst))

    def fetch_ip_information(self):
        self.fail_count = 0
        iterations = len(self.ip_addresses) // 100
        for iteration in range(0, iterations - 1):
            ip_addresses_batch = []
            for ip_address in self.ip_addresses[iteration * 100:(iteration + 1) * 100]:
                ip_addresses_batch.append(ip_address)
            response = requests.post("http://ip-api.com/batch?fields=18548473", data=json.dumps(ip_addresses_batch)).json()
            for data_set in response:
                if "lat" in data_set and "lon" in data_set and "query" in data_set:
                    self.ip_addresses_data[data_set["query"]] = data_set
                else:
                    self.fail_count += 1
        ip_addresses_batch = []
        for ip_address in self.ip_addresses[(iterations * 100) + 1:]:
            ip_addresses_batch.append(ip_address)
        response = requests.post("http://ip-api.com/batch?fields=18556665", data=json.dumps(ip_addresses_batch)).json()
        for data_set in response:
            if "lat" in data_set and "lon" in data_set and "query" in data_set:
                self.ip_addresses_data[data_set["query"]] = data_set
            else:
                self.fail_count += 1

    def get_ip_information(self) -> dict:
        return self.ip_addresses_data

    def get_ip_map(self) -> list:
        return self.ip_map

    def get_local_ip_information(self) -> tuple:
        self.user_information = requests.get("http://ip-api.com/json/?fields=18548473").json()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            self.local_ip = s.getsockname()[0]
        except Exception:
            self.local_ip = '127.0.0.1'
        finally:
            s.close()
            return self.user_information, self.local_ip



def main():
    app = App()
    app.add_ip_addresses()
    app.fetch_ip_information()
    gui = GUI()
    gui.load(app.get_ip_information(), app.get_ip_map(), app.get_local_ip_information())



                


if __name__ == '__main__':
    main()
