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

    def load(self, lat, lon):
        values = (400 + (lon * (20/9)) if lon > 0 else 400 - (-lon * (20/9)),
                  203 + (-lat * (203/90)) if lat < 0 else 203 - (lat * (203/90)))
        self.geometry("800x406")
        image = Image.open("resources/map_of_earth.png")
        background_image = ImageTk.PhotoImage(image)
        canvas = customtkinter.CTkCanvas(self, width=800, height=406)
        canvas.pack()
        canvas.create_image(0, 0, image=background_image, anchor=tkinter.NW)
        canvas.create_line(values[0], values[1], 800, 406, fill="purple", width=3)
        self.mainloop()

class App:
    def __init__(self):
        self.fail_count = None
        self.packets = rdpcap("resources/example_export2.pcapng")
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



def main():
    # app = App()
    # app.add_ip_addresses()
    # app.fetch_ip_information()
    # print(app.get_ip_information())
    # print(app.fail_count)
    gui = GUI()
    gui.load(72, -42)



                


if __name__ == '__main__':
    main()
