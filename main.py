from scapy.all import *
from scapy.layers.inet import IP
import requests
import json
import customtkinter
import tkinter
from PIL import Image, ImageTk
from customtkinter import filedialog

class GUI(customtkinter.CTk):
    def __init__(self):
        super().__init__()

    def load(self, ip_address_data, ip_map, local_information):
        self.geometry("1920x1080")
        image = Image.open("resources/map_of_earth.png")
        background_image = ImageTk.PhotoImage(image)
        main_frame = customtkinter.CTkScrollableFrame(self, 1920, 1080)
        main_frame.pack(fill="both", expand=True)
        canvas = customtkinter.CTkCanvas(main_frame, width=1920, height=960)
        canvas.pack(side="top", fill="both", expand=True)
        canvas.create_image(0, 0, image=background_image, anchor=tkinter.NW)
        packet_frame = customtkinter.CTkScrollableFrame(main_frame, 1920)
        packet_frame.pack(side="bottom", fill="x", expand=False)
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
                start_values = (960 + (src_lon * (16/3)) if src_lon > 0 else 960 - (-src_lon * (16/3)),
                                480 + (-src_lat * (16/3)) if src_lat < 0 else 480 - (src_lat * (16/3)))
                end_values = (960 + (dst_lon * (16/3)) if dst_lon > 0 else 960 - (-dst_lon * (16/3)),
                              480 + (-dst_lat * (16/3)) if dst_lat < 0 else 480 - (dst_lat * (16/3)))
                canvas.create_line(start_values[0], start_values[1], end_values[0], end_values[1], fill="orange",
                                   width=1)
                label = customtkinter.CTkLabel(packet_frame,
                                               text=f"{ip_set[0]} -> "
                                                    f"Country: {ip_address_data[ip_set[0]]['country']} "
                                                    f"City: {ip_address_data[ip_set[0]]['city']} "
                                                    f"Continent: {ip_address_data[ip_set[0]]['continent']} "
                                                    f"Region: {ip_address_data[ip_set[0]]['regionName']} "
                                                    f"District: {ip_address_data[ip_set[0]]['district']} "
                                                    f"Zip: {ip_address_data[ip_set[0]]['zip']} "
                                                    f"ISP: {ip_address_data[ip_set[0]]['isp']} "
                                                    f"Organization: {ip_address_data[ip_set[0]]['org']} "
                                                    f"Mobile: {ip_address_data[ip_set[0]]['mobile']} "
                                                    f"Proxy: {ip_address_data[ip_set[0]]['proxy']} "
                                                    f"Hosting: {ip_address_data[ip_set[0]]['hosting']} ")
                label.pack(anchor="w")
            except KeyError:
                continue
        packet_frame.update_idletasks()
        self.mainloop()

class App:
    def __init__(self, packet_file_path):
        self.user_information = None
        self.local_ip = None
        self.fail_count = None
        self.packets = rdpcap(packet_file_path)
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
    app = App(filedialog.askopenfilename(filetypes=[("Pcap-NG Packet Capture File", "*.pcapng")]))
    app.add_ip_addresses()
    app.fetch_ip_information()
    gui = GUI()
    gui.load(app.get_ip_information(), app.get_ip_map(), app.get_local_ip_information())



                


if __name__ == '__main__':
    main()
