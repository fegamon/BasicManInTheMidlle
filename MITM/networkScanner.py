import scapy.all as scapy
import optparse

def getArguments():
    parser = optparse.OptionParser()
    parser.add_option('-g', '--gtw', dest='gtw', help='Gateway (router) ip. You have to specify the network interface (e.g 127.0.0.1/24)')
    (options, arguments) = parser.parse_args()
    return options

# Obtain connected devices to a given ip address 
def scan(ip):
    arpRequest = scapy.ARP(pdst= ip)
    broadcast = scapy.Ether(dst= 'ff:ff:ff:ff:ff:ff')
    scapy.arping(ip)
    print('')

    # Ask for every device connected to given ip addres and devices reply with its ip and mac address
    arpRequestBroadcast = broadcast/arpRequest
    answeredList = scapy.srp(arpRequestBroadcast, timeout= 1, verbose = False)[0]

    # Create a dictionary to store ip and mac address of every found devices and save into a list
    clientsList = []
    for i in answeredList:
        clientDict = {'ip': i[1].psrc, 'mac': i[1].hwsrc}
        clientsList.append(clientDict)
    return clientsList

def printResult(resultsList):
    print('Ip \t\t\tMAC Adress\n-----------------------------------------------')
    for i in resultsList:
        print(i['ip'] + '\t\t' + i['mac'])


options = getArguments()
results = scan(options.gtw)
printResult(results)
