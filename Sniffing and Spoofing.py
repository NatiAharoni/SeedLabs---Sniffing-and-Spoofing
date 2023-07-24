"""
SEED LABS -  Sniffing and Spoofing Lab

Nati Aharoni
"""

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

# Task 1.1 - Sniffing Packets (and Filtering)

#   Filter only ICMP packets
def filter_icmp_packets():
    pkt = sniff(filter='icmp', prn=print_pkt)

#   Filter only TCP packets from specified IP address and port 23
def filter_tcp_packets_by_ip_and_port():
#   Setting the parameters for the filtering function
    pkt = sniff(filter='tcp and src host 10.0.2.9 and dst port 23', prn=print_pkt)


# Task 1.2 - Spoofing ICMP Packets    
def spoof_icmp_packet():
    a = IP()                    # Creating an IP packet
    a.dst = '10.0.2.8'          # Changing the parameters of IP packet
    a.src = RandIP()._fix()     # The RandIP()._fix() returrn a random valid IP address
    b = ICMP()                  # Creating an ICMP packet
    send(a/b)



#Task 1.3 - Traceroute
def traceroute(ip_address):
    inRoute = True
    i = 1
    print (f"traceroute for ip address {ip_address}")

    while (inRoute):
        a = IP (dst=ip_address, ttl=i)              # Create an IP packet with a ttl value match the number of the iteration
        pkt = (a/ICMP())                            
        response = sr1(pkt, timeout=7, verbose=0)   # sr1 sends the packet and recieves the response (into 'response')

        if response in None:
            print(str(i) + "request timed out")  
        elif response.type == 0:                    # ICMP response type of 0 means the message is Echo-Reply, therefore print the reply.
            print(str(i) + " " + response.src)
            inRoute = False
        else:                                       # The response was recieved but it's not an Echo-Reply, that means it's an intermediate router in the path.
            print(str(i) + " " + response.src)

        i += 1


#Task 1.4 - Sniffing and Spoopfing

def spoof_echo_reply(pkt):

    if (pkt[2].type == 8):              # ICMP response type of 0 means the message is Echo-Request
        src = pkt[1].src                # Extracting the data from the IP layer (= pkt[1])
        dst = pkt[1].dst
        seq = pkt[2].seq                # Extracting the data from the ICMP layer (= pkt[2])
        id = pkt[2].id
        load = pkt[3].load              # Extracting the data from the Raw layer (= pkt[3]) that contains the data section of the packet.

        # Assembling  and sending the response packet ( NOTION: the source and destination were switched)
        reply = IP(src = dst, dst = src) / ICMP (type=0, id=id, seq = seq) / load   
        send(reply, verbose=0)
        print('Echo-Reply was sent successfully!')
    
pkt = sniff (filter = 'icmp', prn = spoof_echo_reply) 

