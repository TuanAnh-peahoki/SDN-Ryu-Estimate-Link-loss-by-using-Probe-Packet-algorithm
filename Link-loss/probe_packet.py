import time
from scapy.all import Ether,IP,UDP,sendp
import time
import sys

pkt_start = Ether(dst="FF:FF:FF:FF:FF:FF")/IP(dst="255.255.255.255")/UDP(dport=65534) #Probe packet
pkt_stop  = Ether(dst="FF:FF:FF:FF:FF:FF")/IP(dst="255.255.255.255")/UDP(dport=65535) #Notify packet to let OFC know all probe packets was sent

while 1:
    # Send 1 Probe packet. It will come to OFC via PacketIn message.
    # OFC will not forward this packet. OFC applies the flow entries for the probe packets
    #print("\nSend 1 probe packet and wait 1 second")
    sendp(pkt_start, verbose=False)

    #Wait for all OFSs receive the flow entries
    time.sleep(1)

    # Send 10,000 probe packets in 1 second
    #print("Send 1,0000 probe packets in 1 second")
    sendp(pkt_start, count=10000, inter=1.0/10000, verbose=False) 
    
    # Wail for all probe packets receive at destinations
    time.sleep(1)

    # Send Notify packet to tell OFC start estimation
    #print("Send 1 Notify packets")
    sendp(pkt_stop, verbose=False)   
    
    # Wait 57 seconds and repeat
    for remaining in range(57, 0, -1):
        sys.stdout.write("\r")
        _str = ["=" for sp in range(10-(remaining+9)%10)]
        sys.stdout.write("{:2d} seconds remaining {}>          ".format(remaining, "".join(_str)))
        sys.stdout.flush()
        time.sleep(1)