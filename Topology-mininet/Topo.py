from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink, TCIntf
from mininet.util import dumpNodeConnections,dumpNetConnections, dumpPorts
from mininet.cli import CLI
from mininet.log import setLogLevel
from ryu.lib import hub
from sys import argv
import argparse
#Link parameter
linkopts1 = dict(bw=100,  delay='1ms') #Host link
#linkopts2 = [dict(loss=2, bw=1000, delay='3ms'),dict(bw=1000, delay='3ms'),dict(loss=5, bw=1000, delay='3ms')] #Switch Link
linkopts2 = dict(loss=10, bw=1000, delay='3ms') #Switch Link, link loss=10%
##########################################################################################
#Custom Topology
class MyTopo(Topo):
    def __init__(self, noOFS=6, noHost=1):
        Topo.__init__(self)
        noOFS = noOFS
        noHost= noHost
        Host = []
        OFS  = []
        #Add Host to topology
        for i in range(noOFS*noHost):
            Host.append(self.addHost("h{}".format(i+1), ip="10.0.{}.1".format(i+1)))
        #Add Switch to topology
        for i in range(noOFS):
            OFS.append(self.addSwitch("s{}".format(i+1)))
        #Link Host to Switch
        for i in range(noOFS):
            for j in range(noHost):
                self.addLink(Host[i*noHost+j],OFS[i],**linkopts1)
        #Link OFSs. E.g., ring topology
        for i in range(noOFS-1): # "-1" is Linear topology
            if i < 3:
                currOFS = OFS[i]
                nextOFS = OFS[(i+1) % noOFS]
                if currOFS != nextOFS:
                    self.addLink(currOFS,nextOFS,**linkopts2)
            else:
                self.addLink(OFS[4], OFS[1],**linkopts2)
                self.addLink(OFS[5],OFS[4],**linkopts2)
                self.addLink(OFS[5],OFS[2],**linkopts2)
                break
##########################################################################################
#Main function:
def main(*args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--NumOFS',  type=int, action="store", default=6)
    parser.add_argument('--NumHost', type=int, action="store", default=1)
    args = parser.parse_args()
    NumOFS = args.NumOFS
    NumHost= args.NumHost
    mytopo = MyTopo(NumOFS,NumHost)
    net  = Mininet(topo=mytopo, switch=OVSKernelSwitch,
                   controller=RemoteController("c0", ip="127.0.0.1"),
                   autoSetMacs=True, link=TCLink)
    print("---------------------- NETS ------------------------")
    dumpNetConnections(net)
    print("----------------------------------------------------\n")
    #Run default command from hosts. E.g., Disable IPv6:
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")
    #Start simulation --------------------------
    net.start()
    #Ex: h1 ping h4
    h1 = net.getNodeByName("h1")
    CLI(net)
    #Stop simulation ----------------------------
    net.stop()
##########################################################################################
#Default run simulation
if __name__ == "__main__":
    setLogLevel("info")
    main()