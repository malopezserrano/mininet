#!/usr/bin/python


import subprocess
import os

from time import sleep
"""from mininet.node import  RemoteController, OVSKernelSwitch"""
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.link import TCLink
"""from mn_wifi.node import OVSKernelAP"""
from mn_wifi.cli import CLI_wifi
from mn_wifi.net import Mininet_wifi

"""h1----ap1----sta1"""

def topology():
    "Create a network."
    net = Mininet_wifi( controller=RemoteController, link=TCLink )

    info("*** Creating nodes\n")
    ap1 = net.addAccessPoint( 'ap1', ssid="ssid_1", mode="g", channel="5" )
    sta1 = net.addStation( 'sta1', ip="192.168.0.100/24" )
    h1 = net.addHost( 'h1', ip="192.168.0.1/24", mac="00:00:00:00:00:04" )
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653 )

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Adding Link\n")
    net.addLink(h1, ap1, bw=1000000000)
    net.addLink(ap1, sta1)

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start( [c0] )

    sleep(5)

    """drop tcp traffic to 80 port"""
    ap1.cmd("ovs-ofctl add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=800,nw_dst=192.168.0.1,actions=drop")

    """Create Queues"""

    ap1.cmd("ovs-vsctl -- set port ap1-eth2 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=1000000000 queues:1=@q1 queues:2=@q2 queues:3=@q3 queues:4=@q4 -- --id=@q1 create queue other-config:min-rate=10000 other-config:max-rate=20000 -- --id=@q2 create queue other-config:min-rate=200000 other-config:max-rate=300000 -- --id=@q3 create queue other-config:min-rate=3000000 other-config:max-rate=4000000 -- --id=@q4 create queue other-config:min-rate=40000000 other-config:max-rate=50000000")

    ap1.cmd("ovs-ofctl add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=80,nw_dst=192.168.0.1,actions=set_queue:1,normal")
    ap1.cmd("ovs-ofctl add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_proto=17,tp_dst=3001,nw_dst=192.168.0.1,actions=set_queue:2,normal")
    ap1.cmd("ovs-ofctl add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=4001,nw_dst=192.168.0.1,actions=set_queue:3,normal")
    ap1.cmd("ovs-ofctl add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=5001,nw_dst=192.168.0.1,actions=set_queue:4,normal")


    info("*** Running CLI\n")
    CLI_wifi( net )

    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
