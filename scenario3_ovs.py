#!/usr/bin/python


import subprocess
import os

from time import sleep
from mininet.node import  RemoteController, OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mn_wifi.node import OVSKernelAP
from mn_wifi.cli import CLI_wifi
from mn_wifi.net import Mininet_wifi

"""   sta1 sta2
        |   |
     ssid1 ssid2
         \ /
         ap1----s1----h1
         / \ 
     ssid3 ssid4
        |   |
      sta3 sta4     """

def topology():
    "Create a network."
    net = Mininet_wifi( controller=RemoteController, link=TCLink )

    info("*** Creating nodes\n")
    sta1 = net.addStation( 'sta1', ip="192.168.0.100/24" )
    sta2 = net.addStation( 'sta2', ip="192.168.0.101/24" )
    sta3 = net.addStation( 'sta3', ip="192.168.0.102/24" )
    sta4 = net.addStation( 'sta4', ip="192.168.0.103/24" )
    ap1 = net.addAccessPoint('ap1', vssids=4, ssid='ssid,ssid1,ssid2,ssid3,ssid4', mode="g")
    s1 = net.addSwitch( 's1' )
    h1 = net.addHost( 'h1', ip="192.168.0.1/24", mac="00:00:00:00:00:10" )
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653 )

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Adding Link\n")
    net.addLink(h1, s1, bw=1000000000)
    net.addLink(ap1, s1, bw=1000000000)

    info("*** Starting network\n")
    net.build()
    c1.start()
    s1.start( [c1] )
    ap1.start( [c1] )

    sleep(5)

    sta1.cmd('iw dev %s connect %s %s'
             % (sta1.params['wlan'][0], ap1.params['ssid'][1],
                ap1.params['mac'][1]))
    sta2.cmd('iw dev %s connect %s %s'
             % (sta2.params['wlan'][0], ap1.params['ssid'][2],
                ap1.params['mac'][2]))
    sta3.cmd('iw dev %s connect %s %s'
             % (sta3.params['wlan'][0], ap1.params['ssid'][3],
                ap1.params['mac'][3]))
    sta4.cmd('iw dev %s connect %s %s'
             % (sta4.params['wlan'][0], ap1.params['ssid'][4],
                ap1.params['mac'][4]))


    """sta1.cmd("ifconfig sta1-wlan1 192.168.1.100/24 up")"""
    """h1.cmd("ifconfig h4-eth0:0 192.168.1.1/24")"""

    ap1.cmd("ovs-ofctl -O OpenFlow11 add-flow ap1 priority=65535,ip,dl_type=0x0800,in_port=2,nw_dst=192.168.0.1,actions=push_vlan:0x8100,set_field:2-\>vlan_vid,output:6")
    ap1.cmd("ovs-ofctl -O OpenFlow11 add-flow ap1 priority=65535,ip,dl_type=0x0800,in_port=3,nw_dst=192.168.0.1,actions=push_vlan:0x8100,set_field:3-\>vlan_vid,output:6")
    ap1.cmd("ovs-ofctl -O OpenFlow11 add-flow ap1 priority=65535,ip,dl_type=0x0800,in_port=4,nw_dst=192.168.0.1,actions=push_vlan:0x8100,set_field:4-\>vlan_vid,output:6")
    ap1.cmd("ovs-ofctl -O OpenFlow11 add-flow ap1 priority=65535,ip,dl_type=0x0800,in_port=5,nw_dst=192.168.0.1,actions=push_vlan:0x8100,set_field:5-\>vlan_vid,output:6")

    """Create Queues"""
    s1.cmd("ovs-vsctl -- set port s1-eth1 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=1000000000 queues:1=@q1 queues:2=@q2 queues:3=@q3 queues:4=@q4 -- --id=@q1 create queue other-config:min-rate=10000 other-config:max-rate=20000 -- --id=@q2 create queue other-config:min-rate=200000 other-config:max-rate=300000 -- --id=@q3 create queue other-config:min-rate=3000000 other-config:max-rate=4000000 -- --id=@q4 create queue other-config:min-rate=40000000 other-config:max-rate=50000000")

    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=2,actions=pop_vlan,set_queue:1,normal")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=3,actions=pop_vlan,set_queue:2,normal")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=4,actions=pop_vlan,set_queue:3,normal")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=5,actions=pop_vlan,set_queue:4,normal")
    
    """sh ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=2,actions=pop_vlan,set_queue:1,normal"""

    info("*** Running CLI\n")
    CLI_wifi( net )

    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()
