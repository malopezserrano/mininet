#!/usr/bin/python


import subprocess
import os

from time import sleep
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mn_wifi.cli import CLI_wifi
from mn_wifi.net import Mininet_wifi

"""
sta1 sta2          h1
  \   /           /
  ssid1---ap1---s1---gw---h3
  /   \           \
sta1 sta2          h2

vlan2:sta2
vlan3:sta3
vlan4:sta1,sta2
"""

def topology():
    "Create a network."
    net = Mininet_wifi( controller=RemoteController, link=TCLink )

    info("*** Creating nodes\n")
    sta1 = net.addStation( 'sta1', wlans=1, mac='00:00:00:00:00:00', ip="192.168.0.100/24" )
    sta2 = net.addStation( 'sta2', wlans=1, mac='00:00:00:00:00:01', ip="192.168.0.101/24" )
    sta3 = net.addStation( 'sta3', wlans=1, mac='00:00:00:00:00:02', ip="192.168.0.102/24" )
    sta4 = net.addStation( 'sta4', wlans=1, mac='00:00:00:00:00:03', ip="192.168.0.103/24" )
    ap1 = net.addAccessPoint( 'ap1', ssid="ssid_1", mode="g", channel="1" )
    s1 = net.addSwitch( 's1' )
    h1 = net.addHost( 'h1', ip="192.168.0.200/24", mac="00:00:00:00:01:00" )
    h2 = net.addHost( 'h2', ip="192.168.0.201/24", mac="00:00:00:00:01:01" )
    r1 = net.addHost( 'r1')
    h3 = net.addHost( 'h3', ip="100.100.100.100/24", mac="00:00:00:00:01:02" )
    c1 = net.addController('c1', controller=RemoteController, ip='127.0.0.1', port=6653 )

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Adding Link\n")
    net.addLink(sta1, ap1)
    net.addLink(sta2, ap1)
    net.addLink(sta3, ap1)
    net.addLink(sta4, ap1)
    net.addLink(ap1, s1, bw=1000000000)
    net.addLink(s1, h1, bw=1000000000)
    net.addLink(s1, h2, bw=1000000000)
    net.addLink(s1, r1, bw=1000000000)
    net.addLink(r1, h3, bw=1000000000)

    info("*** Starting network\n")
    net.build()
    c1.start()
    ap1.start( [c1] )
    s1.start( [c1] )

    sleep(5)

    r1.cmd("ifconfig r1-eth0 0")
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ifconfig r1-eth0 hw ether 00:00:00:00:02:00")
    r1.cmd("ifconfig r1-eth1 hw ether 00:00:00:00:02:01")
    r1.cmd("ip addr add 192.168.0.1/24 brd + dev r1-eth0")
    r1.cmd("ip addr add 100.100.100.1/24 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    sta1.cmd("ip route add default via 192.168.0.1")
    sta2.cmd("ip route add default via 192.168.0.1")
    sta3.cmd("ip route add default via 192.168.0.1")
    sta4.cmd("ip route add default via 192.168.0.1")
    h3.cmd("ip route add default via 100.100.100.1")
    s1.cmd("ovs-ofctl add-flow s1 priority=1,arp,actions=flood")

    """VLAN TAGGING"""
    ap1.cmd("ovs-ofctl -O OpenFlow11 add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_src=192.168.0.100,actions=push_vlan:0x8100,set_field:4-\>vlan_vid,output:2")
    ap1.cmd("ovs-ofctl -O OpenFlow11 add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_src=192.168.0.101,actions=push_vlan:0x8100,set_field:2-\>vlan_vid,output:2")
    ap1.cmd("ovs-ofctl -O OpenFlow11 add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_src=192.168.0.102,actions=push_vlan:0x8100,set_field:3-\>vlan_vid,output:2")
    ap1.cmd("ovs-ofctl -O OpenFlow11 add-flow ap1 priority=65535,ip,dl_type=0x0800,nw_src=192.168.0.103,actions=push_vlan:0x8100,set_field:4-\>vlan_vid,output:2")

    """VLAN BASED ROUTING"""
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=2,nw_dst=192.168.0.200,actions=pop_vlan,output:2")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=3,nw_dst=192.168.0.201,actions=pop_vlan,output:3")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=2,dl_dst=00:00:00:00:02:00,actions=pop_vlan,goto_table:1")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=3,dl_dst=00:00:00:00:02:00,actions=pop_vlan,goto_table:2")
    s1.cmd("ovs-ofctl add-flow s1 priority=65535,ip,dl_vlan=4,dl_dst=00:00:00:00:02:00,actions=pop_vlan,goto_table:3")

    """ACCESS CONTROL"""
    """drop traffic to h1 and h2"""
    s1.cmd("ovs-ofctl add-flow s1 priority=10000,ip,dl_type=0x0800,nw_dst=192.168.0.200,actions=drop")
    s1.cmd("ovs-ofctl add-flow s1 priority=10000,ip,dl_type=0x0800,nw_dst=192.168.0.201,actions=drop")

    """OVS S1 QUEUES"""
    s1.cmd("ovs-vsctl -- set port s1-eth4 qos=@newqos -- --id=@newqos create qos type=linux-htb other-config:max-rate=1000000000 queues:1=@q1 queues:2=@q2 queues:3=@q3 queues:4=@q4 queues:5=@q5 queues:6=@q6 queues:7=@q7 queues:8=@q8 queues:9=@q9 -- --id=@q1 create queue other-config:min-rate=1000000 other-config:max-rate=1000000 -- --id=@q2 create queue other-config:min-rate=2000000 other-config:max-rate=2000000 -- --id=@q3 create queue other-config:min-rate=4000000 other-config:max-rate=4000000 -- --id=@q4 create queue other-config:min-rate=10000000 other-config:max-rate=10000000 -- --id=@q5 create queue other-config:min-rate=20000000 other-config:max-rate=20000000 -- --id=@q6 create queue other-config:min-rate=40000000 other-config:max-rate=40000000 -- --id=@q7 create queue other-config:min-rate=100000000 other-config:max-rate=100000000 -- --id=@q8 create queue other-config:min-rate=200000000 other-config:max-rate=200000000 -- --id=@q9 create queue other-config:min-rate=400000000 other-config:max-rate=400000000")

    """QOS SELECTION VLAN2"""
    s1.cmd("ovs-ofctl add-flow s1 table=1,priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=80,nw_dst=100.100.100.100,actions=set_queue:7,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=1,priority=65535,ip,dl_type=0x0800,nw_proto=17,tp_dst=3001,nw_dst=100.100.100.100,actions=set_queue:8,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=1,priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=5001,nw_dst=100.100.100.100,actions=set_queue:9,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=1,priority=1,ip,dl_dst=00:00:00:00:02:00,actions=normal")

    """QOS SELECTION VLAN3"""
    s1.cmd("ovs-ofctl add-flow s1 table=2,priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=80,nw_dst=100.100.100.100,actions=set_queue:4,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=2,priority=65535,ip,dl_type=0x0800,nw_proto=17,tp_dst=3001,nw_dst=100.100.100.100,actions=set_queue:5,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=2,priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=5001,nw_dst=100.100.100.100,actions=set_queue:6,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=2,priority=1,ip,dl_dst=00:00:00:00:02:00,actions=normal")

    """QOS SELECTION VLAN4"""
    s1.cmd("ovs-ofctl add-flow s1 table=3,priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=80,nw_dst=100.100.100.100,actions=set_queue:1,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=3,priority=65535,ip,dl_type=0x0800,nw_proto=17,tp_dst=3001,nw_dst=100.100.100.100,actions=set_queue:2,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=3,priority=65535,ip,dl_type=0x0800,nw_proto=6,tp_dst=5001,nw_dst=100.100.100.100,actions=set_queue:3,normal")
    s1.cmd("ovs-ofctl add-flow s1 table=3,priority=1,ip,dl_dst=00:00:00:00:02:00,actions=normal")

    info("*** Running CLI\n")
    CLI_wifi( net )

    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()

