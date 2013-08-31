'''
Nacker is a tool to circumvent 802.1x Network Access Control (NAC) on
a wired LAN.

Copyright (C) 2013  Carsten Maartmann-Moe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Created on Aug 29, 2013

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''

from scapy.all import srp,Ether,ARP,conf
import sys
import netaddr

def pingsweep(network):
    conf.verb=0
    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),timeout=2)

    for snd,rcv in ans:
        mac = netaddr.EUI(rcv[Ether].src)
        ip = rcv[ARP].psrc
        print(mac)
        print(ip)
        print(mac.oui.registration().org)
        print('')