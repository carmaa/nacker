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
from scapy.all import *

def ping(ip):
    TIMEOUT = 2
    conf.verb = 0
    print('Pinging {0}'.format(ip))
    packet = IP(dst=ip, ttl=20)/ICMP()
    reply = sr1(packet, timeout=TIMEOUT)
    if not (reply is None):
         print reply.src, "is online"
         return(True)
    else:
         print "Timeout waiting for %s" % packet[IP].src
         return(False)