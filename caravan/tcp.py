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
import threading
import Queue
import time
from scapy.all import *

topports = [80,     # http
            23,     # telnet
            22,     # ssh
            443,    # https
            3389,   # ms-term-serv
            445,    # microsoft-ds
            139,    # netbios-ssn
            21,     # ftp
            135,    # msrpc
            25]     # smtp

def synscan(network):
    pass

class ScannerThread(threading.Thread):
    def __init__(self, portlist, tid):
        threading.Thread.__init__(self)
        self.portlist = portlist
        self.tid = tid


    def run(self):
        if scanner.verbose:
            print "started Thread", self.tid

        # ports scanned by this thread
        totalPorts = 0

        while True:
            port = 0
            try:
                port = self.portlist.get(timeout=1)
            except Queue.Empty:
                return

            response = sr1(IP(dst=scanner.target)/TCP(dport=port, flags="S"),verbose=False, timeout=0.2)

            if response:
                # flags is 18 if SYN,ACK received
                # i.e port is open
                if response[TCP].flags == 18:
                    print("{0}\tOPEN".format(port))

            totalPorts += 1
            self.portlist.task_done()
        # end while block

        #if cfg.verbose:
        #    print "Thread", self.tid, "scanned", totalPorts, "ports"