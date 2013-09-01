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
from pprint import pprint

THREADS = 10

TOPPORTS = [80,     # http
            23,     # telnet
            22,     # ssh
            443,    # https
            3389,   # ms-term-serv
            445,    # microsoft-ds
            139,    # netbios-ssn
            21,     # ftp
            135,    # msrpc
            25]     # smtp

def synscan(target, portlist = Queue.Queue()):
    if portlist.empty():
        for p in TOPPORTS:
            portlist.put(p)

    open_ports = []

    started = time.time()
    print('SYN scan started at {0}'.format(time.ctime(started)))
    print(target)

    threads = []

    for i in range(1, THREADS + 1):
        #if cfg.verbose:
        print('Creating Thread {0}'.format(i))

        t = SYNScannerThread(target, portlist, i, open_ports)
        t.setDaemon(True)
        t.start()
        threads.append(t)

    portlist.join()

    for item in threads:
        item.join()

    finished = time.time()
    print('Finished scanning in {0:5f} seconds at {1} {2}'.format((finished-started), time.ctime(finished), time.tzname[0]))

    return open_ports

class SYNScannerThread(threading.Thread):
    def __init__(self, target, portlist, tid, open_ports):
        threading.Thread.__init__(self)
        self.target = target
        self.portlist = portlist
        self.tid = tid
        self.open_ports = open_ports


    def run(self):
        # ports scanned by this thread
        totalPorts = 0

        while True:
            port = 0
            try:
                port = self.portlist.get(timeout=1)
            except Queue.Empty:
                break

            response = sr1(IP(dst=self.target)/TCP(dport=port, flags="S"),verbose=False, timeout=0.2)

            if response:
                # flags is 18 if SYN,ACK received
                # i.e port is open
                if response[TCP].flags == 18:
                    self.open_ports.append(port)

            totalPorts += 1
            self.portlist.task_done()
        # end while block

        #if cfg.verbose:
        print('Thread {0} scanned {1} ports'.format(self.tid, totalPorts))
