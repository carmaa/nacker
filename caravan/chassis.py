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
import platform
import os
import subprocess
import netifaces
import netaddr
from subprocess import call

LOCALHOST_ADDR = ['127.0.0.1', 'localhost']

def is_linux():
    '''Verifies if the current platform is Linux'''
    os = platform.system()
    return os == 'Linux'

    
def is_osx():
    '''Verifies if the current platform is OS X'''
    os = platform.system()
    return os == 'Darwin'


def is_root():
    '''Verifies if the current user is root'''
    return os.getuid() & os.getgid() == 0


def interfaces():
    return [Interface(i) for i in netifaces.interfaces()]


def ip_interfaces():
    for iface in interfaces():
        if iface.has_ip() and iface.not_localhost():
            yield iface


class Interface():
    def __init__(self, name):
        self.name = name
        self.ifaddresses = None
        self.ip = None
        self.subnet = None
        self.netmask = None
        self.get_netaddr()
    
    def get_netaddr(self):
        try:
            self.ifaddresses = netifaces.ifaddresses(self.name)[netifaces.AF_INET][0]
            self.ip = netaddr.IPAddress(self.ifaddresses['addr'])
            self.netmask = netaddr.IPAddress(self.ifaddresses['netmask'])
            self.subnet = netaddr.IPNetwork('{0}/{1}'.format(self.ip, self.netmask))
        except KeyError:
            pass

    def has_ip(self):
        return self.ip

    def not_localhost(self):
        return str(self.ip) not in LOCALHOST_ADDR

    def spoof_mac(self, mac):
        if is_linux():
            '''Sets the new mac for the interface on a Linux system'''
            subprocess.check_call(['ifconfig','%s' % self.name, 'up'])
            subprocess.check_call(['ifconfig','%s' % self.name, 'hw', 'ether','%s' % mac])
        else:
            '''Sets the new mac for the interface on a Darwin system'''
            subprocess.check_call(['ifconfig','%s' % self.name,'up'])
            subprocess.check_call(['ifconfig','%s' % self.name,'lladdr','%s' % mac])
    
    def dhcp(self):
        if is_linux():
            call(['dhclient', self.name])
        else:
            call(['ipconfig', 'set', self.name, 'DHCP'])
        self.get_netaddr()
