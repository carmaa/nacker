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

import gudev

def devices():
    client = gudev.Client(['rfkill', 'net'])

    for dev in client.query_by_subsystem('net'):
        if dev.get_sysfs_attr_as_int("type") != 1: continue

        driver = dev.get_driver()
        if not driver:
            parent = dev.get_parent()
            if parent:
                driver = parent.get_driver()

        # available: wlan, wwan, wimax
        if dev.get_devtype() == 'wlan':
          type = 'Wireless'
        else:
           type = 'Wired'

        print type, dev.get_name(), driver, dev.get_sysfs_path()