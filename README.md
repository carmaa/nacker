Nacker
======

Nacker is a tool to bypass 802.1x Network Access Control (NAC) on a wired LAN. Nacker will help you locate any non-802.1x configurable hosts on your subnet, and spoof their MAC address so that you appear authenticated to the switch.

The name "Nacker" is a derived from the word "knocker" and NAC; coincidentally combining them equals the slang for [Irish gypsy][1]. D'ya like dags?

I,portant note
--------------
This tool is currently in a non-working state.

Introduction
------------

Increasingly often during internal pentests in modern environments, you will find that you'll not be able to just plug into the nearest Ethernet port to get access to the enterprise network. Most of the times this is because the network is protected by some sort of Network Access Control (NAC) functionality, wich essentially forces hosts on the network to authenticate to the switch, often using the 802.1x protocol with a backend authentication server, typically RADIUS.

There are several ways to circumvent this problem, for example by using an Pwnie Plug or Marvin.

However, there are often far easier ways to bypass NAC. As anyone that has been working in IT can tell you; even in brand new environments there will be legacy hosts on the network (think printers, video conferencing gear, monitoring boxes, etc.) that doesn't support 802.1x. The standard way IT solves this, is to create an exception for said hosts.

So if we can figure out which hosts that are exempt authentication and mimic them on the network, we'll be exempt as well. Sweet!

Nacker automates the procedure of finding exempt hosts on the local LAN, and mimicing them. It is a very simple and dumb tool, but it has the advantage of not requiring plugging in dedicated hardware between an authenticated host and the switch, which both Pwnie Plug and Marvin requires you to do. Just plug in, run Nacker, and with a little bit of luck you'll be authenticated on the network and able to enjoy network access as usual.

[1]: http://www.urbandictionary.com/define.php?term=nacker
