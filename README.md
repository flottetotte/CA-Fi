CA-Fi
=====
Concurrent-Association-free Wireless Networking, allowing truly spontaneous and encounter-based wireless communication 
(currently only for ath9k wifi devices)

What is this ?
==============
CA-Fi is a communication scheme accounting for both network- and encounter-based ad-hoc networking as well as hybrid approaches. It allows devices to communicate without assocations and over the borders of their current association.
Therefore, small message - chunks are send on different channels in order to disseminate the messages as good as possible. CA-Fi contains multi-hop communication, a flexible addressing scheme that does not need a central management instance and message aggregation on intermediate devices also running the driver. 
The basis for all of this is the well known compat wireless driver (see: http://linuxwireless.org/).

This software comes without any form of warranty !

Requirements
============

- You need a Atheros wireless card that runs the ath9k driver, as by now, this is the only card supported
- In order to run the python scripts you need Python >= 2.7 (might work with older releases but not tested !)

Installation
============
- After checkout, change to the compat-wireless-ofi directory and run ./scripts/driver-select ath9k
- Run make as root (otherwise you might get permission errors)
- In the folder you will find a little helper script called doit.sh, after make is complete, run this
  script also as root. This will install the driver, unload the old module and set up the wireless interface.

Usage
=====
- After installation you can try out the basic features of CA-Fi with the small python scripts provided in the folder netlink, which are explained in the following:

min_delegator.py
----------------
The minimal delegator allows to subscribe to an identifier in order to be adressable by other CA-Fi devices. Therefore, start the delegator with "python delegator.py", type :"rID you want to add" (without the quotes) and hit "Enter". "r" stands for register a new identifier. To delete a subscription, just type "dID you want to delete" and hit "Enter".
Typing "q" and hitting "Enter" quits the delegator after a few seconds. Please note, that the subscribed identifiers stay set in the driver.

Once subscribed to an iddentifier, a device is now capable of receiving messages. To test that, start another CA-Fi device and use the chunkburster.py

chunkburster.py
---------------
The chunkburster.py allows to send chunks to a specific identifier. Just run "python chunkburster.py CHUNKCOUNT ID", where CHUNKCOUNT is the number of chunks to send (size is randomly choosen) and ID is the identifier you want to send to. If everything worked out fine, the other CA-Fi device registered to the identifier you have entered should display the content of the generated chunks (which is also random). 

