import os
import sys
import string
import threading 
from netlink import *
from min_kernel_msg_handler import *

def main():
	import platform
	assert platform.processor() == "x86_64"

	sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, socket.NETLINK_CONNECTOR)
	sock.bind((0, 0))

	recv = ReceiveThread(sock)
	recv.start() 

	msg = ofi_netlink_msg(OFI_NL_CTRL, OFI_NL_CTRL_REG)
	msg.send(sock)

	run=1
	while run:
		user = str(raw_input('cmd: '))
		if user == "q":
			run = 0
		elif user[0] ==	"r":
			msg = ofi_netlink_msg(OFI_NL_CTRL, OFI_NL_CTRL_ID_REG)
			subscription = user[1:len(user)]
			subscription += "\x00"
			msg.add_payload(subscription);
			print "Send ctrl to add subscription:" + subscription
			msg.send(sock)
		elif user[0] ==	"d":
			msg = ofi_netlink_msg(OFI_NL_CTRL, OFI_NL_CTRL_ID_DEL)
			subscription = user[1:len(user)]
			subscription += "\x00"
			msg.add_payload(subscription);
			print "Send ctrl to delete subscription:" + subscription
			msg.send(sock)
		else:
			print "Could not parse cmd"	

	recv.stop()
	sys.exit(0)

if __name__ == "__main__":
	main()