import threading
import os
import string
import random
import subprocess
import select
import time
from netlink import *

class ReceiveThread(threading.Thread): 
	def __init__(self, sock): 
		threading.Thread.__init__(self) 
		self.sock = sock
		self.quit = False
		self.apthread = None
		self.wpathread = None
		self.service = ""

	def run(self): 
		while not self.quit:
			r, w, errors = select.select([self.sock], [], [], 3)
			if r == []:
				continue;
			data, (nlpid, nlgrps) = self.sock.recvfrom(OFI_NLMSG_HDR_LEN + OFI_NETLINK_MAX_PAYLOAD)

			nl_len, nl_type, nl_flags, nl_seq, nl_pid, ofi_nl_hdr_type, ofi_nl_hdr_param, ofi_nl_hdr_len \
			= struct.unpack("=IHHIIBBH", data[:OFI_NLMSG_HDR_LEN])

			print "\nout: Got nl with len %i " % (nl_len)
			if (len(data) > OFI_NLMSG_HDR_LEN) and (ofi_nl_hdr_type == OFI_NL_DATA):
				ofichunkh_bloom \
				= struct.unpack(">L", data[OFI_NLMSG_HDR_LEN:OFI_NLMSG_HDR_LEN+4])
				ofichunkh_bloom \
				+= struct.unpack(">L", data[OFI_NLMSG_HDR_LEN+4:OFI_NLMSG_HDR_LEN+8])
				ofichunkh_bloom \
				+= struct.unpack(">L", data[OFI_NLMSG_HDR_LEN+8:OFI_NLMSG_HDR_LEN++12])

				ofichunkh_type, ofichunkh_ttl, ofichunkh_rtx, ofichunkh_rsvd \
				= struct.unpack("=BBBB", data[OFI_NLMSG_HDR_LEN+12:OFI_NLMSG_HDR_LEN+16])

				ofichunkh_len \
				= struct.unpack("=H", data[OFI_NLMSG_HDR_LEN+16:OFI_NLMSG_HDR_LEN+18])
				ofichunkh_len = ofichunkh_len[0]
				print "\nout: Got chunk with rsvd %i " % (ofichunkh_rsvd)

				fmt = "="
				for x in range (0,ofichunkh_len):
					fmt += "B"

				if(ofichunkh_rsvd == 0):
					payloadstart =  OFI_NLMSG_HDR_LEN + OFI_CHUNKHDR_LEN
					payloadend = payloadstart+ofichunkh_len
					payload	= struct.unpack(fmt, data[payloadstart:payloadend]) 
					print "\nout: Got data with len %i " % (ofichunkh_len)
					print "".join('%02x' % i for i in payload)

	def stop(self):
 		self.quit = True