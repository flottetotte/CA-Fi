import os
import sys
import string
import random
import time
from netlink import *
from bloom import *

def content_generator(size=6, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for x in range(size))

def main():
	import platform
	assert platform.processor() == "x86_64"

	if(len(sys.argv) != 3):
		print "Usage: chunkburster.py <number_of_chunks> <id_of_receiver>"
		exit(2)

	sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, socket.NETLINK_CONNECTOR)
	sock.bind((0, 0))

	number = int(sys.argv[1])
	recvid = str(sys.argv[2])

    # Send
	#start = time()
	i = 0
	while(i < number):
		msg = ofi_netlink_msg(OFI_NL_DATA, 0)
		ofih = ofi_header()
		typ = random.randint(0,15)
		if typ <= 10:
			rtx = 3
		else:
			rtx = random.randint(5, 8)	
		rtx = 1
		rsvd = 0
		ttl = 2
		size = random.randint(650, 700)
		content = content_generator(size)

		ofichunk = ofi_chunk(generate_bloom(recvid), typ, ttl, rtx, rsvd)
		ofichunk.add_payload(content)

		print "rsvd for this chunk is " + str(rsvd)
		print "rtx for this chunk is " + str(rtx)
		print "type for this chunk is " + str(typ)
		print "ttl for this chunk is " + str(ttl)

		ofih.add_chunk(ofichunk)

		data = ofih.to_binary()
		data += ofichunk.to_binary()
		msg.add_payload(data)
		msg.send(sock)
		i = i+1
		#time.sleep(0.075)

	#print "started @"  + str(start) + " ended @"+ str(time())

if __name__ == "__main__":
	main()
