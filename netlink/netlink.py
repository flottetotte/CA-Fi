#!/usr/bin/env python
import socket
import os
import struct
import sys

CN_IDX_PROC = 1
CN_VAL_PROC = 1

NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLMSG_OVERRUN = 4

OFI_NETLINK_MAX_PAYLOAD = 1504

#Netlink message types
OFI_NETLINK_MSG = 28

OFI_NL_CTRL= 1

#OFI CTRL Subtypes
OFI_NL_CTRL_REG = 1
OFI_NL_CTRL_ID_REG = 2
OFI_NL_CTRL_ID_DEL = 3

OFI_NL_DATA = 2

OFI_NL_DBG = 3

OFI_NLMSG_HDR_LEN = 20

OFI_HDR_LEN = 14
OFI_CHUNKHDR_LEN = 18

# Create Netlink socket
if getattr(socket, "NETLINK_CONNECTOR", None) is None:
    socket.NETLINK_CONNECTOR = 28

class ofi_netlink_msg:
    def __init__(self, ofi_nl_hdr_type, ofi_nl_hdr_param):
        self.ofi_nl_hdr_type = ofi_nl_hdr_type
        self.ofi_nl_hdr_param = ofi_nl_hdr_param
        self.ofi_nl_hdr_len = 0
        self.payload = None

    def add_payload(self, payload):
        self.payload = payload
        self.ofi_nl_hdr_len = len(self.payload)

    def send(self, nl_sock):
        nl_len = OFI_NLMSG_HDR_LEN + self.ofi_nl_hdr_len
        msg = struct.pack("=IHHIIBBH", nl_len, NLMSG_DONE, 0, 0, os.getpid(), self.ofi_nl_hdr_type, self.ofi_nl_hdr_param, self.ofi_nl_hdr_len)
        if self.payload:
            msg += self.payload
        if nl_sock.send(msg) != nl_len:
            raise RuntimeError, "Failed to send"  

class ofi_header:
    def __init__(self):
        #everything can be computed for this header
        self.bloom = 0x000000000000000000000000
        self.len = 0

    def add_chunk(self, chunk):
        self.bloom |= chunk.bloom
        print hex(self.bloom)
        self.len += chunk.len + 10

    def to_binary(self):
        res = struct.pack(">L", (self.bloom >> 64) & 0xffffffff)
        res += struct.pack(">L", (self.bloom >> 32) & 0xffffffff)
        res += struct.pack(">L", self.bloom & 0xffffffff)
        res += struct.pack("=H", self.len)
        return res
        
class ofi_chunk:
    def __init__(self, bloom, typ, ttl, rtx, rsvd):
        self.bloom = bloom
        self.type = typ
        self.ttl = ttl
        self.rtx = rtx
        self.rsvd = rsvd
        self.len = 0
        self.payload = None

    def add_payload(self, payload):
        self.payload = payload
        self.len = len(payload)
        print self.len

    def to_binary(self):
        res = struct.pack(">L", (self.bloom >> 64) & 0xffffffff)
        res += struct.pack(">L", (self.bloom >> 32) & 0xffffffff)
        res += struct.pack(">L", self.bloom & 0xffffffff)
        res += struct.pack("=BBBBH", self.type, self.ttl, self.rtx, self.rsvd, self.len)         
        res += self.payload
        return res