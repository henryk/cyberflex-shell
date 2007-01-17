#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import sys, utils, binascii

def parse_file(fname):
    fp = file(fname)
    
    in_block = False
    is_rfid = False
    line_no = 0
    direction = 0
    data = []
    last_was_transfer_buffer = False
    
    for line in fp.readlines():
        if not in_block:
            if last_was_transfer_buffer:
                parts = line.split(":")
                if parts[0] == "    00000000":
                    if parts[1][:3] == " 6f":
                        in_block = True
                        direction = 0
                        line_no = 0
                        is_rfid = False
                        data = []
                    elif parts[1][:3] == " 80":
                        in_block = True
                        direction = 1
                        line_no = 0
                        is_rfid = False
                        data = []
                    elif parts[1][:3] == " 6b":
                        in_block = True
                        direction = 0
                        line_no = 0
                        is_rfid = True
                        data = []
                    elif parts[1][:3] == " 83":
                        in_block = True
                        direction = 1
                        line_no = 0
                        is_rfid = True
                        data = []
            if in_block and (not is_rfid or line_no > 0):
                data = [ parts[1][31:] ]
        else:
            if not ":" in line:
                in_block = False
                data_binary = binascii.a2b_hex("".join("".join(data).split()))
                if not is_rfid:
                    print (direction and "<< " or ">> ") + utils.hexdump(data_binary, indent=3)
                    if direction == 1: print
                elif len("".join(data).strip()) > (direction == 0 and 8 or 2) and data_binary not in ("\x00"*5, "\x70\x08\x35\x2d\x66\x76", "\x43\x4f\x53\x73\x01\x02\x01"):
                    print (direction and "«« " or "»» ") + utils.hexdump(data_binary, indent=3)
                    if direction == 1: print
            else:
                line_no = line_no + 1
                if (not is_rfid or line_no > 1):
                    data.append( line.split(":")[1] )
                elif is_rfid and line_no == 1:
                    data.append( line.split(":")[1][6:] )
        
        last_was_transfer_buffer = "TransferBufferMDL" in line

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print >>sys.stderr, "Need one argument"
        sys.exit(1)
    
    parse_file(sys.argv[1])
