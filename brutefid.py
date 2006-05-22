#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import pycsc, utils, cards, TLV_utils, sys, binascii, time

STATUS_INTERVAL = 10

results_dir = {}
results_file = {}
top_level = None
start_time = time.time()
loop = 0

if __name__ == "__main__":
    if len(sys.argv) > 1:
        top_level = binascii.unhexlify("".join( sys.argv[1].split() ))

    pycsc_card = pycsc.pycsc(protocol = pycsc.SCARD_PROTOCOL_ANY)
    card = cards.new_card_object(pycsc_card)
    cards.generic_card.DEBUG = False
    
    print >>sys.stderr, "Using %s" % card.DRIVER_NAME

    card.change_dir()
    if top_level is not None:
        card.change_dir(top_level)
    
    #objective = (0x2f00, 0x5015) ## Test cases on an OpenSC formatted PKCS#15 card
    objective = range(0xffff) 
    for fid in objective:
        data = chr(fid >> 8) + chr(fid & 0xff)
        if loop % STATUS_INTERVAL == 0:
            elapsed = time.time() - start_time
            status = "(elapsed: %i:%02i:%02i" % (elapsed / 3600, (elapsed / 60) % 60, elapsed % 60)
            try:
                eta = (elapsed / loop) * (len(objective) - loop)
                status = status + ", left: %i:%02i:%02i)" % (eta / 3600, (eta / 60) % 60, eta % 60)
            except:
                status = status + ")"
        loop = loop + 1
        
        result = card.change_dir(data)
        if result.sw == card.SW_OK:
            results_dir[fid] = result
            card.change_dir()
            if top_level is not None:
                card.change_dir(top_level)
        
        print >>sys.stderr, "\rDir  %04X -> %02X%02X %s" % (fid, result.sw1, result.sw2, status),
        
        result = card.open_file(data)
        if result.sw == card.SW_OK:
            results_file[fid] = result
        
        print >>sys.stderr, "\rFile %04X -> %02X%02X %s" % (fid, result.sw1, result.sw2, status),


    print >>sys.stderr
    
    print "="*80
    print "Results:"
    for fid, result in results_dir.items():
        if results_file.has_key(fid):
            continue
        
        print "-"*80
        print "Dir\t%04X" % fid
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data)
    
    for fid, result in results_file.items():
        print "-"*80
        print "File\t%04X" % fid
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data)

