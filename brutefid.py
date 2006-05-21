#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import pycsc, utils, cards, TLV_utils

results_dir = {}
results_file = {}

if __name__ == "__main__":
    pycsc_card = pycsc.pycsc(protocol = pycsc.SCARD_PROTOCOL_ANY)
    card = cards.new_card_object(pycsc_card)
    
    print "Using %s" % card.DRIVER_NAME

    #for fid in (0x2f00, 0x5015): ## Test cases on an OpenSC formatted PKCS#15 card
    for fid in range(0xffff):
        data = chr(fid >> 8) + chr(fid & 0xff)
        
        result = card.change_dir(data)
        if result.sw == card.SW_OK:
            results_dir[fid] = result
            card.change_dir()
        
        result = card.open_file(data)
        if result.sw == card.SW_OK:
            results_file[fid] = result

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

