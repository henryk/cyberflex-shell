#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import utils, cards, TLV_utils, sys, binascii, time, traceback

OPTIONS = "m:x:d"
LONG_OPTIONS = ["min-fid", "max-fid", "with-dirs"]

STATUS_INTERVAL = 10

results_dir = {}
results_file = {}
top_level = None
start_time = time.time()
loop = 0

min_fid = 0
max_fid = 0xffff
with_dirs = False

if __name__ == "__main__":
    c = utils.CommandLineArgumentHelper()
    
    (options, arguments) = c.getopt(sys.argv[1:], OPTIONS, LONG_OPTIONS)
    for option, value in options:
        if option in ("-m","--min-fid"):
            min_fid = int(value, 16)
        elif option in ("-x","--max_fid"):
            max_fid = int(value, 16)
        elif option in ("-d","--with-dirs"):
            with_dirs = not with_dirs
    
    if len(arguments) > 0:
        top_level = ("".join( ["".join(e.split()) for e in arguments] )).split("/")
        top_level = [binascii.unhexlify(e) for e in top_level]
    
    print >>sys.stderr, "Reading /%s from %04X to %04X%s" % (
        top_level is not None and "/".join("%r" % e for e in top_level) or "",
        min_fid,
        max_fid,
        with_dirs and " (DFs treated separately)" or "",
    )
    
    card_object = c.connect()
    card = cards.new_card_object(card_object)
    cards.generic_card.DEBUG = False
    
    print >>sys.stderr, "Using %s" % card.DRIVER_NAME

    card.change_dir()
    if top_level is not None:
        for e in top_level: 
            if len(e) == 2:
                card.change_dir(e)
            else:
                card.select_application(e)
    
    #objective = (0x2f00, 0x5015) ## Test cases on an OpenSC formatted PKCS#15 card
    #objective = range(0xffff+1) 
    #objective = range(0x3fff+1) + range(0x7000,0x7fff+1) + range(0xc000,0xd4ff+1) + range(0xd600+1,0xd7ff+1) + range(0xdc00+1,0xffff+1)
    objective = range(min_fid, max_fid+1)
    try:
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
            
            if with_dirs:
                result = card.change_dir(data)
                if card.check_sw(result.sw):
                    results_dir[fid] = result
                    card.change_dir()
                    if top_level is not None:
                        for e in top_level: 
                            if len(e) == 2:
                                card.change_dir(e)
                            else:
                                card.select_application(e)
                
                print >>sys.stderr, "\rDir  %04X -> %02X%02X %s" % (fid, result.sw1, result.sw2, status),
            
            result = card.open_file(data)
            if card.check_sw(result.sw):
                results_file[fid] = result
            
            print >>sys.stderr, "\rFile %04X -> %02X%02X %s" % (fid, result.sw1, result.sw2, status),
    except (SystemExit, KeyboardInterrupt):
        raise
    except:
        traceback.print_exc()


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
            print TLV_utils.decode(result.data,tags=card.TLV_OBJECTS)
    
    for fid, result in results_file.items():
        print "-"*80
        print "File\t%04X" % fid
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data,tags=card.TLV_OBJECTS)

