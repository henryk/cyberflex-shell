#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import utils, cards, TLV_utils, sys, binascii, time, traceback, smartcard

OPTIONS = "m:x:dD"
LONG_OPTIONS = ["min-fid", "max-fid", "with-dirs", "dump-contents"]

STATUS_INTERVAL = 10
SPINNER = ['/','-','\\','|']

results_dir = {}
results_file = {}
contents_file = {}
top_level = None
start_time = time.time()
loop = 0

min_fid = 0
max_fid = 0xffff
with_dirs = False
dump_contents = False

def dump(data):
    print "Dump following (%i bytes)" % (len(data))
    print utils.hexdump(data)
    try:
        print "Trying TLV parse:"
        print TLV_utils.decode(data, tags=card.TLV_OBJECTS, context = card.DEFAULT_CONTEXT)
        print "TLV parsed successfully"
    except (SystemExit, KeyboardInterrupt):
        raise
    except:
        print "TLV error"
        pass

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
        elif option in ("-D", "--dump-contents"):
            dump_contents = not dump_contents
    
    if len(arguments) > 0:
        top_level = ("".join( ["".join(e.split()) for e in arguments] )).split("/")
        top_level = [binascii.unhexlify(e) for e in top_level]
    
    print "Reading /%s from %04X to %04X%s" % (
        top_level is not None and "/".join("%r" % e for e in top_level) or "",
        min_fid,
        max_fid,
        with_dirs and " (DFs treated separately)" or "",
    )
    
    card_object = c.connect()
    card = cards.new_card_object(card_object)
    cards.generic_card.DEBUG = False
    
    print "Using %s" % card.DRIVER_NAME

    card.change_dir()
    if top_level is not None:
        for e in top_level: 
            if len(e) == 2:
                card.change_dir(e)
            else:
                card.select_application(e)
    
    root_node = cards.iso_7816_4_card.iso_node(generic_description="Brute Force Results Tree")
    
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
                    status = status + ", left: %i:%02i:%02i" % (eta / 3600, (eta / 60) % 60, eta % 60)
                except: pass
		if with_dirs: status = status + ", dirs: %2i" % len(results_dir)
                status = status + ", files: %2i)" % len(results_file)
            loop = loop + 1
            
            if with_dirs:
                try:
                    result = card.change_dir(data)
                except smartcard.Exceptions.CardConnectionException:
                    time.sleep(1)
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
                
                print >>sys.stderr, "\rDir  %04X -> %02X%02X %s                      " % (fid, result.sw1, result.sw2, status),
            
            try:
                result = card.open_file(data)
            except smartcard.Exceptions.CardConnectionException:
                time.sleep(1)
                result = card.open_file(data)
            if card.check_sw(result.sw):
                results_file[fid] = result
                
                if dump_contents:
                    contents, sw = card.read_binary_file()
                    contents_result = [sw]
                    if sw == '\x69\x81': # Command incompatible with file structure, retry read_record
                        # FIXME this logic for reading records is not correct
                        print >>sys.stderr, "\rFile %04X -> %02X%02X %s  Reading records...  " % (fid, result.sw1, result.sw2, status),
                        records = {}
                        for i in range(256):
                            if i%STATUS_INTERVAL == 0:
                                print >>sys.stderr, "\rFile %04X -> %02X%02X %s  Reading records...  %s" % (fid, result.sw1, result.sw2, status, 
                                    SPINNER[ (i/STATUS_INTERVAL) % len(SPINNER) ],
                                ),
                            records[i] = card.read_record(i, 4, 0)
                        contents_result.append(records)
                    elif sw == '\x69\x82': # Security status not satisfied
                        pass
                    elif sw == '\x90\x00': # Command execution successful
                        contents_result.append(contents)
                    elif len(contents) > 0: # Something was returned, assume successful execution
                        contents_result.append(contents)
                    
                    contents_file[fid] = contents_result
            
            print >>sys.stderr, "\rFile %04X -> %02X%02X %s                      " % (fid, result.sw1, result.sw2, status),
    except (SystemExit, KeyboardInterrupt):
        raise
    except:
        traceback.print_exc()


    print >>sys.stderr
    
    print "="*80
    print "Results:"
    for fid, result in sorted(results_dir.items()):
        if results_file.has_key(fid):
            continue
        
        print "-"*80
        print "Dir\t%04X" % fid
        if len(result.data) > 0:
	    print utils.hexdump(result.data)
	    try: print TLV_utils.decode(result.data,tags=card.TLV_OBJECTS)
	    except: print "Exception during TLV parse"
    
    for fid, result in sorted(results_file.items()):
        print "-"*80
        print "File\t%04X" % fid
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            try: print TLV_utils.decode(result.data,tags=card.TLV_OBJECTS)
	    except: print "Exception during TLV parse"
        
        if contents_file.has_key( fid ):
            contents_result = contents_file[fid]
            if contents_result[0] == '\x69\x81':
                print "Record-oriented file"
            elif contents_result[0] == '\x69\x82':
                print "Can't read file"
            elif len(contents_result) > 1:
                if contents_result[0] == '\x90\x00':
                    print "Transparent file"
                else:
                    print "Strange file (%02X%02X)" % (ord(contents_result[0][0]), ord(contents_result[0][1]))
            
            if len(contents_result) > 1:
                if isinstance(contents_result[1], str):
                    dump(contents_result[1])
                else:
                    for index, data in contents_result[1].items():
                        if len(data) > 0:
                            print "Record %i:" % index
                            dump(data)
                            print
            
            print
    
    print "<"*40 + ">"*40
    root_node.print_node()

