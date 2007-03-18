#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import pycsc, utils, cards, TLV_utils, sys, binascii, time, getopt, traceback

STATUS_INTERVAL = 10

results_dir = {}
results_file = {}
top_level = None
start_time = time.time()
loop = 0

OPTIONS = "r:l"
LONG_OPTIONS = ["reader=", "list-readers"]
exit_now = False
reader = None

def list_readers():
    for index, name in enumerate(pycsc.listReader()):
        print "%i: %s" % (index, name)

def connect(reader = None):
    "Open the connection to a card"
    
    if reader is None:
        reader = 0
    
    if isinstance(reader, int) or reader.isdigit():
        reader = int(reader)
        readerName = pycsc.listReader()[reader]
    else:
        readerName = reader
    
    newState = pycsc.getStatusChange(ReaderStates=[
            {'Reader': readerName, 'CurrentState':pycsc.SCARD_STATE_UNAWARE}
        ]
    )
    
    print "Using reader: %s" % readerName
    print "Card present: %s" % ((newState[0]['EventState'] & pycsc.SCARD_STATE_PRESENT) and "yes" or "no")
    
    if not newState[0]['EventState'] & pycsc.SCARD_STATE_PRESENT:
        print "Please insert card ..."
        
        last_was_mute = False
        
        while not newState[0]['EventState'] & pycsc.SCARD_STATE_PRESENT \
            or newState[0]['EventState'] & pycsc.SCARD_STATE_MUTE:
            
            try:
                newState = pycsc.getStatusChange(ReaderStates=[
                        {'Reader': readerName, 'CurrentState':newState[0]['EventState']}
                    ], Timeout = 100 
                ) ## 100 ms latency from Ctrl-C to abort should be almost unnoticeable by the user
            except pycsc.PycscException, e:
                if e.args[0] == 'Command timeout.': pass ## ugly
                else: raise
            
            if newState[0]['EventState'] & pycsc.SCARD_STATE_MUTE:
                if not last_was_mute:
                    print "Card is mute, please retry ..."
                last_was_mute = True
            else: 
                last_was_mute = False
            
        print "Card present: %s" % ((newState[0]['EventState'] & pycsc.SCARD_STATE_PRESENT) and "yes" or "no")
    
    print "ATR:          %s" % utils.hexdump(newState[0]['Atr'], short = True)
    return pycsc.pycsc(reader = readerName, protocol = pycsc.SCARD_PROTOCOL_ANY)


if __name__ == "__main__":

    (options, arguments) = getopt.gnu_getopt(sys.argv[1:], OPTIONS, LONG_OPTIONS)
    
    for (option, value) in options:
        if option in ("-r","--reader"):
            reader = value
        if option in ("-l","--list-readers"):
            list_readers()
            exit_now = True

    if exit_now:
        sys.exit()
    del exit_now

    if len(arguments) > 0:
        top_level = ("".join( ["".join(e.split()) for e in arguments] )).split("/")
        top_level = [binascii.unhexlify(e) for e in top_level]
    
    pycsc_card = connect(reader)
    card = cards.new_card_object(pycsc_card)
    cards.generic_card.DEBUG = False
    
    print >>sys.stderr, "Using %s" % card.DRIVER_NAME

    card.change_dir()
    if top_level is not None:
        for e in top_level: card.change_dir(e)
    
    #objective = (0x2f00, 0x5015) ## Test cases on an OpenSC formatted PKCS#15 card
    objective = range(0xffff+1) 
    #objective = range(0x3fff+1) + range(0x7000,0x7fff+1) + range(0xc000,0xd4ff+1) + range(0xd600+1,0xd7ff+1) + range(0xdc00+1,0xffff+1)
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
            
            if True:
                result = card.change_dir(data)
                if card.check_sw(result.sw):
                    results_dir[fid] = result
                    card.change_dir()
                    if top_level is not None:
                        for e in top_level: card.change_dir(e)
                
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

