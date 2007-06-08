#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

from utils import pycsc
import utils, cards, TLV_utils, sys, binascii, time, traceback, re

STATUS_INTERVAL = 10

def fingerprint_rfid(card):
    # Need RFID
    if not isinstance(card, cards.rfid_card.RFID_Card):
        return [""]
    
    uid = card.get_uid()
    
    return "%02X" % ord(uid[0])
    # FIXME: Determine ISO type and then return a value depending on A-fixed UID vs. A-random UID vs. B

def fingerprint_7816(card):
    # Need ISO 7816-4
    if not isinstance(card, cards.iso_7816_4_card.ISO_7816_4_Card):
        return []
    
    # Try a select MF, just in case ...
    try:
        card.change_dir()
    except (SystemExit, KeyboardInterrupt):
        raise
    except:
        traceback.print_exc()
    
    SHORT_SW_MAP = {
        "\x90\x00": 0,
        "\x69\x82": 1, # Security status not satisfied
        "\x6a\x82": 2, # File not found
        None: 3,
    }
    SHORT_SW_WIDTH = 2
    
    def detect_bac(card):
        "Check whether BAC is active and if yes what type of card-os (select not allowed, select allowed but read not allowed)"
        result = card.open_file("\x01\x01", 0x0c) # EF.DG1
        
        if result.sw == "\x90\x00":
            prefix = str(SHORT_SW_MAP[result.sw])
            result = card.send_apdu(utils.C_APDU(card.APDU_READ_BINARY, p1=0, p2=0, le=1))
        else:
            prefix = ""
        
        if SHORT_SW_MAP.has_key(result.sw):
            return prefix + str(SHORT_SW_MAP[result.sw]) 
        else:
            return prefix + "%s:%s" % (SHORT_SW_MAP[None], binascii.b2a_hex(result.sw) )
    
    def map_dg(card):
        "Get a map of which DGs exist and are readable/unreadable and with which SW they are unreadable"
        # Try to read 1 byte from each DG through READ BINARY with short file identifier
        responses = [card.send_apdu(utils.C_APDU(card.APDU_READ_BINARY, p1=i|0x80, p2=0, le=1)) for i in range(1,17)]
        
        result = []
        exceptional = []
        for response in responses:
            if SHORT_SW_MAP.has_key( response.sw ):
                result.append( SHORT_SW_MAP[response.sw] )
            else:
                result.append( SHORT_SW_MAP[None] )
                exceptional.append(response.sw)
        
        UNIT_FORMAT = "%X"
        UNIT_LEN = 4 # For hex in "%X" format. Would be 8 for hex in "%02X" format.
        compressed = []
        current = 0
        count = 0
        for r in result:
            if count >= UNIT_LEN:
                compressed.append( current )
                current = count = 0
            current = (current << SHORT_SW_WIDTH) | r
            count = count + SHORT_SW_WIDTH
        
        if count > 0:
            if not count >= UNIT_LEN:
                while count < UNIT_LEN:
                    current = current << SHORT_SW_WIDTH
                    count += SHORT_SW_WIDTH
            compressed.append( current )
            current = count = 0
        
        
        return "".join( [UNIT_FORMAT % r for r in compressed] ) + ":".join( (len(exceptional) > 0 and [""] or []) + [binascii.b2a_hex(e) for e in exceptional] )
    
    result = []
    postfix = ""
    test_icao = card.select_application(card.resolve_symbolic_aid("mrtd"), le=None)
    if test_icao.sw == "\x67\x00":
        postfix = ":6700" # SELECT APPLICATION with P2=0 and without Le returns 6700 Wrong Length
        test_icao = card.select_application(card.resolve_symbolic_aid("mrtd"), le=None, P2=0x0c)
    
    if not card.check_sw(test_icao.sw, card.PURPOSE_SUCCESS):
        result.append("N"+postfix) # Not an ICAO MRTD
    else:
        result.append("P"+postfix) # An ICAO MRTD
        
        bac = detect_bac(card)
        result.append(bac) # BAC status
        
        dgmap = map_dg(card)
        result.append(dgmap) # Data Group map
    
    return result
    
def fingerprint(card):
    def compress_atr(atr):
        numhist = ord(atr[1]) & 0x0f
        if binascii.a2b_hex( "3B8%X8001" % numhist ) == atr[:4]:
            # Contactless, conforming to PC/SC part 3 section 3.1.3.2.3
            
            if atr[4:6] == "\x80\x4f": # Status indicator in compact-tlv object
                si_len = ord(atr[6])
                aid = atr[7:7+si_len]
                
                if aid[:5] == "\xa0\x00\x00\x03\x06": # RID of PC/SC Workgroup
                    standard_and_name = aid[5:]
                    if standard_and_name[3:] == "\x00" * (len(standard_and_name)-3):
                        return "1:%s" % binascii.b2a_hex(standard_and_name[:3]) # RFU bytes unset
                    else:
                        return "2:%s" % binascii.b2a_hex(standard_and_name) # RFU bytes set
            
            return "0:%s" % binascii.b2a_hex(atr[4:])
        else:
            # Not contactless (or not conforming)
            return "3:%s" % binascii.b2a_hex(atr)
        return ""
    
    result = []
    
    atr = card.get_atr()
    try:
        catr = compress_atr(atr)
    except (KeyboardInterrupt, SystemExit):
        raise
    except: # Any error in the ATR processing
        catr = "F:%s" % binascii.b2a_hex(atr)
    result.append( catr )
    result.extend( fingerprint_7816(card) )
    result.append( fingerprint_rfid(card) )
    
    return ",".join(result)
    
def match_fingerprint(fingerprint, database="fingerprints.txt"):
    fp = file(database, "r")
    
    results = []
    current_result = []
    first_line = True
    matched = False
    
    def do_match(line, fingerprint):
        return re.match(line.strip(), fingerprint.strip()) is not None
    
    for line in fp.readlines():
        if line[0] == "#":
            continue
        
        if line.strip() == "":
            matched = False
            if len(current_result) > 0:
                results.append(current_result)
                current_result = []
        elif not line[0].isspace():
            if do_match(line, fingerprint):
                matched = True
            else:
                matched = False
        elif matched:
            current_result.append(line.strip())
    
    if len(current_result) > 0:
        results.append(current_result)
        current_result = []
    
    fp.close()
    return ["\n".join(e) for e in results]
    
if __name__ == "__main__":
    c = utils.CommandLineArgumentHelper()
    (options, arguments) = c.getopt(sys.argv[1:])
    
    pycsc_card = c.connect()
    card = cards.new_card_object(pycsc_card)
    cards.generic_card.DEBUG = False
    
    print >>sys.stderr, "Using %s" % card.DRIVER_NAME
    
    if isinstance(card, cards.rfid_card.RFID_Card):
        print "UID: %s" % utils.hexdump(card.get_uid(), short=True)
    fp = fingerprint(card)
    print "Fingerprint: %s" % fp
    matches = match_fingerprint(fp)
    if len(matches) > 1:
        print "Matched as: \n\t+ %s" % "\nor\t+ ".join( ["\n\t  ".join(e.split("\n")) for e in matches] )
    elif len(matches) == 1:
        if len(matches[0].split("\n")) == 1:
            print "Matched as: %s" % matches[0]
        else:
            print "Matched as: \n\t%s" % "\n\t".join( matches[0].split("\n") )
    
