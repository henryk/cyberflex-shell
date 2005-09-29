#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import pycsc, utils, cards, os, readline, re, binascii, sys

histfile = os.path.join(os.environ["HOME"], ".cyberflex-shell.history")
try:
    readline.read_history_file(histfile)
except IOError:
    pass
import atexit
atexit.register(readline.write_history_file, histfile)
del os, histfile

readline.parse_and_bind("tab: complete")


readerName = pycsc.listReader()[0]
newState = pycsc.getStatusChange(ReaderStates=[{'Reader': readerName, 'CurrentState':pycsc.SCARD_STATE_UNAWARE}])

print "Cyberflex shell"
print "Using reader: %s" % readerName
print "Card present: %s" % ((newState[0]['EventState'] & pycsc.SCARD_STATE_PRESENT) and "yes" or "no")

if not newState[0]['EventState'] & pycsc.SCARD_STATE_PRESENT:
    print "Please insert card ..."
    
    while not newState[0]['EventState'] & pycsc.SCARD_STATE_PRESENT \
        or newState[0]['EventState'] & pycsc.SCARD_STATE_MUTE:
        
        newState = pycsc.getStatusChange(ReaderStates=[{'Reader': readerName, 'CurrentState':newState[0]['EventState']}])
        
        if newState[0]['EventState'] & pycsc.SCARD_STATE_MUTE:
            print "Card is mute, please retry ..."
        
    print "Card present: %s" % ((newState[0]['EventState'] & pycsc.SCARD_STATE_PRESENT) and "yes" or "no")

print "ATR:          %s" % utils.hexdump(newState[0]['Atr'], short = True)
card_class = cards.find_class(newState[0]['Atr'])

card = card_class()

line = ""
apduregex = re.compile(r'^\s*([0-9a-f]{2}\s*){4,}$', re.I)
while line != "exit":
    try:
        line = raw_input("%s > " % card.get_prompt())
    except EOFError:
        print
        break
    
    if line.strip() == "":
        continue
    
    parts = line.split()
    cmd = parts[0]
    if card.COMMANDS.has_key(cmd.lower()):
        cmdspec = card.COMMANDS[cmd.lower()]
        try:
            cmdspec[0](card, *parts[1:])
        except Exception:
            exctype, value = sys.exc_info()[:2]
            print "%s: %s" % (exctype, value)
        
    elif apduregex.match(line):
        ## Might be an APDU
        apdu = binascii.a2b_hex("".join(line.split()))
        try:
            response = card.send_apdu(apdu)
            print utils.hexdump(response)
        except Exception:
            exctype, value = sys.exc_info()[:2]
            print "%s: %s" % (exctype, value)
