#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import pycsc, utils, cards, os, re, binascii, sys, exceptions, traceback, getopt
from shell import Shell
print_backtrace = True

def cmd_atr(card, *args):
    """Print the ATR of the currently inserted card."""
    print "ATR: %s" % utils.hexdump(card.card.status()['ATR'], short=True)

def cmd_close(card, *args):
    "Close the connection to the currently inserted card"
    shell.unregister_post_hook(_print_sw)
    shell.fallback = None
    shell.unregister_pre_hook(_clear_sw)
    shell.unregister_pre_hook(_update_prompt)
    shell.unregister_commands(card)
    shell.unregister_commands(card, COMMANDS)
    card.close_card()
    shell.set_prompt("(No card) ")

COMMANDS = {
    "atr": cmd_atr,
    "close_card": cmd_close,
}

def list_readers():
    for index, name in enumerate(pycsc.listReader()):
        print "%i: %s" % (index, name)


OPTIONS = "r:l"
LONG_OPTIONS = ["reader=", "list-readers"]
reader = 0
exit_now = False

if __name__ == "__main__":
    
    (options, arguments) = getopt.gnu_getopt(sys.argv[1:], OPTIONS, LONG_OPTIONS)
    
    for (option, value) in options:
        if option in ("-r","--reader"):
            if value.isdigit():
                reader = int(value)
            else:
                reader = value
        if option in ("-l","--list-readers"):
            list_readers()
            exit_now = True
    
    if exit_now:
        sys.exit()
    del exit_now
    
    if isinstance(reader, int):
        readerName = pycsc.listReader()[reader]
    else:
        readerName = reader
    del reader
    
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
    
    pycsc_card = pycsc.pycsc(reader = readerName, protocol = pycsc.SCARD_PROTOCOL_ANY)
    card = cards.new_card_object(pycsc_card)
    
    shell = Shell("cyberflex-shell")
    shell.register_commands(card, COMMANDS)
    shell.register_commands(card)
    
    def _update_prompt():
        shell.set_prompt(card.get_prompt() + " ")
    shell.register_pre_hook(_update_prompt)
    
    def _clear_sw():
        card.sw_changed = False
    shell.register_pre_hook(_clear_sw)
    
    apduregex = re.compile(r'^\s*([0-9a-f]{2}\s*){4,}$', re.I)
    def do_raw_apdu(*args):
        apdu_string = "".join(args)
        if not apduregex.match(apdu_string):
            raise NotImplementedError
        
        apdu_binary = binascii.a2b_hex("".join(apdu_string.split()))
        apdu = utils.C_APDU(apdu_binary)
        response = card.send_apdu(apdu)
        
        if len(response.data) > 0: ## The SW is already printed by _print_sw as a post_hook
            print utils.hexdump(response.data)
        
    shell.fallback = do_raw_apdu
    
    def _print_sw():
        if card.sw_changed:
            print card.decode_statusword()
    shell.register_post_hook(_print_sw)

    shell.run()
