#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import pycsc, utils, cards, os, re, binascii, sys, exceptions, traceback
from shell import Shell
print_backtrace = True

def cmd_atr(card, *args):
    """Print the ATR of the currently inserted card."""
    print "ATR: %s" % utils.hexdump(card.card.status()['ATR'], short=True)

COMMANDS = {
    "atr": cmd_atr
}

if __name__ == "__main__":
    
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
    
    pycsc_card = pycsc.pycsc(protocol = pycsc.SCARD_PROTOCOL_ANY)
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
        apdu = utils.APDU(apdu_binary)
        response = card.send_apdu(apdu)
        print utils.hexdump(response)
        
    shell.fallback = do_raw_apdu
    
    def _print_sw():
        if card.sw_changed:
            print card.decode_statusword()
    shell.register_post_hook(_print_sw)

    shell.run()
