#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import pycsc, utils, cards, os, re, binascii, sys, exceptions, traceback, getopt
from shell import Shell

def list_readers():
    for index, name in enumerate(pycsc.listReader()):
        print "%i: %s" % (index, name)

class Cyberflex_Shell(Shell):
    def __init__(self, basename):
        self.print_backtrace = True
        self.reader = 0
        Shell.__init__(self, basename)
        self.register_commands(self, self.NOCARD_COMMANDS)
    
    def cmd_listreaders(self):
        "List the available readers"
        list_readers()

    def cmd_atr(self, *args):
        """Print the ATR of the currently inserted card."""
        print "ATR: %s" % utils.hexdump(self.card.card.status()['ATR'], short=True)
    
    def cmd_close(self, *args):
        "Close the connection to the currently inserted card"
        self.unregister_post_hook(self._print_sw)
        self.fallback = None
        self.unregister_pre_hook(self._clear_sw)
        self.unregister_pre_hook(self._update_prompt)
        self.unregister_commands(self.card)
        self.unregister_commands(self, self.CARD_COMMANDS)
        self.register_commands(self, self.NOCARD_COMMANDS)
        self.card.close_card()
        self.set_prompt("(No card) ")
    
    def cmd_reopen(self, reader = None):
        "Re-open the connection to the card"
        self.cmd_close()
        self.cmd_open(reader)
    
    def _update_prompt(self):
        self.set_prompt(self.card.get_prompt() + " ")

    def _clear_sw(self):
        self.card.sw_changed = False

    _apduregex = re.compile(r'^\s*([0-9a-f]{2}\s*){4,}$', re.I)
    def do_raw_apdu(self, *args):
        apdu_string = "".join(args)
        if not self._apduregex.match(apdu_string):
            raise NotImplementedError
        
        apdu_binary = binascii.a2b_hex("".join(apdu_string.split()))
        apdu = utils.C_APDU(apdu_binary)
        response = self.card.send_apdu(apdu)
        
        if len(response.data) > 0: ## The SW is already printed by _print_sw as a post_hook
            print utils.hexdump(response.data)

    def _print_sw(self):
        if self.card.sw_changed:
            print self.card.decode_statusword()
    
    def cmd_open(self, reader = None):
        "Open the connection to a card"
        if reader is None:
            reader = self.reader
        
        if isinstance(reader, int) or reader.isdigit():
            reader = int(reader)
            readerName = pycsc.listReader()[reader]
        else:
            readerName = reader
        self.reader = reader
        
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
        
        pycsc_card = pycsc.pycsc(reader = readerName, protocol = pycsc.SCARD_PROTOCOL_ANY)
        self.card = cards.new_card_object(pycsc_card)
        
        self.unregister_commands(self, self.NOCARD_COMMANDS)
        self.register_commands(self, self.CARD_COMMANDS)
        self.register_commands(self.card)
        
        self.register_pre_hook(self._update_prompt)
        self.register_pre_hook(self._clear_sw)
        
        shell.fallback = self.do_raw_apdu
        
        shell.register_post_hook(self._print_sw)
    
    COMMANDS = dict(Shell.COMMANDS)
    COMMANDS.update( {
        "list_readers": cmd_listreaders,
    } )
    
    CARD_COMMANDS = {
        "atr": cmd_atr,
        "close_card": cmd_close,
        "reopen_card": cmd_reopen,
    }
    
    NOCARD_COMMANDS = {
        "open_card": cmd_open,
    }
    

OPTIONS = "r:l"
LONG_OPTIONS = ["reader=", "list-readers"]
exit_now = False
reader = None

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
    
    print "Cyberflex shell"
    shell = Cyberflex_Shell("cyberflex-shell")
    shell.cmd_open(reader)
    shell.run()
