#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import pycsc, utils, cards, os, re, binascii, sys, exceptions

try:
    import readline
except ImportError:
    print "No readline available"

if sys.modules.has_key("readline"):
    histfile = os.path.join(os.environ["HOME"], ".cyberflex-shell.history")
    try:
        readline.read_history_file(histfile)
    except IOError:
        pass
    import atexit
    atexit.register(readline.write_history_file, histfile)
    del os, histfile
    
    readline.parse_and_bind("tab: complete")
    
class Cyberflex_Shell_Completer:
    def __init__(self, *commands):
        self.commands = commands
        self.card = None
    def set_card(self, card):
        self.card = card
    def complete(self, text, state):
        found = -1
        def check(text, state, cmd, found):
            if text == cmd[:len(text)]:
                found = found+1
            if found == state:
                return (found, cmd)
            else:
                return (found, None)
        
        if self.card is not None:
            for (cmd, cmdspec) in self.card.COMMANDS.items():
                (found, retval) = check(text, state, cmd, found)
                if retval is not None:
                    return retval
        for cmdset in self.commands:
            for (cmd, cmdspec) in cmdset.items():
                (found, retval) = check(text, state, cmd, found)
                if retval is not None:
                    return retval
        
        return False

def cmd_exit(card, *args):
    sys.exit()
def cmd_help(card, *args):
    print "Cyberflex-shell help"
    print "\n%s Card commands:" % card.DRIVER_NAME
    for (cmd, cmdspec) in card.COMMANDS.items():
        print "%s\n\t\t%s" % (cmdspec[1], cmdspec[2])
    print "\nShell commands:"
    for (cmd, cmdspec) in COMMANDS.items():
        print "%s\n\t\t%s" % (cmdspec[1], cmdspec[2])
def cmd_atr(card, *args):
    print "ATR: %s" % utils.hexdump(card.card.status()['ATR'], short=True)

COMMANDS = {
    "exit": (cmd_exit, "exit", 
        """Exit the shell."""),
    "help": (cmd_help, "help",
        """Print this help."""),
    "atr": (cmd_atr, "atr",
        """Print the ATR of the currently inserted card.""")
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
    card_class = cards.find_class(newState[0]['Atr'])
    
    card = card_class()
    
    if sys.modules.has_key("readline"):
        completer = Cyberflex_Shell_Completer(COMMANDS)
        completer.set_card(card)
        readline.set_completer(completer.complete)

    
    line = ""
    apduregex = re.compile(r'^\s*([0-9a-f]{2}\s*){4,}$', re.I)
    while True:
        try:
            line = raw_input("%s > " % card.get_prompt())
        except EOFError:
            print
            break
        
        line = line.strip()
        if line == "":
            continue
        
        parts = line.split()
        cmd = parts[0]
        if card.COMMANDS.has_key(cmd.lower()):
            cmdspec = card.COMMANDS[cmd.lower()]
            try:
                cmdspec[0](card, *parts[1:])
            except Exception:
                exctype, value = sys.exc_info()[:2]
                if exctype == exceptions.SystemExit:
                    raise exctype, value
                print "%s: %s" % (exctype, value)
            
        elif COMMANDS.has_key(cmd.lower()):
            cmdspec = COMMANDS[cmd.lower()]
            try:
                cmdspec[0](card, *parts[1:])
            except Exception:
                exctype, value = sys.exc_info()[:2]
                if exctype == exceptions.SystemExit:
                    raise exctype, value
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
            
        else:
            print "Unknown command"
