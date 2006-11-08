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
    
    def cmd_runscript(self, filename):
        "Run an APDU script from a file"
        fh = file(filename)
        
        doit = False
        ignored_SWs = []
        
        for line in fh:
            if line[:2] == "//" or line[:1] == "#":
                continue
            
            if not doit:
                print "?? %s" % line.strip()
                print "Execute? (Yes/No/All/Exit) ",
                answer = sys.stdin.readline()
                if answer[0].lower() in ('y', "\n"):
                    pass
                elif answer[0].lower() == 'n':
                    continue
                elif answer[0].lower() == 'a':
                    doit = True
                elif answer[0].lower() == 'e':
                    return
                else:
                    continue
            
            self.parse_and_execute(line)
            
            if self.card.sw_changed and self.card.last_sw != self.card.SW_OK \
                    and self.card.last_sw not in ignored_SWs:
                
                print "SW was not %s. Ignore (i) or Abort (a)? " % binascii.hexlify(self.card.SW_OK),
                answer = sys.stdin.readline()
                if answer[0].lower() in ('i', "\n"):
                    pass
                elif answer[0].lower() == 'a':
                    return
                elif answer[0] == 'S':
                    ignored_SWs.append(self.card.last_sw)
                    pass
                else:
                    return
    
    def cmd_listreaders(self):
        "List the available readers"
        list_readers()
    
    @staticmethod
    def cipher(do_encrypt, cipherspec, key, data, iv = None):
        from Crypto.Cipher import DES3, DES, AES, IDEA, RC5
        cipherparts = cipherspec.split("-")
        
        if len(cipherparts) > 2:
            raise ValueError, 'cipherspec must be of the form "cipher-mode" or "cipher"'
        elif len(cipherparts) == 1:
            cipherparts[1] = "ecb"
        
        c_class = locals().get(cipherparts[0].upper(), None)
        if c_class is None: 
            raise ValueError, "Cipher '%s' not known, must be one of %s" % (cipherparts[0], ", ".join([e.lower() for e in dir() if e.isupper()]))
        
        mode = getattr(c_class, "MODE_" + cipherparts[1].upper(), None)
        if mode is None:
            raise ValueError, "Mode '%s' not known, must be one of %s" % (cipherparts[1], ", ".join([e.split()[1].lower() for e in dir(c_class) if e.startswith("MODE_")]))
        
        cipher = None
        if iv is None:
            cipher = c_class.new(key, mode)
        else:
            cipher = c_class.new(key, mode, iv)
            
        
        result = None
        if do_encrypt:
            result = cipher.encrypt(data)
        else:
            result = cipher.decrypt(data)
        
        del cipher
        return result
    
    def cmd_enc(self, *args):
        "Encrypt or decrypt with openssl-like interface"
        
        args = list(args)
        print args
        
        MODE_DECRYPT = "-d"
        MODE_ENCRYPT = "-e"
        mode = MODE_ENCRYPT
        if "-e" in args:
            mode = MODE_ENCRYPT
        
        input = None
        if "-in" in args:
            i = args.index("-in")
            input = args[i+1]
        
        if "-K" not in args:
            raise ValueError, "Must specify key with -K"
        i = args.index("-K")
        key = args[i+1]
        key = binascii.a2b_hex("".join(key.split()))
        
        iv = None
        if "-iv" in args:
            i = args.index("-iv")
            iv = args[i+1]
        
        cipher = "des"
        if args[0][0] != "-":
            cipher = args[0]
        
        text = None
        if "-text" in args:
            if input is not None:
                raise ValueError, "Can't give -in and -text"
            i = args.index("-text")
            text = binascii.a2b_hex("".join(args[i+1].split()))
        
        if text is None:
            if input is None:
                text = self.card.last_result.data
            else:
                fp = file(input)
                text = fp.read()
                fp.close()
        
        result = self.cipher(mode == MODE_ENCRYPT, cipher, key, text, iv)
        
        self.card.last_result = utils.R_APDU(result+"\x00\x00")
        print utils.hexdump(result)
    
    
    def cmd_eval(self, *args):
        "Execute raw python code"
        eval(" ".join(args))
        print

    def cmd_atr(self, *args):
        """Print the ATR of the currently inserted card."""
        print "ATR: %s" % utils.hexdump(self.card.card.status()['ATR'], short=True)
    
    def cmd_save_response(self, file_name, start = None, end = None):
        "Save the data in the last response to a file. start and end are optional"
        lastlen = len(self.card.last_result.data)
        if start is not None:
            start = (lastlen + (int(start,0) % lastlen) ) % lastlen
        else:
            start = 0
        if end is not None:
            end = (lastlen + (int(end,0) % lastlen) ) % lastlen
        else:
            end = lastlen
        
        fp = file(file_name, "w")
        try:
            fp.write(self.card.last_result.data[start:end])
        finally:
            fp.close()
    
    def cmd_disconnect(self, *args):
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
    
    def cmd_reconnect(self, reader = None):
        "Re-open the connection to the card"
        self.cmd_disconnect()
        self.cmd_connect(reader)
    
    def cmd_fancy(self, *args):
        "Parse a fancy APDU and print the result"
        data = binascii.a2b_hex("".join(self.parse_fancy_apdu(*args).split()))
        self.card.last_result = utils.R_APDU(data+"\x00\x00")
        print utils.hexdump(data)
    
    def _update_prompt(self):
        self.set_prompt(self.card.get_prompt() + " ")

    def _clear_sw(self):
        self.card.sw_changed = False
    
    _fancyapduregex = re.compile(r'^\s*([0-9a-f]{2}\s*){4,}\s*((xx|yy)\s*)?(([0-9a-f]{2}|\)|\()\s*)*$', re.I)
    @staticmethod
    def parse_fancy_apdu(*args):
        apdu_string = " ".join(args)
        if not Cyberflex_Shell._fancyapduregex.match(apdu_string):
            raise ValueError
        
        apdu_string = apdu_string.lower()
        have_le = False
        pos = apdu_string.find("xx")
        if pos == -1:
            pos = apdu_string.find("yy")
            have_le = True
        
        apdu_head = ""
        apdu_tail = apdu_string
        if pos != -1:
            apdu_head = apdu_string[:pos]
            apdu_tail = apdu_string[pos+2:]
        
        if apdu_head.strip() != "" and not Cyberflex_Shell._apduregex.match(apdu_head):
            raise ValueError
        
        stack = [""]
        for char in apdu_tail:
            if char in (" ", "a", "b", "c", "d", "e", "f") or char.isdigit():
                stack[-1] = stack[-1] + char
            elif char == ")":
                if len(stack) == 1:
                    raise ValueError
                else: 
                    inner_content = stack.pop()
                    l = len("".join(inner_content.split()))
                    assert l % 2 == 0
                    l = l/2
                    formatted_len = "%02x" % l  ## FIXME len > 255?
                    stack[-1] = stack[-1] + " " + formatted_len + " " + inner_content
            elif char == "(":
                stack.append("")
            else:
                raise ValueError
        
        if len(stack) > 1:
            raise ValueError
        
        
        apdu_string = stack[0]
        
        if apdu_head.strip() != "":
            l = len("".join(stack[0].split()))
            assert l % 2 == 0
            l = l/2
            if have_le: 
                l = l - 1 ## FIXME Le > 255?
            formatted_len = "%02x" % l  ## FIXME len > 255?
            apdu_string = apdu_head + " " + formatted_len + " " + stack[0]
        
        return apdu_string
    
    def do_fancy_apdu(self, *args):
        apdu_string = None
        try:
            apdu_string = Cyberflex_Shell.parse_fancy_apdu(*args)
        except ValueError:
            raise NotImplementedError
        
        return self.do_raw_apdu(apdu_string)
    
    _apduregex = re.compile(r'^\s*([0-9a-f]{2}\s*){4,}$', re.I)
    def do_raw_apdu(self, *args):
        apdu_string = "".join(args)
        if not Cyberflex_Shell._apduregex.match(apdu_string):
            raise NotImplementedError
        
        apdu_binary = binascii.a2b_hex("".join(apdu_string.split()))
        apdu = utils.C_APDU(apdu_binary)
        response = self.card.send_apdu(apdu)
        
        if len(response.data) > 0: ## The SW is already printed by _print_sw as a post_hook
            print utils.hexdump(response.data)

    def _print_sw(self):
        if self.card.sw_changed:
            print self.card.decode_statusword()
    
    def _find_driver_class(driver_name):
        for i in dir(cards):
            _obj = getattr(cards, i)
            if driver_name.lower() == i.lower():
                return _obj
            if hasattr(_obj, "DRIVER_NAME") and driver_name.lower() == getattr(_obj, "DRIVER_NAME").lower():
                return _obj
        raise NameError, "Class not found"
    
    _find_driver_class = staticmethod(_find_driver_class)
    
    def cmd_unloaddriver(self, driver_name):
        "Remove a driver from the current connection"
        self.unregister_commands(self.card)
        try:
            self.card.remove_classes( [self._find_driver_class(driver_name)] )
        finally:
            self.register_commands(self.card)
    
    def cmd_loaddriver(self, driver_name):
        "Add a driver to the current connection"
        self.unregister_commands(self.card)
        try:
            self.card.add_classes( [self._find_driver_class(driver_name)] )
        finally:
            self.register_commands(self.card)
    
    def cmd_connect(self, reader = None):
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
        
        shell.fallback = self.do_fancy_apdu
        
        shell.register_post_hook(self._print_sw)
    
    COMMANDS = dict(Shell.COMMANDS)
    COMMANDS.update( {
        "list_readers": cmd_listreaders,
        "eval": cmd_eval,
        "save_response": cmd_save_response,
        "fancy": cmd_fancy,
        "enc": cmd_enc,
    } )
    
    CARD_COMMANDS = {
        "atr": cmd_atr,
        "disconnect": cmd_disconnect,
        "reconnect": cmd_reconnect,
        "driver_load": cmd_loaddriver,
        "driver_unload": cmd_unloaddriver,
        "run_script": cmd_runscript,
    }
    
    NOCARD_COMMANDS = {
        "connect": cmd_connect,
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
    shell.cmd_connect(reader)
    shell.run()
