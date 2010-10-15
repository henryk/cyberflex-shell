#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import crypto_utils, utils, cards, readers, os, re, binascii, sys, exceptions, traceback, getopt, datetime
from shell import Shell

class Logger(object):
    def __init__(self, filename, stream, prefix = "# "):
        self.fp = file(filename, "w")
        self.stream = stream
        self.prefix = prefix
        self.need_prefix = True
    
    def println(self, string):
        if not self.need_prefix:
            self.fp.write("\n")
            self.need_prefix = True
        self.fp.write("\n".join(string.splitlines()) + "\n")
    
    def flush(self):
        return self.stream.flush()
    
    def close(self):
        self.fp.close()
    
    def writelines(self, lines):
        for line in lines:
            self.write(line)
    
    def write(self, line):
        if self.need_prefix:
            self.fp.write(self.prefix)
            self.need_prefix = False
        
        self.fp.write( ( ("\n"+self.prefix).join(line.splitlines()) ) )
        if len(line) > 0 and line[-1] == "\n":
            self.fp.write("\n")
            self.need_prefix = True
        
        self.stream.write(line)

class Cyberflex_Shell(Shell):
    def __init__(self, basename):
        self.print_backtrace = True
        self.reader = 0
        self.logger = None
        Shell.__init__(self, basename)
        self.register_commands(self, self.NOCARD_COMMANDS)
        self.set_prompt("(No card) ")
    
    def cmd_runscript(self, filename, ask = True):
        "Run an APDU script from a file"
        fh = file(filename)
        
        doit = not ask
        #ignored_SWs = ["\x62\x82"]
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
            
            if self.card.sw_changed and not self.card.check_sw(self.card.last_sw) \
                    and self.card.last_sw not in ignored_SWs:
                
                print "SW(%s) was not OK. Ignore (i) or Abort (a)? " % binascii.hexlify(self.card.last_sw),
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
        for i, (name, obj) in enumerate(readers.list_readers()):
            print "%i: %s" % (i,name)
    
    def cmd_enc(self, *args):
        "Encrypt or decrypt with openssl-like interface"
        
        args = list(args)
        
        MODE_DECRYPT = "-d"
        MODE_ENCRYPT = "-e"
        mode = MODE_ENCRYPT
        if "-d" in args:
            mode = MODE_DECRYPT
        
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
            iv = binascii.a2b_hex("".join(iv.split()))
        
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
        
        result = crypto_utils.cipher(mode == MODE_ENCRYPT, cipher, key, text, iv)
        
        self.card.last_result = utils.R_APDU(result+"\x00\x00")
        print utils.hexdump(result)
    
    
    def cmd_eval(self, *args):
        "Execute raw python code"
        eval(" ".join(args))
        print

    def cmd_atr(self, *args):
        """Print the ATR of the currently inserted card."""
        print "ATR: %s" % utils.hexdump(self.card.reader.get_ATR(), short=True)
    
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
    
    def cmd_load_response(self, filename, start=None, end=None):
        "Load the data from a file and pretend it was the last response from the card.  start and end are optional"
        fp = file(filename, "r")
        try:
            data = fp.read()
        finally:
            fp.close()
        datalen = len(data)
        
        if start is not None:
            start = (datalen + (int(start,0) % datalen) ) % datalen
        else:
            start = 0
        if end is not None:
            end = (datalen + (int(end,0) % datalen) ) % datalen
        else:
            end = datalen
        
        self.card.last_result = utils.R_APDU(data[start:end] + "\x00\x00")
    
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
        apdu = utils.C_APDU.parse_fancy(*args)
        data = apdu.render()
        if hasattr(self, "card"):
            self.card.last_result = utils.R_APDU(data+"\x00\x00")
        print utils.hexdump(data)
    
    def _update_prompt(self):
        self.set_prompt(self.card.get_prompt() + " ")

    def _clear_sw(self):
        self.card.sw_changed = False
        self.card.last_delta = None
    
    def do_fancy_apdu(self, *args):
        "Parse and transmit a fancy APDU"
        apdu = None
        try:
            apdu = utils.C_APDU.parse_fancy(*args)
        except ValueError:
            raise NotImplementedError
        
        if apdu is not None:
            return self.do_apdu(apdu)
    
    def do_normal_apdu(self, *args):
        "Transmit an APDU"
        apdu_string = "".join(args)
        if not utils.C_APDU._apduregex.match(apdu_string):
            raise NotImplementedError
        
        apdu_binary = binascii.a2b_hex("".join(apdu_string.split()))
        apdu = utils.C_APDU(apdu_binary)
        
        return self.do_apdu(apdu)
    
    def do_raw_apdu(self, *args):
        "Transmit a raw data string as an APDU"
        apdu_string = "".join(args)
        
        apdu_binary = binascii.a2b_hex("".join(apdu_string.split()))
        apdu = utils.Raw_APDU(apdu_binary)
        
        return self.do_apdu(apdu)
    
    def do_apdu(self, apdu):
        response = self.card.send_apdu(apdu)
        
        if len(response.data) > 0: ## The SW is already printed by _print_sw as a post_hook
            print utils.hexdump(response.data)
    
    def pause_log(self):
        if self.logger is not None:
            sys.stdout = self.logger.stream
    
    def unpause_log(self):
        if self.logger is not None:
            sys.stdout = self.logger
    
    def start_log(self, filename):
        if self.logger is not None:
            self.stop_log()
        self.logger = Logger(filename, sys.stdout)
        sys.stdout = self.logger
        print "Logging to %s" % filename
        try:
            self.logger.println( "# ATR of currently inserted card is: %s" % utils.hexdump(self.card.reader.get_ATR(), short=True) )
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            pass
        self.register_pre_hook(self.pause_log)
    
    def stop_log(self):
        if self.logger is not None:
            print "Log stopped"
            sys.stdout = self.logger.stream
            self.logger.flush()
            self.logger = None
            self.unregister_pre_hook(self.pause_log)
    
    def parse_and_execute(self, line):
        if self.logger is not None:
            self.logger.println( self.logger.prefix + "\n" 
                + self.logger.prefix + "=== " + datetime.datetime.now().isoformat(" ") + " " + ("="*49) )
            self.logger.println(line)
        if self.logger is not None:
            self.unpause_log()
        result = Shell.parse_and_execute(self, line)
        return result
    
    def cmd_log(self, filename = None):
        "Start (when given a filename) or stop (otherwise) logging to a file"
        if filename is not None:
            date = datetime.datetime.now()
            vars = {
                "HOMEDIR": os.environ["HOME"],
                "ISOTIME": date.isoformat()
            }
            self.start_log(filename % vars)
        else:
            self.stop_log()

    def _print_sw(self):
        to_print = []
        if self.card.sw_changed:
            to_print.append(self.card.decode_statusword())
        
        if self.card.last_delta is not None:
            to_print.append("%0.03gs" % self.card.last_delta)
        
        if to_print:
            print ", ".join(to_print)
    
    def _find_driver_class(driver_name):
        for i in dir(cards):
            _obj = getattr(cards, i)
            if driver_name.lower() == i.lower():
                return _obj
            if hasattr(_obj, "DRIVER_NAME") and driver_name.lower() in [e.lower() for e in getattr(_obj, "DRIVER_NAME")]:
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
        
        reader_object = readers.connect_to(reader)
        self.card = cards.new_card_object(reader_object)
        
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
        "load_response": cmd_load_response,
        "fancy": cmd_fancy,
        "enc": cmd_enc,
        "log": cmd_log,
    } )
    
    CARD_COMMANDS = {
        "atr": cmd_atr,
        "disconnect": cmd_disconnect,
        "reconnect": cmd_reconnect,
        "driver_load": cmd_loaddriver,
        "driver_unload": cmd_unloaddriver,
        "raw": do_raw_apdu,
        "run_script": cmd_runscript,
    }
    
    NOCARD_COMMANDS = {
        "connect": cmd_connect,
    }

def usage():
    print """Cyberflex shell
Synopsis: cyberflex-shell.py [options] [scriptfiles]
Options:
    -r, --reader             Select the reader to use, either by
                             index or by name
    -l, --list-readers       List the available readers and their
                             indices
    -n, --dont-connect       Don't connect to the card on startup
    -y, --dont-ask           Don't ask for confirmation for every
                             command run from the scriptfiles
    -i, --force-interactive  Force interactive mode after running
                             scripts from the command line
    -h, --help               This help
"""

OPTIONS = "nyih"
LONG_OPTIONS = ["dont-connect","dont-ask","force-interactive","help"]
exit_now = False
dont_connect = False
dont_ask = False
force_interactive = False
reader = None

if __name__ == "__main__":
    
    helper = readers.CommandLineArgumentHelper()
    
    (options, arguments) = helper.getopt(sys.argv[1:], OPTIONS, LONG_OPTIONS)
    
    for (option, value) in options:
        if option in ("-h","--help"):
            usage()
            exit_now = True
        if option in ("-n","--dont-connect"):
            dont_connect = True
        if option in ("-y","--dont-ask"):
            dont_ask = True
        if option in ("-i","--force-interactive"):
            force_interactive = True
    
    if exit_now:
        sys.exit()
    del exit_now
    
    print "Cyberflex shell"
    shell = Cyberflex_Shell("cyberflex-shell")
    
    if not dont_connect:
        shell.cmd_connect(helper.reader)
    
    shell.run_startup()
    
    for filename in arguments:
        shell.cmd_runscript(filename, not dont_ask)
    
    if len(arguments) == 0 or force_interactive:
        shell.run()
