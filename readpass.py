#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import utils, cards, TLV_utils, sys, binascii, time, traceback

OPTIONS = "iGW:R:"
LONG_OPTIONS = ["interactive","no-gui", "write-files-basename", "read-files-basename"]

use_gui = True
write_files = None
read_files = None
start_interactive = False

if __name__ == "__main__":
    c = utils.CommandLineArgumentHelper()
    
    (options, arguments) = c.getopt(sys.argv[1:], OPTIONS, LONG_OPTIONS)
    
    for option, value in options:
        if option in ("-G","--no-gui"):
            use_gui = False
            start_interactive = False
        elif option in ("-W","--write-files-basename"):
            write_files = value
        elif option in ("-R","--read-files-basename"):
            read_files = value
        elif option in ("-i", "--interactive"):
            start_interactive = True
            use_gui = True
    
    if read_files is None and not start_interactive:
        card_object = c.connect()
        card = cards.new_card_object(card_object)
        cards.generic_card.DEBUG = False
        
        print >>sys.stderr, "Using %s" % card.DRIVER_NAME
        
        if len(arguments) > 1:
            p = cards.passport_application.Passport.from_card(card, arguments[:2])
        elif len(arguments) == 1:
            p = cards.passport_application.Passport.from_card(card, ["",arguments[0]])
        else:
            p = cards.passport_application.Passport.from_card(card)
    elif read_files is not None:
        p = cards.passport_application.Passport.from_files(basename=read_files)
    elif start_interactive:
        p = None
    
    if write_files is not None and not start_interactive:
        p.to_files(basename=write_files)
    
    if use_gui:
        import gui
        
        g = gui.PassportGUI()
        if p is not None:
            g.set_passport(p)
        else:
            g.clear_display()
        g.set_card_factory(c)
        g.run()
