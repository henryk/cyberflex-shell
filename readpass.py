#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

from utils import pycsc
import utils, cards, TLV_utils, sys, binascii, time, traceback

OPTIONS = "G"
LONG_OPTIONS = ["no-gui"]

use_gui = True

if __name__ == "__main__":
    c = utils.CommandLineArgumentHelper()
    
    (options, arguments) = c.getopt(sys.argv[1:], OPTIONS, LONG_OPTIONS)
    
    for option, value in options:
        if option in ("-G","--no-gui"):
            use_gui = False
    
    pycsc_card = c.connect()
    card = cards.new_card_object(pycsc_card)
    cards.generic_card.DEBUG = False
    
    print >>sys.stderr, "Using %s" % card.DRIVER_NAME
    
    if len(arguments) > 1:
        p = cards.passport_application.Passport.from_card(card, arguments[:2])
    elif len(arguments) == 1:
        p = cards.passport_application.Passport.from_card(card, ["",arguments[0]])
    else:
        p = cards.passport_application.Passport.from_card(card)
    
    if use_gui:
        import gui
        
        g = gui.PassportGUI()
        g.set_passport(p)
        g.run()
