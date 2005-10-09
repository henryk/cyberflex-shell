import utils, binascii
from generic_card import *
from utils import APDU

class Java_Card(Card):
    APDU_SELECT_APPLICATION = APDU("\x00\xa4\x04\x00")
    DRIVER_NAME = "Generic Java"
    APPLICATIONS = {
        "muscle": "\xa0\x00\x00\x00\x01\x01"
    }
    
    def __init__(self, card = None):
        Card.__init__(self, card = card)

    def select_application(self, aid):
        result = self.send_apdu(
            APDU(self.APDU_SELECT_APPLICATION,
            content = aid) )
        return result
    
    def cmd_selectapplication(self, application):
        """Select an application on the card. 
        application can be given either as hexadezimal aid or by symbolic name (if known)."""
        
        if self.APPLICATIONS.has_key(application):
            aid = self.APPLICATIONS[application]
        else:
            aid = binascii.a2b_hex("".join(application.split()))
        result = self.select_application(aid)
        if len(result) > 2:
            print utils.hexdump(result[:-2])
    
    COMMANDS = dict(Card.COMMANDS)
    COMMANDS.update( {
        "select_application": cmd_selectapplication
        } )
