from generic_card import *

class Java_Card(Card):
    APDU_SELECT_APPLICATION = "\x00\xa4\x04\x00"
    DRIVER_NAME = "Generic Java"
    
    def __init__(self, card = None):
        Card.__init__(self, card = card)

    def select_application(self, aid):
        result = self.send_apdu(self.APDU_SELECT_APPLICATION + chr(len(aid)) + aid)
        return result
