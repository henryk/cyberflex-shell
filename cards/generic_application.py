import binascii, re, sys, cards

class Application:
    
    # This must be a sequence of regular expressions
    # When an application is selected through a matching AID
    # then all correponding classes are merged into the card
    # object.
    # The application classes themselves are responsible for
    # unmerging, should their application become deselected.
    # However, the default implementation in the generic
    # Application class which triggers unmerging on a card reset
    # and a successfull SELECT APPLICATION should be sufficient
    # in most cases.
    # (Still haven't thought this through, though...)
    ## FIXME Unloading is not implemented yet
    #
    # NOTE: Implementing classes MUST derive from Application
    AID_LIST = []
    
    def load_applications(card, aid):
        classes_to_load = []
        for i in dir(cards):
            possible_class = getattr(cards, i)
            if not hasattr(possible_class, "DRIVER_NAME") or not issubclass(possible_class, Application):
                continue
            if possible_class.can_handle_aid(card, aid):
                classes_to_load.append(possible_class)
                print ".oO(Loading application '%s')" % ", ".join(possible_class.DRIVER_NAME)
        
        card.add_classes(classes_to_load)
    load_applications = staticmethod(load_applications)
    
    def can_handle_aid(cls, card, aid):
        for i in cls.AID_LIST:
            if re.match(i+"$", binascii.b2a_hex(aid), re.I):
                return True
        return False
    can_handle_aid = classmethod(can_handle_aid)
