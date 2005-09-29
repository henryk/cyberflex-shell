"""This package contains different card-specific modules."""
from generic_card import Card
from java_card import Java_Card
from cyberflex_card import Cyberflex_Card
from sys import modules

def find_class(ATR):
    """Find a card class that supports the card identified by ATR. 
    Returns the generic card class when no better match is found."""
    for card_class in dir(modules[__name__]):
        card_class = getattr(modules[__name__], card_class)
        if hasattr(card_class, "can_handle"):
            if card_class.can_handle(ATR):
                return card_class
    return Card
