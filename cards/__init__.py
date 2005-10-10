"""This package contains different card-specific modules.

The __init__.py file will automatically load all modules in the cards directory
and import all classes that have a DRIVER_NAME attribute. If you want to write
your own classes you should therefore make sure it has a DRIVER_NAME and then
put it in the same directory as the other classes. Preferably you should derive
from the generic_card.Card class."""

from sys import modules as _modules
from dircache import listdir as _listdir

for filename in _listdir(_modules[__name__].__path__[0]):
    if filename[-3:].lower() == ".py":
        possible_module = filename[:-3]
        if possible_module.lower() == "__init__":
            continue
        try:
            module = __import__(possible_module, globals(), locals(), [])
            for possible_class in dir(module):
                if hasattr(getattr(module, possible_class), "DRIVER_NAME"):
                    setattr(_modules[__name__], possible_class, getattr(module, possible_class))
        except ImportError:
            pass


del filename, possible_module, module, possible_class

def find_class(ATR):
    """Find a card class that supports the card identified by ATR. 
    Returns the generic card class when no better match is found."""
    for card_class in dir(_modules[__name__]):
        card_class = getattr(_modules[__name__], card_class)
        if hasattr(card_class, "can_handle"):
            if card_class.can_handle(ATR):
                return card_class
    return Card
