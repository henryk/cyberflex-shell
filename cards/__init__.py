"""This package contains different card-specific modules.

The __init__.py file will automatically load all modules in the cards directory
and import all classes that have a DRIVER_NAME attribute. If you want to write
your own classes you should therefore make sure it has a DRIVER_NAME and then
put it in the same directory as the other classes. Preferably you should derive
from the generic_card.Card class."""

from sys import modules as _modules
from dircache import listdir as _listdir
from new import classobj as _classobj

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

def new_card_object(card):
    """Return a new object that will incorporate all classes that
    think that they can handle the given card. The object will always 
    contain the Card class."""
    
    card_classes = [Card]
    
    for card_class in dir(_modules[__name__]):
        card_class = getattr(_modules[__name__], card_class)
        
        if card_class in card_classes:
            continue
        
        if hasattr(card_class, "can_handle"):
            if card_class.can_handle(card):
                card_classes.append(card_class)
    
    return Cardmultiplexer( tuple(card_classes), card )

class Cardmultiplexer:
    """This class will provide an object that 'multiplexes' several card classes
    into one.
    
    This is somewhat different from multiple inheritance in that classes can 
    be dynamically added and removed from instances of this class. It also 
    provides support for merging some list and dictionary class attributes 
    of the participating classes instead of overriding them."""
    
    def __init__(self, classes, *args, **kwargs):
        """Creates a new Cardmultiplexer object. 
        
        The first positional argument must be a list of classes that you want
        to initially melt together.
        
        Any additional positional or keyword arguments that you give will be saved
        and provided to the __init__ methods of all classes that you add.
        (You may change the saved arguments at a later time with 
        set_init_arguments().)"""
        
        self._classes = []
        self._classes_needed = []
        self._init_args = args
        self._init_kwargs = kwargs
        
        self.add_classes(classes)
    
    
    def add_classes(self, classes):
        """Add some new classes to this Cardmultiplexer object. classes
        should be a sequence of class objects.
        
        Note that there are two tricky parts in this process:
            1. We wouldn't want to add superclasses of classes that
                already are here. This usually makes no sense, because 
                Python can handle the method resolution order in this 
                case for itself pretty fine.
            2. The way to get bound methods is kind of hackish:
                As soon as the list of classes changes we create a new
                class object incorporating all classes from _classes as
                well as this class (Cardmultiplexer) and then set our
                __class__ attribute to this new object."""
        
        (newcls, delcls) = self._update_classes(list(classes), [])
        for cls in newcls:
            cls.__init__(self, *self._init_args, **self._init_kwargs)
    
    def remove_classes(self, classes):
        """Remove classes from this Cardmultiplexer object."""
        (newcls, delcls) = self._update_classes([], list(classes))
    
    def _update_classes(self, addclasses, delclasses):
        """This handles the task of figuring out which classes to actually
        melt together. It uses two lists: new_classes and classes_needed:
        new_classes contains all the classes the user wishes to melt. Then
        classes will be continually added from new_classes to classes_needed
        unless there is already a subclass in this list. If a class is added
        then all superclasses of it will be removed from the list."""
        new_classes = self._classes + addclasses 
        for cls in delclasses:
            new_classes.remove(cls)
        
        classes_needed = []
        
        for new_class in new_classes:
            already_covered = False
            
            ## Check if this class is already covered by classes_needed
            for potential_sub in classes_needed:
                if issubclass(potential_sub, new_class):
                    already_covered = True
                    break
            
            if not already_covered:
                ## Remove all super classes of this class and then add the class itself
                classes_needed = [cls for cls in classes_needed 
                    if not issubclass(new_class, cls)]
                classes_needed.append(new_class)
        
        diffplus = [cls for cls in classes_needed if cls not in self._classes_needed]
        diffminus = [cls for cls in self._classes_needed if cls not in classes_needed]
        
        self._classes = new_classes
        self._classes_needed = classes_needed
        self.__class__ = _classobj("Cardmultiplexer (merged)", 
            tuple(classes_needed + [Cardmultiplexer]), {})
        return (diffplus,diffminus)
