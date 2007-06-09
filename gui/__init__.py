import gtk,gtk.glade,gobject
import os, time

class Converter:
    SUPPORTS = ["jp2"]
    
    def convert(type, image_data):
        stdin, stdout = os.popen2("convert %s:- bmp:-" % type)
        n = time.time()
        stdin.write(image_data)
        stdin.close()
        return_data = stdout.read()
        stdout.close()
        #print "Took", time.time()-n, "seconds for conversion"
        return return_data
    convert = staticmethod(convert)

class PassportGUI:
    GLADE_FILE = "gui/passport/passport.glade"
    
    def __init__(self):
        "Create and show main window."
        self.passport = None
        self.format_strings = {}
        self.images = []
        self.now_showing = 0
        self.main_window_xml = gtk.glade.XML(self.GLADE_FILE, "main")
        self.main_window = self.main_window_xml.get_widget("main")
    
    def run(self):
        gtk.gdk.threads_init()
        gtk.main()
    
    def lookup_country(passport, contents):
        return passport.COUNTRY_CODES.get( contents[0], ("Unknown Code", "") )
    
    def split_name(passport, contents):
        return (contents[0][0], " ".join(contents[0][1:]))
    
    def parse_date(passport, contents):
        year, month, day = int(contents[0][0:2]), int(contents[0][2:4]), int(contents[0][4:6])
        if year < 30: # Yeah, two-digit years for the win!
            year = 2000 + year
        else:
            year = 1900 + year
        
        return ("%04i-%02i-%02i" % (year, month, day), )
    
    def format_mrz(passport, contents):
        mrz = contents[0]
        if contents[1] is not None:
            mrz = contents[1]
        
        return [e.replace("<","&lt;") for e in mrz]
    
    s = lambda a,b: (str(b[0]),)
    PROPERTY_TRANSFORMATIONS = [
        # This code implies an m:n relation from passport object properties to
        # displayed fields. This is a sequence of ( (passport_field, ...) transform_callable, (destination_field, ...))
        # transform_callable will be called with a reference to the passport and a list of the values of (passport_field, ...)
        # and must return len( (destination_field, ...) ) values wich will then be displayed in the corresponding
        # destination fields.
        
        ( ("type",), s, ("type",)),
        ( ("issuer",), s, ("issuer",)),
        ( ("issuer",), lookup_country, ("issuer_clear1", "issuer_clear2")),
        ( ("name",), split_name, ("surname", "firstname")),
        ( ("document_no",), s, ("document_no",)),
        ( ("nationality",), s, ("nationality",)),
        ( ("nationality",), lookup_country, ("nationality_clear1", "nationality_clear2")),
        ( ("date_of_birth",), parse_date,  ("dob",)),
        ( ("sex",), s,  ("sex",)),
        ( ("expiration_date",), parse_date, ("doe",)),
        ( ("optional",), s,  ("optional",)),
        ( ("given_mrz", "dg1_mrz"), format_mrz, ("mrz1", "mrz2") ),
    ]
    del s
    
    def set_passport(self, passport):
        self.passport = passport
        
        for sources, transform, destinations in self.PROPERTY_TRANSFORMATIONS:
            values = [getattr(passport, src) for src in sources]
            transformed = transform(passport, values)
            for index, dst in enumerate(destinations):
                widget = self.main_window_xml.get_widget(dst)
                if not self.format_strings.has_key(dst):
                    self.format_strings[dst] = widget.get_label()
                widget.set_label( self.format_strings[dst] % transformed[index] )
        
        data = []
        if hasattr(passport, "dg2_cbeff") and passport.dg2_cbeff is not None:
            for biometric in passport.dg2_cbeff.biometrics:
                data = data + [(a,b,"Encoded Face") for (a,b) in biometric.get_data()]
        
        self._set_images(data)
    
    def _set_images(self, data):
        self.images = []
        for type, image_data, description in data:
            if type in Converter.SUPPORTS:
                image_data = Converter.convert(type, image_data)
            
            loader = gtk.gdk.PixbufLoader()
            loader.write(image_data)
            loader.close()
            pixbuf = loader.get_pixbuf()
            
            self.images.append( (pixbuf, description) )
        
        self.update_image_shown()
    
    def update_image_shown(self):
        if self.now_showing >= len(self.images):
            self.now_showing = len(self.images)-1
        
        if len(self.images) > 0:
            pixbuf, description = self.images[self.now_showing]
        else:
            self.now_showing = 0
            pixbuf, description = None, "No image loaded"
        
        label = self.main_window_xml.get_widget("image_label")
        if not self.format_strings.has_key("image_label"):
            self.format_strings["image_label"] = label.get_label()
        label.set_label( self.format_strings["image_label"] % {
            "num": len(self.images) > 0 and (self.now_showing+1) or 0,
            "count": len(self.images),
            "description": description,
        } )
        
        if pixbuf is not None:
            self.main_window_xml.get_widget("image").set_from_pixbuf(pixbuf)
