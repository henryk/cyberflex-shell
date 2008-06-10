import gtk,gtk.glade,gobject
import sys, os, time, TLV_utils, cards

class Converter:
    SUPPORTS = ["jp2"]
    MAXSIZE = 400
    
    def convert(type, image_data):
        stdin, stdout = os.popen2("convert %s:- -resize %sx%s bmp:-" % (type, Converter.MAXSIZE, Converter.MAXSIZE))
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
        self.card_factory = None
        
        signals = {
            "on_exit_clicked": self.exit_clicked,
            "on_clear_clicked": self.clear_clicked,
            "on_open_clicked": self.open_clicked,
            "on_main_delete_event": self.exit_clicked,
            "on_main_destroy": gtk.main_quit,
            "on_next_image_clicked": self.next_image,
            "on_prev_image_clicked": self.prev_image,
            "on_mrz_entry1_activate": self.mrz1_activate,
            "on_mrz_entry2_activate": self.mrz2_activate,
        }
        self.main_window_xml.signal_autoconnect(signals)
    
    def mrz1_activate(self, widget, event=None, data=None):
        self.main_window_xml.get_widget("mrz_entry2").grab_focus()
    
    def mrz2_activate(self, widget, event=None, data=None):
        self.main_window_xml.get_widget("open").clicked()
        self.main_window_xml.get_widget("mrz_entry1").grab_focus()
    
    def exit_clicked(self, widget, event=None, data=None):
        gtk.main_quit()
        return True
    
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
                data = data + [(a,b,"Encoded Face") for (a,b) in biometric.get_images()]
        
        for dg, tag, type in ( ("dg5", 0x5F40, "Displayed Portrait"), ("dg7", 0x5F43, "Displayed Signature or Usual Mark") ):
            if hasattr(passport, "%s_tlv" % dg):
                structure = getattr(passport, "%s_tlv" % dg)
                if structure is not None:
                    hits = TLV_utils.tlv_find_tag(structure, tag)
                    for t,l,v in hits:
                        data.append( ("jpg",v,type) )
        
        self._set_images(data)
    
    def clear_display(self):
        for sources, transform, destinations in self.PROPERTY_TRANSFORMATIONS:
            for index, dst in enumerate(destinations):
                widget = self.main_window_xml.get_widget(dst)
                if not self.format_strings.has_key(dst):
                    self.format_strings[dst] = widget.get_label()
                widget.set_label( "" )
        self._set_images([])
        self.main_window_xml.get_widget("mrz_entry1").set_text("")
        self.main_window_xml.get_widget("mrz_entry2").set_text("")
        self.update_image_shown()
    
    def clear_clicked(self, widget, event=None, data=None):
        self.clear_display()
    
    def open_clicked(self, widget, event=None, data=None):
        mrz1 = self.main_window_xml.get_widget("mrz_entry1").get_text()
        mrz2 = self.main_window_xml.get_widget("mrz_entry2").get_text()
        mrz = [e.strip().upper().replace(";","<") for e in mrz1, mrz2]
        
        self.clear_display()
        
        self.main_window_xml.get_widget("mrz_entry1").set_text(mrz[0])
        self.main_window_xml.get_widget("mrz_entry2").set_text(mrz[1])
        
        while gtk.events_pending():
            gtk.main_iteration_do(block=False)
        
        if self.card_factory:
            try:
                card_object = self.card_factory.connect()
                card = cards.new_card_object(card_object)
                cards.generic_card.DEBUG = False
                
                print >>sys.stderr, "Using %s" % card.DRIVER_NAME
                
                p = cards.passport_application.Passport.from_card(card, mrz)
                
                self.set_passport(p)
            except KeyboardInterrupt,SystemExit: raise
            except:
                import traceback
                traceback.print_exc()
    
    def set_card_factory(self, c):
        self.card_factory = c
    
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
    
    def update_image_shown(self, add=0):
        self.now_showing = self.now_showing + add
        
        if self.now_showing >= len(self.images):
            self.now_showing = len(self.images)-1
        if self.now_showing < 0:
            self.now_showing = 0
        
        if len(self.images) > 0:
            pixbuf, description = self.images[self.now_showing]
        else:
            pixbuf, description = None, "No image loaded"
        
        label = self.main_window_xml.get_widget("image_label")
        if not self.format_strings.has_key("image_label"):
            self.format_strings["image_label"] = label.get_label()
        label.set_label( self.format_strings["image_label"] % {
            "num": len(self.images) > 0 and (self.now_showing+1) or 0,
            "count": len(self.images),
            "description": description,
        } )
        
        if not self.format_strings.has_key("image"):
            self.format_strings["image"] = self.main_window_xml.get_widget("image").get_stock()
        
        if pixbuf is not None:
            self.main_window_xml.get_widget("image").set_from_pixbuf(pixbuf)
        else:
            self.main_window_xml.get_widget("image").set_from_stock(*self.format_strings["image"])
        
        self.main_window_xml.get_widget("prev_image").set_property("sensitive", self.now_showing > 0)
        self.main_window_xml.get_widget("next_image").set_property("sensitive", self.now_showing < len(self.images)-1)
    
    def next_image(self, widget):
        self.update_image_shown(+1)
    
    def prev_image(self, widget):
        self.update_image_shown(-1)
