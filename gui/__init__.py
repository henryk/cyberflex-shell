import gtk,gtk.glade,gobject

class PassportGUI:
    GLADE_FILE = "gui/passport/passport.glade"
    
    def __init__(self):
        "Create and show main window."
        self.passport = None
        self.main_window_xml = gtk.glade.XML(self.GLADE_FILE, "main")
        self.main_window = self.main_window_xml.get_widget("main")
    
    def run(self):
        gtk.gdk.threads_init()
        gtk.main()
    
    def set_passport(self, passport):
        self.passport = passport
