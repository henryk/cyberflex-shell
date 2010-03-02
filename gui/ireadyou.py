#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

import gtk,gtk.glade,gobject
import sys, os, time
try:
    import utils, TLV_utils, cards, readers
except ImportError, e:
    try:
        sys.path.append(".")
        import utils, TLV_utils, cards, readers
    except ImportError:
        raise e

from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.ReaderMonitoring import ReaderMonitor, ReaderObserver
import smartcard

class FileLikeTextBuffer(object):
    def __init__(self):
        self.had_newline = True
        self.buffer = gtk.TextBuffer()
        self.endmark = self.buffer.create_mark("The End", self.buffer.get_end_iter(), False)
        self.views = []
    
    def add_view(self, v):
        self.views.append(v)
        v.scroll_mark_onscreen( self.endmark )
    
    def writelines(self, sequence):
        for s in sequence: self.write(s)
    
    def write(self, s):
        d = "%s: " % time.strftime("%F %T")
        
        parts = s.split("\n")
        if self.had_newline:
            self.had_newline = False
            s = d
        else:
            s = ""
        
        if parts[-1] == '':
            del parts[-1]
            self.had_newline = True
        
        s = s + ("\n"+d).join(parts)
        if self.had_newline: s = s + "\n"
        
        self.buffer.insert( self.buffer.get_end_iter(), s)
        for v in self.views:
            v.scroll_mark_onscreen( self.endmark )
    
    def flush(self): pass
    
    def for_stream(self, stream):
        class stream_to_buf(object):
            def __init__(self, parent, stream):
                self.parent = parent
                self.stream = stream
            
            def flush(self):
                self.parent.flush()
                self.stream.flush()
            
            def write(self, s):
                self.parent.write(s)
                self.stream.write(s)
            
            def writelines(self, s):
                self.parent.writelines(s)
                self.stream.writelines(s)
        
        return stream_to_buf(self, stream)

class ireadyou(object,CardObserver,ReaderObserver):
    GLADE_FILE = "gui/ireadyou/ireadyou.glade"
    
    def __init__(self, ticket = None):
        "Create and show main window."
        self.main_window_xml = gtk.glade.XML(self.GLADE_FILE, "main")
        self.main_window = self.main_window_xml.get_widget("main")
        
        self.card_tabs = self.main_window_xml.get_widget("card_tabs")
        while self.card_tabs.get_n_pages() > 0:
            self.card_tabs.remove_page(0)
        for t in self.CARD_TYPES:
            a, b, l = gtk.Alignment(yscale=1,xscale=1,xalign=0.5,yalign=0.5), gtk.VBox(), gtk.Label(t[1])
            a.add(b)
            a.show()
            b.show()
            l.show()
            
            self.card_tabs.append_page(a, tab_label=l)
        
        self.ticket_button_group = gtk.RadioButton()
        self.ticket_button_group._ticket = None
        
        self.status_area = self.main_window_xml.get_widget("status_area")
        self.known_readers = []
        self.known_cards = {} # Note stupid: the keys to this dict are not objects from the known_readers list but rather reader name strings
        self.connected_cards = {} # Again: the keys are not cards but repr(card)
        self.tickets = {} # ditto
        self.ticket_displayed = None # This is either None or a tuple (card object, ticket object)
        
        self._update_status()
        
        self.logbuf = FileLikeTextBuffer()
        sys.stdout = self.logbuf.for_stream(sys.stdout)
        sys.stderr = self.logbuf.for_stream(sys.stderr)
        self.logview = self.main_window_xml.get_widget("logview")
        self.logview.set_buffer(self.logbuf.buffer)
        self.logbuf.add_view(self.logview)
        
        signals = {
            "on_exit_clicked": self.exit_clicked,
            "on_main_delete_event": self.exit_clicked,
            "on_main_destroy": gtk.main_quit,
        }
        self.main_window_xml.signal_autoconnect(signals)
        
        self._clear_display()
        
        self.rmon = ReaderMonitor()
        self.cmon = CardMonitor()
        
        self.rmon.addObserver(self)
        self.cmon.addObserver(self)
    
    def _clear_display(self):
        self.card_tabs.set_current_page(0)
        
        for i in range(self.card_tabs.get_n_pages()):
            a = self.card_tabs.get_nth_page(i)
            vbox = a.get_child()
            for c in vbox.get_children():
                vbox.remove(c)
            label = self.card_tabs.get_tab_label(a)
            label.set_property("sensitive", False)
    
    def _update_status(self):
        for c in self.status_area.get_children():
            self.status_area.remove(c)
        
        if len(self.known_readers) == 0:
            self.status_area.add( gtk.Label(u"Keine Lesegeräte angeschlossen.") )
        else:
            for reader in self.known_readers:
                frame = gtk.Frame(label=str(reader))
                
                if len(self.known_cards[ reader.name ]) == 0:
                    frame.add( gtk.Label(u"Keine Karten verbunden.") )
                else:
                    vbox = gtk.VBox()
                    for card in self.known_cards[ reader.name ]:
                        if self.connected_cards.has_key(repr(card)):
                            card_ = self.connected_cards[ repr(card) ]
                            cardname = card_.get_driver_name()
                        else:
                            cardname = str(card)
                        
                        hbox = gtk.HBox()
                        cardlabel = gtk.Label( "<b>%s</b>: " % cardname )
                        cardlabel.set_use_markup(True)
                        hbox.pack_start(cardlabel, expand=False)
                        
                        vbox2 = gtk.VBox()
                        hbox.pack_start(vbox2, expand=True)
                        for ticket in self.tickets[ repr(card) ]:
                            button = gtk.RadioButton(group=self.ticket_button_group, label=str(ticket), use_underline=False)
                            vbox2.pack_start(button, expand=False)
                            
                            button.connect("toggled", self._ticket_button_toggled)
                            button._ticket = (card, ticket)
                            
                            if self.ticket_displayed is not None and ticket == self.ticket_displayed[1]:
                                button.set_active(True)
                        
                        vbox.add(hbox)
                    frame.add(vbox)
                
                self.status_area.add(frame)
        
        self.status_area.show_all()
    
    def _format_datum(d):
        return d.strftime("%x")
    
    CARD_TYPES = [
        (("SCHUL_T",),  
            "Schulticket", (
                ("Name", "name_klar", None),
                ("Alter", "alter", None),
                ("Geburtsdatum", "geburtsdatum", _format_datum),
                ("Schule", "schule", None),
                (u"Kartengültigkeit", "gueltigkeit", None),
            ),
        ),
        (("JOBT_ERW",), 
            "Jobticket",  (
                ("Name", "name_klar", None),
                ("Geburtsdatum", "geburtsdatum", _format_datum),
                (u"Kartengültigkeit", "gueltigkeit", None),
            ),
        ),
        (("MT_ABO",),   
            "Monatsabo", (
                ("Abo-Nummer", "abonr", None),
                (u"Kartengültigkeit", "gueltigkeit", None),
            ),
        ),
        (None,          
            "Anderes", (
            ),
        ),
    ]
    
    def _ticket_button_toggled(self, togglebutton):
        self.ticket_displayed = None
        for b in togglebutton.get_group():
            if b.get_active():
                if hasattr(b, "_ticket"):
                    self.ticket_displayed = b._ticket
        self._update_ticket_display()
    
    def _update_ticket_display(self):
        self._clear_display()
        if self.ticket_displayed is None:
            return
        
        todisplay = self.ticket_displayed[1]
        
        for i,t in enumerate(self.CARD_TYPES):
            if todisplay.tickettyp in t[0]:
                break
            # Note: implicit selection of the last card type when no match is found
        
        self.card_tabs.set_current_page(i)
        a = self.card_tabs.get_nth_page(i)
        vbox = a.get_child()
        label = self.card_tabs.get_tab_label(a)
        label.set_property("sensitive", True)
        
        for labeltext, propertyname, transformation in t[2]:
            frame = gtk.Frame(label=labeltext)
            content = getattr(todisplay, propertyname, None)
            contenttext = str( transformation is not None and transformation(content) or content )
            contentlabel = gtk.Label("<b><tt><big>%s</big></tt></b>" % contenttext)
            contentlabel.set_use_markup(True)
            contentlabel.show()
            frame.add( contentlabel )
            frame.show()
            
            vbox.add(frame)
    
    def exit_clicked(self, widget, event=None, data=None):
        gtk.main_quit()
        return True
    
    def run(self):
        gtk.main()
    
    # From the CardObserver and ReaderObserver classes
    def update( self, observable, (added, removed) ):
        try:
            gtk.gdk.threads_enter()
            #print observable, added, removed
            if observable is self.rmon.instance:
                self.reader_update(observable, (added, removed) )
            elif observable is self.cmon.instance:
                self.card_update(observable, (added, removed) )
            self._update_status()
            self._update_ticket_display()
        finally:
            gtk.gdk.threads_leave()
    
    def reader_update( self, observable, (added, removed) ):
        for r in removed:
            if r in self.known_readers:
                for card in list(self.known_cards[ r.name ]):
                    self._remove_card(card)
                assert len(self.known_cards[ r.name ]) == 0
                del self.known_cards[ r.name ]
                self.known_readers.remove(r)
        for a in added:
            if a not in self.known_readers:
                self.known_readers.append(a)
                self.known_cards[ a.name ] = []
    
    def card_update( self, observable, (added, removed) ):
        for r in removed:
            if not self.known_cards.has_key(r.reader): continue
            if r in self.known_cards[r.reader]:
                self._remove_card(r)
        for a in added:
            if not self.known_cards.has_key(a.reader): continue
            if a not in self.known_cards[a.reader]:
                self._add_card(a)
    
    def _add_card(self, card):
        self.known_cards[ card.reader ].append(card)
        if not self.tickets.has_key( repr(card) ):
            self.tickets[ repr(card) ] = []
        
        conn = card.createConnection()
        connected = False
        try:
            conn.connect()
            connected = True
        except smartcard.Exceptions.NoCardException, e:
            pass
        
        if connected:
            card_ = cards.new_card_object(conn)
            cards.generic_card.DEBUG = False
            self.connected_cards[ repr(card) ] = card_
            
            for i in range(1,9):
                try:
                    ticket = cards.vrs_application.VrsTicket.from_card(card_, record_no = i)
                    print "Loaded ticket '%s' from record %i" % (ticket, i)
                    self._add_ticket(card, ticket)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception,e:
                    if not str(e).startswith("'No ticket in record no."):
                        print e
                
                if not isinstance(card_, cards.vrs_application.VRS_Application):
                    break
    
    def _remove_card(self, card):
        if self.tickets.has_key( repr(card) ):
            for t in list(self.tickets[ repr(card) ]):
                self._remove_ticket(card, t)
            assert len(self.tickets[ repr(card) ]) == 0
            del self.tickets[ repr(card) ]
        
        if self.connected_cards.has_key( repr(card) ):
            try:
                self.connected_cards[ repr(card) ].close_card()
            except smartcard.Exceptions.CardConnectionException, e:
                pass
            
            del self.connected_cards[ repr(card) ]
        self.known_cards[ card.reader ].remove(card)
    
    def _add_ticket(self, card, ticket):
        self.tickets[ repr(card) ].append( ticket )
        if self.ticket_displayed is None:
            self.ticket_displayed = ( card, ticket )
    
    def _remove_ticket(self, card, ticket):
        if self.ticket_displayed is not None and self.ticket_displayed[1] == ticket:
            self.ticket_displayed = None
            # TODO: Find a different ticket to display
        self.tickets[ repr(card) ].remove(ticket)

OPTIONS = ""
LONG_OPTIONS = []

if __name__ == "__main__":
##    c = readers.CommandLineArgumentHelper()
##    
##    (options, arguments) = c.getopt(sys.argv[1:], OPTIONS, LONG_OPTIONS)
##    
##    card_object = c.connect()
##    card = cards.new_card_object(card_object)
##    #cards.generic_card.DEBUG = False
##    
##    print >>sys.stderr, "Using %s" % card.DRIVER_NAME
##    
##    if len(arguments) > 0:
##        ticket = cards.vrs_application.VrsTicket.from_card(card, record_no = int(arguments[0], 0))
##    else:
##        ticket = cards.vrs_application.VrsTicket.from_card(card)
    
    gtk.gdk.threads_init()
    g = ireadyou()
    g.run()
