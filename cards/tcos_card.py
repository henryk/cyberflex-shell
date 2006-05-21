import utils
from iso_7816_4_card import *

class TCOS_Card(ISO_7816_4_Card):
    DRIVER_NAME = "TCOS"
    APDU_LIST_X = C_APDU("\x80\xaa\x01\x00\x00")
    
    def list_x(self, x):
        "Get a list of x objects, where x is one of 1 (DFs) or 2 (EFs)"
        result = self.send_apdu(C_APDU(self.APDU_LIST_X, p1=x))
        
        tail = result.data
        result_list = []
        while len(tail) > 0:
            head, tail = tail[:2], tail[2:]
            result_list.append(head)
        return result_list
    
    def cmd_listdirs(self):
        "List DFs in current DF"
        result = self.list_x(1)
        print "DFs: " + ", ".join([utils.hexdump(a, short=True) for a in result])
    
    def cmd_listfiles(self):
        "List EFs in current DF"
        result = self.list_x(2)
        print "EFs: " + ", ".join([utils.hexdump(a, short=True) for a in result])
    
    def cmd_list(self):
        "List all EFs and DFs in current DF"
        dirs = self.list_x(1)
        files = self.list_x(2)
        self.sw_changed = False
        print "\n".join( ["[%s]" % utils.hexdump(a, short=True) for a in dirs]
            + [" %s " % utils.hexdump(a, short=True) for a in files] )
    
    ATRS = list(Card.ATRS)
    ATRS.extend( [
            ("3bba96008131865d0064057b0203318090007d", None),
        ] )
    
    COMMANDS = dict(ISO_7816_4_Card.COMMANDS)
    COMMANDS.update( {
        "list_dirs": cmd_listdirs,
        "list_files": cmd_listfiles,
        "ls": cmd_list,
        } )
