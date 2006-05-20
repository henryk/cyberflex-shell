import utils
from iso_7816_4_card import *

class TCOS_Card(ISO_7816_4_Card):
    DRIVER_NAME = "TCOS"
    APDU_LIST_X = C_APDU("\x80\xaa\x01\x00\x00")
    APDU_READ_BINARY = C_APDU("\x00\xb0\x00\x00")
    
    def list_x(self, x):
        "Get a list of x objects, where x is one of 1 (DFs) or 2 (EFs)"
        result = self.send_apdu(C_APDU(self.APDU_LIST_X, p1=x))
        
        tail = result.data
        result_list = []
        while len(tail) > 0:
            head, tail = tail[:2], tail[2:]
            result_list.append(head)
        return result_list
    
    def read_binary_file(self, offset = 0):
        """Read from the currently selected EF.
        Repeat calls to READ BINARY as necessary to get the whole EF."""
        
        if offset >= 1<<15:
            raise ValueError, "offset is limited to 15 bits"
        contents = ""
        had_one = False
        
        while True:
            command = C_APDU(self.APDU_READ_BINARY, p1 = offset >> 8, p2 = (offset & 0xff), le = 0)
            result = self.send_apdu(command)
            if len(result.data) > 0:
                contents = contents + result.data
                offset = offset + len(result.data)
            
            if result.sw != self.SW_OK:
                break
            else:
                had_one = True
        
        if had_one: ## If there was at least one successful pass, ignore any error SW. It probably only means "end of file"
            self.sw_changed = False
        
        return contents
    
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
    
    def cmd_cd(self, dir = None):
        "Change into a DF, or into the MF if no dir is given"
        if dir is None:
            return self.cmd_selectfile("00", "00", "")
        else:
            return self.cmd_selectfile("01", "00", dir)
    
    def cmd_open(self, file):
        "Shortcut for 'select_file 02 00 file'"
        return self.cmd_selectfile("02", "00", file)
    
    def cmd_cat(self):
        "Print a hexdump of the currently selected file (e.g. consecutive READ BINARY)"
        contents = self.read_binary_file()
        self.last_result = R_APDU(contents + self.last_sw)
        print utils.hexdump(contents)
    
    ATRS = list(Card.ATRS)
    ATRS.extend( [
            ("3bba96008131865d0064057b0203318090007d", None),
        ] )
    
    COMMANDS = dict(ISO_7816_4_Card.COMMANDS)
    COMMANDS.update( {
        "list_dirs": cmd_listdirs,
        "list_files": cmd_listfiles,
        "ls": cmd_list,
        "cd": cmd_cd,
        "open": cmd_open,
        "cat": cmd_cat,
        } )
