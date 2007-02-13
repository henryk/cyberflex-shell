import TLV_utils
from generic_card import *
from generic_application import Application

class ISO_7816_4_Card(Card):
    APDU_SELECT_APPLICATION = C_APDU(ins=0xa4,p1=0x04)
    APDU_SELECT_FILE = C_APDU(ins=0xa4)
    APDU_READ_BINARY = C_APDU(ins=0xb0,le=0)
    APDU_READ_RECORD = C_APDU(ins=0xb2,le=0)
    DRIVER_NAME = "ISO 7816-4"
    FID_MF = "\x3f\x00"
    
    SELECT_P2 = 0x0
    
##    def can_handle(cls, card):
##        return True
##    can_handle = classmethod(can_handle)

    def select_file(self, p1, p2, fid):
        result = self.send_apdu(
            C_APDU(self.APDU_SELECT_FILE,
            p1 = p1, p2 = p2,
            data = fid, le = 0) )
        return result
    
    def change_dir(self, fid = None):
        "Change to a child DF. Alternatively, change to MF if fid is None."
        if fid is None:
            return self.select_file(0x00, self.SELECT_P2, "")
        else:
            return self.select_file(0x01, self.SELECT_P2, fid)
    
    def cmd_cd(self, dir = None):
        "Change into a DF, or into the MF if no dir is given"
        
        if dir is None:
            result = self.change_dir()
        else:
            fid = binascii.a2b_hex("".join(dir.split()))
            result = self.change_dir(fid)
        
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data,tags=self.TLV_OBJECTS)
    
    def open_file(self, fid):
        "Open an EF under the current DF"
        return self.select_file(0x02, self.SELECT_P2, fid)
    
    def cmd_open(self, file):
        "Open a file"
        fid = binascii.a2b_hex("".join(file.split()))
        
        result = self.open_file(fid)
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data,tags=self.TLV_OBJECTS)

    def read_binary_file(self, offset = 0):
        """Read from the currently selected EF.
        Repeat calls to READ BINARY as necessary to get the whole EF."""
        
        if offset >= 1<<15:
            raise ValueError, "offset is limited to 15 bits"
        contents = ""
        had_one = False
        
        while True:
            command = C_APDU(self.APDU_READ_BINARY, p1 = offset >> 8, p2 = (offset & 0xff))
            result = self.send_apdu(command)
            if len(result.data) > 0:
                contents = contents + result.data
                offset = offset + len(result.data)
            
            if not self.check_sw(result.sw):
                break
            else:
                had_one = True
        
        if had_one: ## If there was at least one successful pass, ignore any error SW. It probably only means "end of file"
            self.sw_changed = False
        
        return contents
    
    def read_record(self, p1 = 0, p2 = 0, le = 0):
        "Read a record from the currently selected file"
        command = C_APDU(self.APDU_READ_RECORD, p1 = p1, p2 = p2, le = le)
        result = self.send_apdu(command)
        return result.data
    
    def cmd_cat(self):
        "Print a hexdump of the currently selected file (e.g. consecutive READ BINARY)"
        contents = self.read_binary_file()
        self.last_result = R_APDU(contents + self.last_sw)
        print utils.hexdump(contents)
    
    def cmd_read_record(self, p1 = None, p2 = None, le = "0"):
        "Read a record"
        if p1 is None and p2 is None:
            p1 = p2 = "0"
        elif p2 is None:
            p2 = "0x04" # Use record number in P1
        contents = self.read_record(p1 = int(p1,0), p2 = int(p2,0), le = int(le,0))
        print utils.hexdump(contents)
    
    def cmd_next_record(self, le = "0"):
        "Read the next record"
        return self.cmd_read_record(p1 = "0", p2 = "2", le = le)
    
    def cmd_selectfile(self, p1, p2, fid):
        """Select a file on the card."""
        
        p1 = binascii.a2b_hex("".join(p1.split()))
        p2 = binascii.a2b_hex("".join(p2.split()))
        fid = binascii.a2b_hex("".join(fid.split()))
        
        result = self.select_file(p1, p2, fid)
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data,tags=self.TLV_OBJECTS)
    
    def select_application(self, aid):
        result = self.send_apdu(
            C_APDU(self.APDU_SELECT_APPLICATION,
            data = aid, le = 0) ) ## FIXME With or without le
        if self.check_sw(result.sw):
            Application.load_applications(self, aid)
        return result
    
    def cmd_selectapplication(self, application):
        """Select an application on the card. 
        application can be given either as hexadecimal aid or by symbolic name (if known)."""
        
        s = [a for a,b in self.APPLICATIONS.items()
                if (b[0] is not None and b[0].lower() == application.lower())
                or (len(b) > 2 and application.lower() in [c.lower() for c in b[2].get("alias", [])])
            ]
        if len(s) > 0:
            aid = s[0]
        else:
            aid = binascii.a2b_hex("".join(application.split()))
        result = self.select_application(aid)
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data,tags=self.TLV_OBJECTS)
    
    ATRS = list(Card.ATRS)
    ATRS.extend( [
            (".*", None),   ## For now we accept any card
        ] )
    
    COMMANDS = dict(Card.COMMANDS)
    COMMANDS.update( {
        "select_application": cmd_selectapplication,
        "select_file": cmd_selectfile,
        "cd": cmd_cd,
        "cat": cmd_cat,
        "open": cmd_open,
        "read_record": cmd_read_record,
        "next_record": cmd_next_record,
        } )

    STATUS_WORDS = dict(Card.STATUS_WORDS)
    STATUS_WORDS.update( {
        "62??": "Warning, State of non-volatile memory unchanged",
        "63??": "Warning, State of non-volatile memory changed",
        "64??": "Error, State of non-volatile memory unchanged",
        "65??": "Error, State of non-volatile memory changed",
        "66??": "Reserved for security-related issues",
        "6700": "Wrong length",
        "68??": "Functions in CLA not supported",
        "69??": "Command not allowed",
        "6A??": "Wrong parameter(s) P1-P2",
        "6B00": "Wrong parameter(s) P1-P2",
        "6D00": "Instruction code not supported or invalid",
        "6E00": "Class not supported",
        "6F00": "No precise diagnosis",
        
        "6200": "Warning, State of non-volatile memory unchanged, No information given",
        "6281": "Warning, State of non-volatile memory unchanged, Part of returned data may be corrupted",
        "6282": "Warning, State of non-volatile memory unchanged, End of file/record reached before reading Le bytes",
        "6283": "Warning, State of non-volatile memory unchanged, Selected file invalidated",
        "6284": "Warning, State of non-volatile memory unchanged, FCI not formatted according to ISO-7816-4 5.1.5",
        
        "6300": "Warning, State of non-volatile memory changed, No information given",
        "6381": "Warning, State of non-volatile memory changed, File filled up by the last write",
        "63C?": lambda SW1,SW2: "Warning, State of non-volatile memory changed, Counter provided by '%i'" % (SW2%16),
        
        "6500": "Error, State of non-volatile memory changed, No information given",
        "6581": "Error, State of non-volatile memory changed, Memory failure",
        
        "6800": "Functions in CLA not supported, No information given",
        "6881": "Functions in CLA not supported, Logical channel not supported",
        "6882": "Functions in CLA not supported, Secure messaging not supported",
        
        "6900": "Command not allowed, No information given",
        "6981": "Command not allowed, Command incompatible with file structure",
        "6982": "Command not allowed, Security status not satisfied",
        "6983": "Command not allowed, Authentication method blocked",
        "6984": "Command not allowed, Referenced data invalidated",
        "6985": "Command not allowed, Conditions of use not satisfied",
        "6986": "Command not allowed, Command not allowed (no current EF)",
        "6987": "Command not allowed, Expected SM data objects missing",
        "6988": "Command not allowed, SM data objects incorrect",
        
        "6A00": "Wrong parameter(s) P1-P2, No information given",
        "6A80": "Wrong parameter(s) P1-P2, Incorrect parameters in the data field",
        "6A81": "Wrong parameter(s) P1-P2, Function not supported",
        "6A82": "Wrong parameter(s) P1-P2, File not found",
        "6A83": "Wrong parameter(s) P1-P2, Record not found",
        "6A84": "Wrong parameter(s) P1-P2, Not enough memory space in the file",
        "6A85": "Wrong parameter(s) P1-P2, Lc inconsistent with TLV structure",
        "6A86": "Wrong parameter(s) P1-P2, Incorrect parameters P1-P2",
        "6A87": "Wrong parameter(s) P1-P2, Lc inconsistent with P1-P2",
        "6A88": "Wrong parameter(s) P1-P2, Referenced data not found",
    } )
    
    TLV_OBJECTS = TLV_utils.tags
