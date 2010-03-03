import sys;sys.path.append(".."); sys.path.append(".")
import TLV_utils
from generic_card import *
from generic_application import Application
import building_blocks

class iso_node(object):
    SORT_NONE = False
    SORT_NORMAL = True
    SORT_DFFIRST = object() # Random object, just for identity testing
    
    def __init__(self, parent=None, management_information=None, card_object=None, generic_description=None):
        self._parent = parent
        self._management_information = management_information # FCI, FCP or FMD
        self._card_object = card_object
        self._children = []
        self._generic_description = generic_description # Note: Only used for iso_node, not for iso_ef or iso_df
        
        if self._parent is not None:
            self._parent.add_child(self)
            if self._card_object is None and self._parent._card_object is not None:
                self._card_object = self._parent._card_object
    
    def print_node(self, indent=0, stream=None,  stringlist=None,  **kwargs):
        result = self._format_node(indent, **kwargs)
        if stream is not None:
            stream.write("\n".join(result))
        elif stringlist is not None:
            stringlist.extend(result)
        else:
            print "\n".join(result)
        
        if kwargs.get("recurse", True):
            tosort = kwargs.get("sort", self.SORT_NONE)
            
            def cmp_normal(a,b): return cmp(a.fid,b.fid)
            def cmp_dffirst(a,b):
                return (a.__class__ != b.__class__) and (a.__class__ == iso_df and -1 or 1) or cmp(a.fid,b.fid)
            
            if tosort is self.SORT_DFFIRST:
                for child in sorted(self._children, cmp=cmp_dffirst):
                    child.print_node(indent+1, **kwargs)
            elif tosort:
                for child in sorted(self._children, cmp=cmp_normal):
                    child.print_node(indent+1, **kwargs)
            else:
                for child in self._children:
                    child.print_node(indent+1, **kwargs)

    def _dump_internal(self, data, indent, do_tlv=True):
        c = utils.hexdump(data)
        r = map(lambda a: self.get_indent(indent)+a, c.splitlines(False))
        if do_tlv:
            try:
                if self._card_object is not None:
                    c = TLV_utils.decode(data, tags=self._card_object.TLV_OBJECTS, context = self._card_object.DEFAULT_CONTEXT)
                else:
                    c = TLV_utils.decode(data)
                r.append( self.get_indent(indent) + "Trying TLV parse:" )
                r.extend( map(lambda a: self.get_indent(indent)+a, c.splitlines(False)) )
            except (SystemExit, KeyboardInterrupt):
                raise
            except:
                pass
        return r

    def _format_node(self, indent, **kwargs):
        result = []
        if self._generic_description:
            result.append(self.get_indent(indent) + "+ " + self._generic_description)
        else:
            result.append(self.get_indent(indent) + "+ Generic Node")
        if kwargs.get("with_management_information", True):
            result.extend(self._format_management_information(indent))
        return result
    
    def _format_management_information(self, indent):
        result = []
        if self._management_information is None: return result
        
        try:
            if self._card_object is not None:
                c = TLV_utils.decode(self._management_information, tags=self._card_object.TLV_OBJECTS, context = self._card_object.DEFAULT_CONTEXT)
            else:
                c = TLV_utils.decode(self._management_information)
            result.append(self.get_indent(indent+1) + "Management information:")
            result.extend( map(lambda a: self.get_indent(indent+2)+a, c.splitlines(False)) )
        except (SystemExit, KeyboardInterrupt):
            raise
        except:
            result.append(self.get_indent(indent+1) + "Raw dump of unparseable management information following:")
            result.extend(self._dump_internal(self._management_information, indent=indent+2, do_tlv=False))
        
        return result
    
    def add_child(self, node):
        raise NotImplementedError, "Can't add a child to a mere node"

    def get_fid(self): return self._fid
    def get_parent(self): return self._parent
    
    fid = property(get_fid)
    parent = property(get_parent)
    
    @staticmethod
    def get_indent(indent):
        return "\t"*indent

class iso_ef(iso_node):
    TYPE_TRANSPARENT = 1
    TYPE_RECORD = 2
    
    def __init__(self, fid, type=None, **kwargs):
        super(iso_ef, self).__init__(**kwargs)
        self._fid = fid
        self._content = None
        self._type = type
    
    def _format_node(self, indent, **kwargs):
        result = [self.get_indent(indent) + "+ EF: %s" % utils.hexdump(self.fid, short=True)]
        
        if kwargs.get("with_management_information", True):
            result.extend(self._format_management_information(indent))
        
        if kwargs.get("with_content", True) and self._content is not None:
            if self._type is self.TYPE_TRANSPARENT:
                result.append(self.get_indent(indent+1) + 
                    "Contents (length: %i (0x%0X)):" % (len(self._content),len(self._content)) 
                    )
                result.extend(self._dump_internal(self._content,indent=indent+2))
            elif self._type is self.TYPE_RECORD:
                result.append(self.get_indent(indent+1) + "%i (0x0%X) records following:" % (len(self._content),len(self._content)) )
                
                for i,d in enumerate(self._content):
                    result.append(self.get_indent(indent+2) + 
                        "Record %i (length: %i (0x%0X)):" % (i, len(d),len(d)) 
                        )
                    result.extend(self._dump_internal(d,indent=indent+3))
            else:
                result.append(self.get_indent(indent+1) + "Contents:")
                result.append(self.get_indent(indent+2) + repr(self._content))
        return result
    
class iso_df(iso_node):
    def __init__(self, fid, **kwargs):
        super(iso_df, self).__init__(**kwargs)
        self._fid = fid

    def _format_node(self, indent, **kwargs):
        result = [self.get_indent(indent) + "+ DF: %s" % utils.hexdump(self.fid, short=True)]
        if kwargs.get("with_management_information", True):
            result.extend(self._format_management_information(indent))
        return result

    def add_child(self, node):
        if node not in self._children:
            self._children.append(node)

class ISO_7816_4_Card(building_blocks.Card_with_read_binary,Card):
    APDU_SELECT_APPLICATION = C_APDU(ins=0xa4,p1=0x04)
    APDU_SELECT_FILE = C_APDU(ins=0xa4, le=0)
    APDU_READ_BINARY = C_APDU(ins=0xb0,le=0)
    APDU_READ_RECORD = C_APDU(ins=0xb2,le=0)
    DRIVER_NAME = ["ISO 7816-4"]
    FID_MF = "\x3f\x00"
    
    SELECT_FILE_P1 = 0x02
    SELECT_P2 = 0x0
    SELECT_FILE_LE = None
    
    EF_CLASS = iso_ef
    DF_CLASS = iso_df
    
##    def can_handle(cls, card):
##        return True
##    can_handle = classmethod(can_handle)

    def select_file(self, p1, p2, fid):
        result = self.send_apdu(
            C_APDU(self.APDU_SELECT_FILE,
            p1 = p1, p2 = p2,
            data = fid, le = self.SELECT_FILE_LE) )
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
    
    def open_file(self, fid, p2 = None):
        "Open an EF under the current DF"
        if p2 is None: p2 = self.SELECT_P2
        return self.select_file(self.SELECT_FILE_P1, p2, fid)
    
    def cmd_open(self, file):
        "Open a file"
        fid = binascii.a2b_hex("".join(file.split()))
        
        result = self.open_file(fid)
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data,tags=self.TLV_OBJECTS)
    
    def read_record(self, p1 = 0, p2 = 0, le = 0):
        "Read a record from the currently selected file"
        command = C_APDU(self.APDU_READ_RECORD, p1 = p1, p2 = p2, le = le)
        result = self.send_apdu(command)
        return result.data
    
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
    
    def select_application(self, aid, le=0, **kwargs):
        result = self.send_apdu(
            C_APDU(self.APDU_SELECT_APPLICATION,
            data = aid, le = le, **kwargs) ) ## FIXME With or without le
        if self.check_sw(result.sw):
            Application.load_applications(self, aid)
        return result
    
    def resolve_symbolic_aid(self, symbolic_name):
        "Returns symbolic_name, or if symbolic_name is a known symbolic_name then its corresponding aid."
        s = [a for a,b in self.APPLICATIONS.items()
                if (b[0] is not None and b[0].lower() == symbolic_name.lower())
                or (len(b) > 2 and symbolic_name.lower() in [c.lower() for c in b[2].get("alias", [])])
            ]
        if len(s) > 0:
            aid = s[0]
        else:
            aid = binascii.a2b_hex("".join(symbolic_name.split()))
        
        return aid
    
    def cmd_selectapplication(self, application):
        """Select an application on the card. 
        application can be given either as hexadecimal aid or by symbolic name (if known)."""
        
        aid = self.resolve_symbolic_aid(application)
        
        result = self.select_application(aid)
        if len(result.data) > 0:
            print utils.hexdump(result.data)
            print TLV_utils.decode(result.data,tags=self.TLV_OBJECTS)
    
    def cmd_pretendapplication(self, application):
        "Pretend that an application has been selected on the card without actually sending a SELECT APPLICATION. Basically for debugging purposes."
        aid = self.resolve_symbolic_aid(application)
        Application.load_applications(self, aid)
    
    ATRS = list(Card.ATRS)
    ATRS.extend( [
            (".*", None),   ## For now we accept any card
        ] )
    
    STOP_ATRS = list(Card.STOP_ATRS)
    STOP_ATRS.extend( [
            ("3b8f8001804f0ca000000306......00000000..", None), # Contactless storage cards (PC/SC spec part 3 section 3.1.3.2.3
            ("3b8180018080", None), # Mifare DESfire (special case of contactless smartcard, ibid.)
        ] )
    
    COMMANDS = dict(Card.COMMANDS)
    COMMANDS.update(building_blocks.Card_with_read_binary.COMMANDS)
    COMMANDS.update( {
        "select_application": cmd_selectapplication,
        "pretend_application": cmd_pretendapplication,
        "select_file": cmd_selectfile,
        "cd": cmd_cd,
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

if __name__ == "__main__":
    
    root = iso_df('\x3f\x00')
    ef_one = iso_ef('\xb0\x01', parent=root, type=iso_ef.TYPE_TRANSPARENT, management_information="he")
    ef_two = iso_ef('\xa0\x00', parent=root, type=iso_ef.TYPE_RECORD, management_information="h")
    df_one = iso_df('\xa0\x01', parent=root)
    df_two = iso_df('\xa0\x00', parent=df_one)
    ef_three = iso_ef('\x00\x03', parent=df_one, type=iso_ef.TYPE_RECORD)
    ef_four = iso_ef('\x00\x04', parent=df_one)
    ef_five = iso_ef('\x00\x05', parent=df_two)
    df_three = iso_df('\xa0\x00', parent=df_one)
    
    ef_one._content = "Foobaluhahihohoahajabla"
    ef_two._content = ("bla", "bli", "blu")
    ef_three._content = ("Foobaluhahihohoahajabla",)
    
    root.print_node(sort=root.SORT_DFFIRST)
