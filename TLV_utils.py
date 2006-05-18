import binascii, utils

context_FCP = object()
context_FMD = object()
context_FCI = object()
recurse = object()
binary = object()
number = object()
ascii = object()

tags = {
    None: {
        0x62: (recurse, "File Control Parameters", context_FCP),
        0x64: (recurse, "File Management Data", context_FMD),
        0x6F: (recurse, "File Control Information", context_FCI),
        0x80: (number, "Number of data bytes in the file, excluding structural information"),
        0x81: (number, "Number of data bytes in the file, including structural information"),
        0x82: (binary, "File descriptor byte"),
        0x83: (binary, "File identifier"),
        0x84: (binary, "DF name"),
        0x85: (binary, "Proprietary information"),
        0x86: (binary, "Security attributes"),
        0x87: (binary, "Identifier of an EF containing an extension of the FCI"),
    },
}

def tvl_unpack(data):
    tag = ord(data[0])
    length = ord(data[1])
    value = data[2:(2+length)]
    rest = data[(2+length):]
    
    return tag, length, value, rest

def decode(data, context = None, level = 0):
    result = []
    while len(data) > 0:
        tag, length, value, data = tvl_unpack(data)
        
        interpretation = tags.get(context, tags.get(None, {})).get(tag, (binary, "Unknown"))
        current = ["\t"*level]
        current.append("Tag 0x%02X, Len 0x%02X, '%s':" % (tag, length, interpretation[1]))
        
        if interpretation[0] is recurse:
            current.append("\n")
            current.append( decode(value, interpretation[2], level+1) )
        elif interpretation[0] is number:
            num = 0
            for i in value:
                num = num * 256
                num = num + ord(i)
            current.append( " 0x%02x (%i)" % (num, num))
        elif interpretation[0] is ascii:
            current.append( " %s" % value)
        elif interpretation[0] is binary:
            current.append( " %s" % utils.hexdump(value, short=True))
        
        result.append( "".join(current) )
    
    return "\n".join(result)

if __name__ == "__main__":
    test = binascii.unhexlify("".join(("6f 2b 83 02 2f 00 81 02 01 00 82 03 05 41 26 85" \
        +"02 01 00 86 18 60 00 00 00 ff ff b2 00 00 00 ff" \
        +"ff dc 00 00 00 ff ff e4 10 00 00 ff ff").split()))
    
    decoded = decode(test)
    print decoded
