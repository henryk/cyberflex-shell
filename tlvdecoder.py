#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

from TLV_utils import *
import binascii, sys

if __name__ == "__main__":
    a = binascii.unhexlify("".join( sys.stdin.read().split() ))
    print decode(a)
