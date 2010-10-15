"""Unit test for utils.py"""

import utils
import unittest

class APDUCase1Tests(unittest.TestCase):
    
    def setUp(self):
        self.a4 = utils.C_APDU("\x00\xa4\x00\x00")
    
    def tearDown(self):
        del self.a4
    
    def testCreation(self):
        self.assertEqual(0, self.a4.CLA)
        self.assertEqual(0xa4, self.a4.INS)
        self.assertEqual(0, self.a4.P1)
        self.assertEqual(0, self.a4.P2)
    
    def testRender(self):
        self.assertEqual("\x00\xa4\x00\x00", self.a4.render())
    
    def testCopy(self):
        b0 = utils.C_APDU(self.a4, INS=0xb0)

        self.assertEqual("\x00\xb0\x00\x00", b0.render())
    
    def testAssign(self):
        self.a4.p2 = 5
        
        self.assertEqual(5, self.a4.P2)
        self.assertEqual("\x00\xa4\x00\x05", self.a4.render())
    
    def testCreateSequence(self):
        a4_2 = utils.C_APDU(0, 0xa4, 0, 0)
        
        self.assertEqual(self.a4.render(), a4_2.render())

