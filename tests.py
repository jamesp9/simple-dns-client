import unittest

from dns_client import QueryDNS


GOOGLE_NAME_SERVER = '8.8.8.8'
JP_IT_IP_ADDRESS = '52.62.133.15'


class CheckSimpleDnsClient(unittest.TestCase):
    """
    """

    def setUp(self):
        """
        Use Google's DNS server to lookup my own domain which only has one ip
        address.
        """
        self.query_dns = QueryDNS('jp-it.net.au', GOOGLE_NAME_SERVER)

    def test_pack_header_fields(self):
        """
        """
        packed_header = self.query_dns.pack_header_fields(42, 0x100, 0, 0, 0, 0)
        self.assertEqual(packed_header,
                         b'\x00*\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def test_question_construction(self):
        """
        """
        packed_question = self.query_dns.construct_question()
        self.assertEqual(packed_question,
                         b'\x05jp-it\x03net\x02au\x00\x00\x01\x00\x01')

    def tearDown(self):
        """Close socket to clean up"""
        self.query_dns.close_socket()