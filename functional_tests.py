import unittest

from dns_client import QueryDNS


GOOGLE_NAME_SERVER = '8.8.8.8'
JP_IT_IP_ADDRESS = '52.62.133.15'


class CheckSimpleDnsClient(unittest.TestCase):
    """
    Basic function test.
    """

    def setUp(self):
        """
        Use Google's DNS server to lookup my own domain which only has one ip
        address.
        """
        query_dns = QueryDNS('jp-it.net.au', GOOGLE_NAME_SERVER)
        self.decoded_stdout = query_dns.main().split('\n')

    def test_number_of_answers(self):
        """
        Check an answer of 1 is returned
        """
        response_num_answers = self.decoded_stdout[6]
        self.assertEqual(response_num_answers, 'Number of Answers: 1')

    def test_domain_answer(self):
        """
        Check the answer returned by the DNS server.
        """
        response_answer = self.decoded_stdout[7]
        self.assertEqual(response_answer, JP_IT_IP_ADDRESS)