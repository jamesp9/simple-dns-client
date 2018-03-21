import subprocess
import unittest


class CheckSimpleDnsClient(unittest.TestCase):
    """
    """

    def setUp(self):
        """
        Use Google's DNS server to lookup my own domain which only has one ip
        address.
        """
        arguments = [
            'python', 'dns_client_original.py', 'jp-it.net.au', '8.8.8.8']
        self.completed_process = subprocess.run(
            arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.decoded_stdout = self.completed_process.stdout.decode().split('\n')

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
        self.assertEqual(response_answer, '52.62.133.15')