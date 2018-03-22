"""
Basic DNS client based on information from:
RFC 1035 - Domain names - Implementation and Specification
"""
import random
import socket
import struct
import sys

PORT = 53
MAX_LABEL_OCTETS = 63
MAX_NAME_OCTETS = 255
MAX_OCTETS_FOR_UDP_MESSAGE = 512
HEADER_SIZE_BYTES = 12


class QueryDNS:
    """
    Class to Query DNS with UDP packets.
    """
    OUTPUT = ''

    def __init__(self, hostname, dnsserver):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        random.seed(9)
        self.hostname = hostname
        self.dnsserver = dnsserver
        self.identifier = None

    def print_output(self, text):
        """
        Catch the printed output of original program
        """
        self.OUTPUT += text + '\n'

    @staticmethod
    def pack_header_fields(id, flags, question_count=1, answer_count=0,
                           name_server_count=0, additional_record_count=0):
        """
                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        Pack bits in MSB (big-endian '>')
        h 	short integer 	2 bytes
        H 	unsigned short integer 	2 bytes

        Returns a bytestring
        """
        return struct.pack('>hhHHHH', id, flags, question_count, answer_count,
                           name_server_count, additional_record_count)

    def construct_question(self, qtype=1, qclass=1):
        """
        Construct the Question portion of the message. Contains QDCOUNT
        number of queries.

        Arguments:
            qtype - record type (1 = A record)
            qclass - 1 = IN (the Internet)

                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                     QNAME                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QTYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QCLASS                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        Pack bits in MSB (big-endian '>')

        Returns a byte string
        """
        qname = b''
        for label in self.hostname.split('.'):
            label_length = len(label)
            if label_length > MAX_LABEL_OCTETS:
                self.print_output(
                    'Please check domain name. Label {0} is greater than {1}'
                    ' octets.'.format(label, MAX_LABEL_OCTETS))
                sys.exit(1)
            # A length octet followed by that many octets
            packed_label = struct.pack('>B{0}s'.format(label_length),
                                       label_length, label.encode('ascii'))
            qname += packed_label

        # Terminate qname with a zero length octet
        qname = struct.pack(">{0}sB".format(len(qname)), qname, 0)

        if len(qname) > MAX_NAME_OCTETS:
            self.print_output('Query name has breached the size limit, of {}'
                              ' octets.'.format(MAX_NAME_OCTETS))
            sys.exit(2)

        return struct.pack('>{0}sHH'.format(len(qname)), qname, qclass, qtype)

    def receive_response(self):
        """
        Wait for the DNS query response, will exit if response takes longer
        that 2 seconds.
        Returns a byte string of UDP data.
        """
        delay = 0.1
        while True:
            self.udp_sock.settimeout(delay)
            try:
                data = self.udp_sock.recv(MAX_OCTETS_FOR_UDP_MESSAGE)
            except socket.timeout:
                delay *= 2  # exponential back off
                if delay > 2.0:
                    self.print_output("Delay is more than 2.0 seconds.")
                    self.close_socket()
                    sys.exit(3)
            except Exception as e:
                self.print_output("A further exception occurred: {}".format(e))
            else:
                break

        return data

    @staticmethod
    def unpack_header_fields(response_data):
        """
                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        """
        # The header is 6 short integers
        field_values = struct.unpack('>HHHHHH', response_data[:HEADER_SIZE_BYTES])
        return {
            'identifier': field_values[0],
            'flags': field_values[1],
            'qd_count': field_values[2],
            'an_count': field_values[3],
            'ns_count': field_values[4],
            'ar_count': field_values[5],
        }

    @staticmethod
    def decipher_header_flags(values):
        """
        Get all the fields values out of the Header
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        """
        response_codes = {
            '0': 'No Error',
            '1': 'Format error',
            '2': 'Server failure',
            '3': 'Name Error',
            '4': 'Not Implemented',
            '5': 'Refused',
        }
        rcode = values & 0x000F
        if str(rcode) in response_codes.keys():
            response_code = (rcode, response_codes[str(rcode)])
        elif 6 <= rcode <= 15:
            response_code = (rcode, 'Reserved for future use')

        flags = {
            'recursion_available': 1 if values & 0x0080 == 128 else 0,
            'response_code': response_code,

        }

        return flags

    @staticmethod
    def get_question_section(response_data):
        """
        Question Section
                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                     QNAME                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QTYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QCLASS                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        """
        offset = HEADER_SIZE_BYTES
        section = {}
        # QNAME
        labels = []
        while True:
            length_octet = response_data[offset]
            offset += 1
            # The domain name terminates with the zero length octet
            if length_octet == 0:
                break

            label = response_data[offset:offset + length_octet]
            labels.append(label.decode())
            offset += length_octet

        section['qname'] = '.'.join(labels)

        # QTYPE
        section['qtype'] = response_data[offset: offset + 2]
        offset += 2

        # QCLASS
        section['qclass'] = response_data[offset: offset + 2]
        offset += 2

        return section, offset

    def get_answer_section(self, response_data, offset, answer_count):
        """
        Answer Section

        Resource record format
                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                      NAME                     /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     CLASS                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      TTL                      |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   RDLENGTH                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        /                     RDATA                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        """
        section = {}
        # Response - Resource Record - Answers
        address_count = 0
        for an in range(1, answer_count + 1):
            # NAME
            rrname = response_data[offset: offset + 2]
            rrname = struct.unpack('>H', rrname)[0]
            if rrname & 0xc000:
                pass
                # print("rr name is compressed: offset {0}".format(rrname & 0x3fff))
            offset += 2

            # TYPE, CLASS, TTL, RDLENDTH
            type_class_ttl_rdlength = response_data[offset: offset + 10]
            section['type'], section['class'], section['ttl'], section['rdlength'] = struct.unpack(
                '>HHLH', type_class_ttl_rdlength)
            # print("RR - TYPE:{0} CLASS:{1} TTL:{2} RDLENGTH:{3}".format(rrtype,rrclass,rrttl,rrrdlength))
            offset += 10

            # RDATA
            if (section['type'] == 1 and section['class'] == 1 and
                    section['rdlength'] == 4):
                section['rdata'] = response_data[offset: offset + 4]
                self.print_output(socket.inet_ntoa(section['rdata']))
                offset += 4
                address_count += 1
            else:
                offset += section['rdlength']

        section['address_count'] = address_count

        return section

    def check_response_header_id(self, response_identifier):
        """"""
        if response_identifier != self.identifier:
            print('Transaction IDs do not match {} {}'.format(
                response_identifier, self.identifier))
            sys.exit(4)

    def close_socket(self):
        """"""
        self.udp_sock.close()

    def main(self):
        """
        Replace the whole original monolith for now.
        """
        ########################################################################
        # Make the request
        ########################################################################
        self.udp_sock.connect((self.dnsserver, PORT))

        self.print_output('Hostname: {0}\nDNS Server: {1}'.format(
            self.hostname, self.dnsserver))

        # Header section
        self.identifier = random.randint(1, 65535)
        flags = 0x0100  # recursion is desired (RD bit set to 1)
        query_header = self.pack_header_fields(self.identifier, flags)

        # Question section
        query_question = self.construct_question()

        # Put the message together and send the query
        self.udp_sock.send(query_header + query_question)

        ########################################################################
        # Listen for the response
        ########################################################################
        response_data = self.receive_response()
        self.print_output("Bytes received: {0}".format(len(response_data)))

        response_header_fields = self.unpack_header_fields(response_data)
        response_header_flags = self.decipher_header_flags(
            response_header_fields['flags'])

        self.print_output("Recursion supported: {0}".format(
            response_header_flags['recursion_available']))

        self.print_output("Identifier: {0}".format(response_header_fields['identifier']))

        # RCODE - Response Code
        self.print_output("Query Status: {0} ({1})".format(
            *response_header_flags['response_code']))

        # Answer Count
        answer_count = response_header_fields['an_count']
        self.print_output('Number of Answers: {0}'.format(answer_count))

        # Question Section
        question_section, offset = self.get_question_section(response_data)
        # print("QTYPE: {0}".format(struct.unpack('>H' , qtype)[0]))
        # print("QCLASS: {0}".format(struct.unpack('>H' , qclass)[0]))

        # Answer Section
        answer_section = self.get_answer_section(response_data, offset, answer_count)

        self.print_output("Number of addresses found: {0}".format(
            answer_section['address_count']))

        self.print_output("End of processing.")

        self.close_socket()

        return self.OUTPUT


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("dnsquery <lookup hostname> <DNS server IP address>")
        sys.exit(1)

    hostname = sys.argv[1]
    dnsserver = sys.argv[2]

    query_dns = QueryDNS(hostname, dnsserver)
    print(query_dns.main())
