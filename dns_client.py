'''
RFC 1035 - Domain names - Implementation and Specification
*  2.3.4 Size limits  *
labels          63 octets or less, the two high order bits are 0
names           255 octets or less
TTL             positive values of a signed 32 bit number.
UDP messages    512 octets or less
'''

import random
import socket
import struct
import sys

PORT = 53
MAX_LABEL_OCTETS = 63
MAX_NAME_OCTETS = 255
MAX_OCTETS_FOR_UDP_MESSAGE = 512


class QueryDNS:
    """
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

    def main(self):
        """
        Replace the whole original monolith for now.
        """
        self.udp_sock.connect((self.dnsserver, PORT))

        self.print_output('Hostname: {0}\nDNS Server: {1}'.format(
            self.hostname, self.dnsserver))

        # Header section
        self.identifier = random.randint(1, 65535)
        flags = 0x0100  # recursion is desired (RD bit set to 1)
        query_header = self.pack_header_fields(self.identifier, flags)

        # Question section
        query_question = self.construct_question()

        self.udp_sock.send(query_header + query_question)

        delay = 0.1
        while True:
            self.udp_sock.settimeout(delay)
            # print("Waiting {0} seconds for a reply".format(delay))
            try:
                data = self.udp_sock.recv(MAX_OCTETS_FOR_UDP_MESSAGE)
            except socket.timeout:
                delay *= 2  # exponential backoff
                if delay > 2.0:
                    # print("Not waiting more than 2 seconds for a reply. Exiting.")
                    self.print_output("Delay is more than 2.0 seconds.")
                    self.udp_sock.close()
                    sys.exit(3)
            except Exception as e:
                self.print_output("how did we get here: {}".format(e))
            else:
                break

        # Length of reply
        self.print_output("Bytes recieved: {0}".format(len(data)))

        # Response - Header
        #                                    1  1  1  1  1  1
        #      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        #    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #    |                      ID                       |
        #    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        #    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #    |                    QDCOUNT                    |
        #    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #    |                    ANCOUNT                    |
        #    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #    |                    NSCOUNT                    |
        #    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #    |                    ARCOUNT                    |
        #    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        offset = 12
        header = struct.unpack('>HHHHHH', data[:offset])  # first 6 short int's (2 bytes)
        # Response - Header - ID
        if header[0] != self.identifier:
            print("Transaction ID's do not match", header[0], self.identifier)
            sys.exit(4)
        self.print_output("Identifier: {0}".format(self.identifier))

        # Response - Header - Flags - RA - Recursion Available
        ra = header[1] & 0x0080
        if ra == 128:
            ra = 1
        self.print_output("Recursion supported: {0}".format(ra))

        # Response - Header - Flags - RCODE - Response Code
        rcode = header[1] & 0x000F
        if rcode == 0:
            rcode_str = "No Error"
        elif rcode == 1:
            rcode_str = "Format error"
        elif rcode == 2:
            rcode_str = "Server failure"
        elif rcode == 3:
            rcode_str = "Name Error"
        elif rcode == 4:
            rcode_str = "Not Implented"
        elif rcode == 5:
            rcode_str = "Refused"
        else:
            rcode_str = "Reserved for furture use"
        self.print_output("Query Status: {0} ({1})".format(rcode, rcode_str))

        ancount = header[3]
        # Response - Header - ANCOUNT - Answer Count
        self.print_output("Number of Answers: {0}".format(ancount))

        # Response - Question - QNAME
        while True:
            lo = data[offset]  # Length octet
            offset += 1
            if lo == 0:
                break

            label = data[offset:offset + lo]
            # print(lo, label)
            offset += lo

        # Response - Question - QTYPE
        qtype = data[offset: offset + 2]
        offset += 2
        # print("QTYPE: {0}".format(struct.unpack('>H' , qtype)[0]))

        # Response - Question - QCLASS
        qclass = data[offset: offset + 2]
        offset += 2
        # print("QCLASS: {0}".format(struct.unpack('>H' , qclass)[0]))

        # Response - Resource Record - Answers
        add_cnt = 0
        for an in range(1, ancount + 1):
            # Response - Resource Record - NAME
            rrname = data[offset: offset + 2]
            rrname = struct.unpack('>H', rrname)[0]
            if rrname & 0xc000:
                pass
                # print("rr name is compressed: offset {0}".format(rrname & 0x3fff))
            offset += 2

            # Response - Resource Record - TYPE, CLASS, TTL, RDLENDTH
            rrfixed = data[offset: offset + 10]
            rrtype, rrclass, rrttl, rrrdlength = struct.unpack(">HHLH", rrfixed)
            # print("RR - TYPE:{0} CLASS:{1} TTL:{2} RDLENGTH:{3}".format(rrtype,rrclass,rrttl,rrrdlength))
            offset += 10

            # Response - Resource Record - RDATA
            if rrtype == 1 and rrclass == 1 and rrrdlength == 4:
                rdata = data[offset: offset + 4]
                self.print_output(socket.inet_ntoa(rdata))
                offset += 4
                add_cnt += 1
            else:
                offset += rrrdlength

        self.print_output("Number of addresses found: {0}".format(add_cnt))

        self.print_output("End of processing.")

        self.udp_sock.close()

        return self.OUTPUT


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("dnsquery <lookup hostname> <DNS server IP address>")
        sys.exit(1)

    hostname = sys.argv[1]
    dnsserver = sys.argv[2]

    query_dns = QueryDNS(hostname, dnsserver)
    print(query_dns.main())
