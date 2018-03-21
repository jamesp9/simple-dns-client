#!/usr/bin/env python3

# RFC 1035 - Domain names - Implementation and Specification
# *  2.3.4 Size limits  *
# labels          63 octets or less, the two high order bits are 0
# names           255 octets or less
# TTL             positive values of a signed 32 bit number.
# UDP messages    512 octets or less

import socket
import sys
import struct
import random

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
random.seed(9)
MAX = 512  # max num octets for domain UDP packet
PORT = 53

# dsthost = "192.168.2.15"
if len(sys.argv) != 3:
    print("dnsquery <lookup hostname> <DNS server IP address>")
    sys.exit(1)

hostname = sys.argv[1]
dnsserver = sys.argv[2]

s.connect((dnsserver, PORT))
# print('Socket name is:', s.getsockname())
print('Hostname: {0}\nDNS Server: {1}'.format(hostname, dnsserver))

# DNS Query - Header
tranID = random.randint(1, 65535)
flags = 0x0100  # recursion is desired
questions = 1
answerRR = 0
authorityRR = 0
additionalRR = 0
# packed binary bits should be big endian ">" for network
query_header = struct.pack('>hhHHHH', tranID, flags, questions, answerRR, authorityRR, additionalRR)

# DNS Query - Question
qname = b''
for label in hostname.split('.'):
    lab_len = len(label)
    if lab_len > 63:
        print("Please check domain name. Label {0} is greater than 63 octets.".format(label))
        sys.exit(1)
    # label =  1 length octet + that number of octets
    plabel = struct.pack(">B{0}s".format(lab_len), lab_len, label.encode('ascii'))
    qname += plabel

qname = struct.pack(">{0}sB".format(len(qname)), qname, 0)  # terminate with zero length octet
if len(qname) > 256:
    print("Query name has breached the size limit, of 255 octets.")
    sys.exit(2)

qtype = 1  # type A host address
qclass = 1  # class 1, IN (Internet)
query_question = struct.pack('>{0}sHH'.format(len(qname)), qname, qclass, qtype)

s.send(query_header + query_question)

delay = 0.1
while True:
    s.settimeout(delay)
    # print("Waiting {0} seconds for a reply".format(delay))
    try:
        data = s.recv(MAX)
    except socket.timeout:
        delay *= 2  # exponential backoff
        if delay > 2.0:
            # print("Not waiting more than 2 seconds for a reply. Exiting.")
            print("Delay is more than 2.0 seconds.")
            s.close()
            sys.exit(3)
    except Exception as e:
        print("how did we get here: {}".format(e))
    else:
        break

# Length of reply
print("Bytes recieved: {0}".format(len(data)))

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
if header[0] != tranID:
    print("Transaction ID's do not match", header[0], tranID)
    sys.exit(4)
print("TranID: {0}".format(tranID))


# Response - Header - Flags - RA - Recursion Available
ra = header[1] & 0x0080
if ra == 128:
    ra = 1
print("Recursion supported: {0}".format(ra))

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
print("Query Status: {0} ({1})".format(rcode, rcode_str))

ancount = header[3]
# Response - Header - ANCOUNT - Answer Count
print("Number of Answers: {0}".format(ancount))

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
        print(socket.inet_ntoa(rdata))
        offset += 4
        add_cnt += 1
    else:
        offset += rrrdlength

print("Number of addresses found: {0}".format(add_cnt))

print("End of processing.")
