#!/usr/bin/python3
'''
CS455 - Project 1 - DNS Client
Group Members:
Mason Nousain G01047858
Matthew Le G01131617
'''
import sys
import random
import sys
import codecs
import socket
import signal

HEX_DECODER = codecs.getdecoder("hex_codec")

'''
    Converts string to hex
    return string
'''
def str_to_hex(label):
    result = "".join([hex(ord(letter))[2:] for letter in label])

    return "0x" + result

'''
    Convert byte to int
'''
def byte_to_int(byte):
    result = 0
    for b in range(len(byte)):
        result = result *256 + int(byte[b])
    return result

'''
    Takes number of bits and returns the max value with that number of bits
    return int -> max
'''
def max_bits(b):
    max = (2 ** b) - 1
    return max

'''
    DNS Query
    Takes hostname and prepares a query message
    return int -> message
'''
def dns_query(hostname):

    print("Preparing DNS query...")

    id = random.randrange(32768, 65535)

    # generate header
    header = gen_header(id) # Encode header from random id

    # generate question
    if hostname[0:4] == "www.":
        hostname = hostname[4:]
    question = gen_question(hostname) # Encode question from hostname

    # generate message
    message = gen_message(hostname, header, question) # Encode header and question into message

    print("DNS query header = " + hex(header))
    print("DNS query question section = " + hex(question))
    print("Complete DNS query = " + hex(message) + "\n")

    return message

'''
    DNS Send
    param message -> int
    return data, address -> (byte, tuple)
'''
def dns_send(message):

    DNS_IP = "8.8.8.8"
    DNS_PORT = 53
    byte_len = 1

    #convert message to byte-like object
    while True:
        try:
            msg_in_bytes = message.to_bytes(byte_len, byteorder = 'big')
            break
        except OverflowError:
            byte_len += 1

    print("Contacting DNS server...")

    # Define UDP socket
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(5)

    print("Sending DNS query...")
    for i in range(3):
        print(f"DNS Response recieved {i+1} of 3 attempts")
        try:
            #send packet to server
            client.sendto(msg_in_bytes, (DNS_IP, DNS_PORT))
            #receive data from the server.
            data, address = client.recvfrom(65565)

            break
        except socket.timeout:
            if i == 2:
                print("Timeout Error")
                sys.exit(0)
    print("-------------------------------------------")
    return data, address


'''
    dns receive and process
'''
def process_response(data, address):

    response = byte_to_int(data)
    dataSize = len(hex(response))-2


    #Used for debuging
    print("Response: " + hex(response))
    print("Address: " + str(address))
    print("Response_Size: " + str(dataSize))


    #decode header from response
    decoded_header = decode_header(response, dataSize)

    #decode question and answer from response
    decode_quest_ans(response, dataSize, decoded_header["ANCOUNT"])

    return

'''
    Takes the randomly generated id and sets bits to create header
    return int -> header
'''
def gen_header(id):

    header = id
    #print("ID: " + hex(header))

    header = header << 1        # QR set to 0
    header = header << 4        # Opcode set to 0 -> Standard Query
    header = header << 2        # AA and TC set to 0
    header = header << 1 | 1    # RD set to 1
    header = header << 1        # RA set to 0
    header = header << 3        # Z set to 0
    header = header << 4        # RCODE set to 0
    header = header << 16 | 1   # QDCOUNT set to 1
    header = header << 16       # ANCOUNT set to 0
    header = header << 16       # NSCOUNT set to 0
    header = header << 16       # ARCOUNT set to 0

    return header

'''
    Takes the response data and dataSize and decodes the header and prints the results
    return dictionary -> header
'''
def decode_header(response, dataSize):

    header = {
        "ID": 0,
        "QR": 0,
        "Opcode": 0,
        "AA": 0,
        "TC": 0,
        "RD": 0,
        "RA": 0,
        "Z": 0,
        "RCODE": 0,
        "QDCOUNT": 0,
        "ANCOUNT": 0,
        "NSCOUNT": 0,
        "ARCOUNT": 0,
        }

    header["ID"] = response >> ((dataSize*4) - 16) & 0xffff
    header["QR"] = response >> ((dataSize*4) - 17) & 0b1
    header["Opcode"] = response >> ((dataSize*4) - 21) & 0xf
    header["AA"] = response >> ((dataSize*4) - 22) & 0b1
    header["TC"] = response >> ((dataSize*4) - 23) & 0b1
    header["RD"] = response >> ((dataSize*4) - 24) & 0b1
    header["RA"] = response >> ((dataSize*4) - 25) & 0b1
    header["Z"] = response >> ((dataSize*4) - 28) & 0b111
    header["RCODE"] = response >> ((dataSize*4) - 32) & 0xf
    header["QDCOUNT"] = response >> ((dataSize*4) - 48) & 0xffff
    header["ANCOUNT"] = response >> ((dataSize*4) - 64) & 0xffff
    header["NSCOUNT"] = response >> ((dataSize*4) - 80) & 0xffff
    header["ARCOUNT"] = response >> ((dataSize*4) - 96) & 0xffff

    print("-------------------------------------------")
    print("header.ID = " + hex(header["ID"]))
    print("header.QR = " + hex(header["QR"]))
    print("header.Opcode = " + hex(header["Opcode"]))
    print("header.AA = " + hex(header["AA"]))
    print("header.TC = " + hex(header["TC"]))
    print("header.RD = " + hex(header["RD"]))
    print("header.RA = " + hex(header["RA"]))
    print("header.Z = " + hex(header["Z"]))
    print("header.RCODE = " + hex(header["RCODE"])) # RCODE = 0 if no errors, and >0 otherwise
    print("header.QDCOUNT = " + hex(header["QDCOUNT"]))
    print("header.ANCOUNT = " + hex(header["ANCOUNT"])) # number of answers
    print("header.NSCODE = " + hex(header["NSCOUNT"]))
    print("header.ARCOUNT = " + hex(header["ARCOUNT"]))

    return header

'''
    Takes the hostname and generates the proper formated question
    returns int -> question
'''
def gen_question(hostname):

    question = 0

    labels = hostname.split(".") # splits hostname into labels

    # Encodes QNAME into question based on hostname
    for label in labels:
        tempHex  = str_to_hex(label)
        tempInt = int(tempHex, 16) # convert hex string into int
        sizeLabel = len(label)     # get size of label

        #print("label: " + label + " | length: " + str(len(label)) + " | hex: " + tempHex + " | dec: " + str(tempInt)) # testing output
        question = question << 8 | sizeLabel # Encode length of each label
        question = (question << (sizeLabel * 8)) | tempInt # Encode each label into question
        #print("question: " + hex(question)) # testing output

    question = question << 8         # Terminate QNAME with zero length octet
    question = question << 16 | 1    # QTYPE set to 1
    question = question << 16 | 1    # QCLASS set to 1

    return question

'''
    Takes the response data and dataSize and decodes the question and answer and prints the results
'''
def decode_quest_ans(response, dataSize, numAnswers):

    question = {
        "QNAME": 0,
        "QTYPE": 0,
        "QCLASS": 0,
    }

    sizeLabel = response >> ((dataSize*4) - 104) & 0xff
    temp = 104
    temp1 = 112
    while sizeLabel != 0:
        #print("QNAME label size: " + str(sizeLabel))
        for i in range(sizeLabel):
            tempInt = response >> ((dataSize*4) - temp1) & 0xff
            question["QNAME"] = question["QNAME"] << 8 | tempInt
            temp1 = temp1 + 8

        temp = temp + ((sizeLabel*8) + 8)
        #print("Temp: " + str(temp))
        sizeLabel = response >> ((dataSize*4) - temp) & 0xff
        temp1 = temp1 + 8

    question["QTYPE"] = response >> ((dataSize*4) - (temp + 16)) & 0xffff
    question["QCLASS"] = response >> ((dataSize*4) - (temp + 32)) & 0xffff

    temp = temp + 32

    print("-------------------------------------------")
    print("question.QNAME = " + hex(question["QNAME"]))
    print("question.QTYPE = " + hex(question["QTYPE"]))
    print("question.QCLASS = " + hex(question["QCLASS"]))
    print("-------------------------------------------")

    i = 1

    while i <= numAnswers:

        print(f"Answer {i}")
        i+=1

        answer = {
        "NAME": 0,
        "TYPE": 0,
        "CLASS": 0,
        "TTL": 0,
        "RDLENGTH": 0,
        "RDATA": 0,
        }

        temp = temp + 16
        answer["NAME"] = response >> ((dataSize*4) - temp) & 0xffff

        temp = temp + 16
        answer["TYPE"] = response >> ((dataSize*4) - temp) & 0xffff

        temp = temp + 16
        answer["CLASS"] = response >> ((dataSize*4) - temp) & 0xffff

        temp = temp + 32
        answer["TTL"] = response >> ((dataSize*4) - temp) & 0xffffffff

        temp = temp + 16
        answer["RDLENGTH"] = response >> ((dataSize*4) - temp) & 0xffff

        temp = temp + 32
        answer["RDATA"] = response >> ((dataSize*4) - temp) & 0xffffffff

        print("answer.NAME = " + hex(answer["NAME"]))
        print("answer.TYPE = " + hex(answer["TYPE"]))
        print("answer.CLASS = " + hex(answer["CLASS"]))
        print("answer.TTL = " + str(answer["TTL"]) + " seconds")
        print("answer.RDLENGTH = " + str(answer["RDLENGTH"]))
        #print("answer.RDATA = " + hex(answer["RDATA"]))

        byte_len = 1
        while True:
            try:
                RDATA_in_bytes = answer["RDATA"].to_bytes(byte_len, byteorder = 'big')
                break
            except OverflowError:
                byte_len += 1

        print("answer.RDATA = " + socket.inet_ntoa(RDATA_in_bytes))
        print("-------------------------------------------")
        if temp < (dataSize*4):
            hexDumpSize = (dataSize*4) - temp
            #print("hexDumpSize = " + str(hexDumpSize))
            hexDump = response & max_bits(hexDumpSize)
            response = hexDump
            #print("Additional RRs received: " + hex(hexDump))
            #print("-------------------------------------------")
        else:
            break

    return
'''
    Takes hostname, header, and question then encodes header and question into a single message
    returns int -> message
'''
def gen_message(hostname, header, question):

    message = header #  Encode header into message
    labels = hostname.split(".") # split hostname into labels

    QNameSize = 0;

    for label in labels:
        sizeLabel = len(label)
        QNameSize = QNameSize + (sizeLabel * 8) + 8

    #print("QNameSize: " + str(QNameSize))

    q_size = QNameSize + 40;    # size in bits of question
    message = message << q_size | question  # Encode question into message

    return message

def main():

    try:

        hostname = sys.argv[1]


        print(f'Resolving Hostname: {hostname}')
    except IndexError:
        print("Requires: Hostname")
        sys.exit(0)

    # Prepare query message from hostname
    message = dns_query(hostname)

    # Send query message and get response
    response, address = dns_send(message)

    # Process response and print
    process_response(response, address)
    print('\n\n')



if __name__ == "__main__":
    main()
