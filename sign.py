#!/usr/bin/env python

import struct
import hashlib
import serial
import binascii
import time

BUF_SIZE = 65536

k_serial = None

restart_flag = False
sequence = 4096

def rshift16(val, n): 
    return val>>n if val >= 0 else (val+0x10000)>>n

def read_file(filename):
    file_bytes = ()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            file_bytes = file_bytes + tuple(data)
    return file_bytes

class FileELF:
    def __init__(self):
        None

class CardInfo:
    def __init__(self):
        self.version = None
        self.sn = None
        self.type = None
        self.make_time = None

    @classmethod
    def from_buffer(cls, buf):
        card_info = CardInfo()

        card_info.version = buf[0:3]
        card_info.sn = buf[3:7]
        card_info.type = buf[7:8]
        card_info.make_time = buf[8:15]

        return card_info

    def __str__(self):
        return "[{}, {}, {}, {}]".format(self.version, self.sn, self.type, self.make_time)

class CustomerInfo:
    def __init__(self):
        self.cid = None
        self.name = None
        self.address = None
        self.phone = None

    @classmethod
    def from_buffer(cls, buf):
        customer_info = CustomerInfo()

        customer_info.cid = buf[0:2].decode('ascii')
        customer_info.name = buf[2:66].decode('ascii')
        customer_info.address = buf[66:166].decode('ascii')
        customer_info.phone = buf[166:196].decode('ascii')
        # reserve = buf[196:214]

        return customer_info

    def __str__(self):
        return "[{}, {}, {}, {}]".format(self.cid, self.name, self.address, self.phone)

class Packet:
    def __init__(self):
        self.restart_flag = False
        self.data_len = 16
        self.data = bytearray(1024)
        self.data[0] = 32
        self.seq = 0

    @classmethod
    def from_buffer(cls, buffer):
        pkt = Packet()
        pkt.set_data(buffer)
        return pkt

    def set_restart_flag(self):
        self.restart_flag = True
        self.data[0] |= 128

    def get_restart_flag(self):
        return self.data[0] & 0x80
    
    def set_command(self, command):
        buf = bytearray(struct.pack('<h', command))
        self.data[16] = buf[0]
        self.data[17] = buf[1]
        self.data[2] = 4
        self.data_len += 4

    def set_checksum_data(self, checksum):
        buf = bytearray(struct.pack('<h', checksum))
        self.data[12] = buf[0]
        self.data[13] = buf[1]

    def set_checksum_head(self, checksum):
        buf = bytearray(struct.pack('<h', checksum))
        self.data[14] = buf[0]
        self.data[15] = buf[1]

    def set_checksum(self):
        data_csum = Packet.checksum(self.data, 16, self.data_len - 16)
        self.set_checksum_data(data_csum)
        head_csum = Packet.checksum(self.data, 0, 16)
        self.set_checksum_head(head_csum)

    def set_sequence(self, seq):
        buf = struct.pack('<i', seq)
        self.data[4] = buf[0]
        self.data[5] = buf[1]
        self.data[6] = buf[2]
        self.data[7] = buf[3]

    def set_data(self, data):
        self.data = data
        self.data_len = len(data)

    def set_ic_data(self, data):
        if len(data) > 400:
            return

        self.data[20:20+len(data)] = data
        self.data_len += len(data)
        
    def get_ic_data(self):
        return self.data[20:self.data_len]

    def set_ack_type(self):
        self.data[1] |= 0x1
    
    def is_ack_type(self):
        return self.data[1] & 0x1 != 0x0
    
    def set_ic_data_len(self, len):
        len += 4
        buf = struct.pack('<i', len)
        self.data[2] = buf[0]
        self.data[3] = buf[1]

    def get_sequence(self):
        return ((self.data[7] & 0xFF) << 24) + ((self.data[6] & 0xFF) << 16) + ((self.data[5] & 0xFF) << 8) + (self.data[4] & 0xFF)

    def get_command(self):
        return (((self.data[17] & 0xFF) << 8) + (self.data[16] & 0xFF))

    def validate_checksum(self):
        sum = Packet.checksum(self.data, 0, 16)
        if sum != 0:
            return False

        if not self.is_ack_type():
            data_checksum = (((self.data[13] & 0xFF) << 8) + (self.data[12] & 0xFF))
            sum = Packet.checksum(self.data, 16, self.data_len - 16)
            if sum < 0:
                sum += 65536
            if sum != data_checksum:
                return False
        return True

    def get_bytes(self):
        return self.data[0:self.data_len]

    @staticmethod
    def checksum(buf, offset, length):
        sum = 0
        count = length
        i = offset
        while (count > 1):
            sum += (buf[i] & 0xFF) + ((buf[i + 1] & 0xFF) << 8)
            i += 2
            count -= 2

        if count > 0:
            sum += (buf[i] & 0xFF)

        while sum >> 16 != 0:
            sum = (sum & 0xFFFF) + (rshift16(sum, 16))

        new_sum = ~(sum)
        if new_sum < -32768:
            new_sum += 65536
        return new_sum

class APDU:
    SW_ERROR = -1
    SW_SUCCESS = 0
    SW_COMMAND_NOT_ALLOWED = -2
    SW_WRONG_P1P2 = -3
    SW_USER_KEY_NOT_IMPORTED = 253
    SW_CERT_NOT_IMPORTED = 254
    USER_PUB_KEY_NULL = 255
    SW_FILE_NOT_FOUND = -2
    DOWNLOAD_RSA_KEY_INS = -43
    DOWNLOAD_CERT_INS = -9
    CARD_COPY_INS = -13
    READ_CARD_VER_INS = -54
    CLA_00 = 0
    CLA_80 = -128

    SW_9000 = bytearray([0x90, 0x0 ])
    SW_6a82 = bytearray([0x6a, 0x82])
    SW_6986 = bytearray([0x69, 0x86])
    SW_6b00 = bytearray([0x6b, 0x0 ])
    SW_6983 = bytearray([0x69, 0x83])
    SW_6a80 = bytearray([0x6a, 0x80])

    def __init__(self):
        self.sw = []

    def set_sw(self, sw):
        self.sw = sw

    @classmethod
    def status_sw(cls, sw):
        if sw == None:
            return 1
        elif len(sw) != 2:
            return -1
        elif sw == APDU.SW_9000:
            return 0
        elif sw == APDU.SW_6a82:
            return -2
        elif sw == APDU.SW_6986:
            return -2
        elif sw == APDU.SW_6b00:
            return -3
        elif sw == APDU.SW_6983:
            return 253
        elif sw == APDU.SW_6a80:
            return 253
        else:
            return -1

    def select_application(self, app_name):
        app_name_len = len(app_name)
        select_apdu = bytearray(5 + app_name_len)
        head = bytearray([0, 0xa4, 4, 0])
        lc = bytearray([app_name_len])
        data = bytearray(app_name, 'ascii')
        select_apdu = head + lc + data
        return select_apdu

    def build_sign_apdu(self, elf, signature):
        # todo: compose sign apdu
        return None

    def get_more_sign_apdu(self, seq):
        return bytearray([0x80, 0xf1, 0, seq])

    def build_card_app_ver_ins(self):
        return bytearray([0, 0xca, 0, 0, 0])

    def select_file(self, file_tag):
        head = bytearray([0, 0xa4, 0, 0, 2])
        data = struct.pack('>h', file_tag)
        req_data = head + data
        return req_data

    def read_file(self, file_offset):
        offset = struct.pack('<h', file_offset)
        head = bytearray([0, 0xb0])
        req_data = head + offset
        return req_data

    def request_contact_card_data(self, length):
        return bytearray([0, 0xc0, 0, 0, length])

def translated(data):
    idx = 0
    tmp = bytearray(len(data) * 2)
    tmp[idx] = 0x7e; idx += 1

    for i in range(0, len(data)):
        if data[i] == 0x7e:
            tmp[idx] = 0xdb; idx += 1
            tmp[idx] = 0xdc; idx += 1
        elif data[i] == 0xdb:
            tmp[idx] = 0xdb; idx += 1
            tmp[idx] = 0xdd; idx += 1
        else:
            tmp[idx] = data[i]; idx += 1
    tmp[idx] = 0x7e; idx += 1
    return tmp[0:idx]

def restore_translated(data):
    # tmp = bytearray(len(data))
    tmp = [0x0] * len(data)
    idx = 0
    xr = iter(xrange(0, len(data)))
    for i in xr:
        c = data[i]
        if c == 0x7e:
            continue
        elif c == 0xdb:
            i += 1
            next(xr)
            if i >= len(data):
                return None
            if data[i] == 0xdc:
                c = 0x7e
            elif data[i] == 0xdd:
                c = 0xdb
            else:
                return None
        tmp[idx] = c; idx += 1

    return tmp[0:idx]

def get_seq():
    global sequence
    sequence += 1
    return sequence

def get_current_seq():
    global sequence
    return sequence

def reset_seq():
    global sequence
    print("reset sequence")
    sequence += 1
    return sequence

def packet_in(pkt):
    if not pkt.validate_checksum():
        print("checksum failed")
        return False

    # TODO
    # if pkt.get_restart_flag():
    #     reset_seq()

    if not pkt.is_ack_type():
        seq = pkt.get_sequence()
        send_ack(seq)
        return True
    return False

def send_no_receive(pkt):
    global k_serial

    pkt.set_checksum()

    payload = translated(pkt.get_bytes())

    print(">> " + binascii.hexlify(payload))

    k_serial.write(payload)
    k_serial.flush()

def send_and_receive(pkt):
    global k_serial

    pkt.set_sequence(get_seq())

    pkt.set_checksum()

    payload = translated(pkt.get_bytes())

    print(">> " + binascii.hexlify(payload))

    k_serial.write(payload)
    k_serial.flush()

    while k_serial.in_waiting == 0:
        time.sleep(0.5)

    buf = k_serial.read(k_serial.in_waiting)

    print("<< " + binascii.hexlify(buf))

    tmp = []
    ret = None
    for i in range(0, len(buf)):
        if buf[i] == '~': # 0x7e
            if len(tmp) > 1:
                # found packet
                tmp.append(ord(buf[i]))
                pkt_buf = restore_translated(tmp)
                pkt = Packet.from_buffer(pkt_buf)
                tmp = []
                # packets.append(pkt)
                if packet_in(pkt):
                    ret = pkt
                continue
        tmp.append(ord(buf[i]))

    return ret

def send_apdu(apdu):
    print(">> send apdu")
    global k_serial
    pkt = Packet()
    pkt.set_command(4)
    pkt.set_ic_data_len(len(apdu))
    pkt.set_ic_data(apdu)

    reply = send_and_receive(pkt)
    return reply

def process_apdu(apdu):
    print(">> process apdu")
    reply = send_apdu(apdu)

    data = None
    rec_data = reply.get_ic_data()
    if len(rec_data) > 4:
        code = bytearray(rec_data[0:4])
        status = struct.unpack('>i', code)[0]

        if status != 0:
            print("status 1 = " + str(status))
            return None

        data = rec_data[4:]

        if len(data) == 2 and data[0] == 0x61:
            apdu = APDU()
            req = apdu.request_contact_card_data(data[1])
            reply = send_apdu(req)
            rec_data = reply.get_ic_data()
            if len(rec_data) > 4:
                code = bytearray(rec_data[0:4])
                status = struct.unpack('>i', code)[0]

                if status != 0:
                    print("status 2 = " + str(status))
                    return None

                data = bytearray(rec_data[4:])
    
    return data



def send_command(command):
    global restart_flag

    pkt = Packet()
    if not restart_flag:
        pkt.set_restart_flag()
        restart_flag = True

    pkt.set_command(command)
    reply = send_and_receive(pkt)
    return reply

def connect():
    print(">> connect")
    return send_command(1)

def power_on_card():
    print(">> power on card")
    return send_command(2)

def power_off_card():
    print(">> power off card")
    return send_command(3)

def get_card_info():
    print(">> get card info")
    apdu = APDU()
    select_file_req = apdu.select_file(1)
    process_apdu(select_file_req)

    read_file_req = apdu.read_file(0)
    data = process_apdu(read_file_req)
    # print ">> card info = " + binascii.hexlify(data)
    if APDU.status_sw(data[-2:]) == 0:
        card_info = CardInfo.from_buffer(data)
        return card_info
    else:
        return None

def get_customer_info():
    print(">> get customer info")
    apdu = APDU()
    select_file_req = apdu.select_file(2)
    process_apdu(select_file_req)

    read_file_req = apdu.read_file(0)
    data = process_apdu(read_file_req)
    # print ">> customer info = " + binascii.hexlify(data)
    if APDU.status_sw(data[-2:]) == 0:
        customer_info = CustomerInfo.from_buffer(data)
        return customer_info
    else:
        return None

def select_application():
    print(">> select application")
    apdu = APDU()
    application_select_apdu = apdu.select_application("NEWPOS-CARD")
    process_apdu(application_select_apdu)

def send_ack(seq):
    print(">> sending ack")
    pkt = Packet()
    pkt.set_ack_type()
    pkt.set_sequence(seq)
    send_no_receive(pkt)

def get_needed_signed_file(elf):
    # todo: check signed file tag
    sig_0001_tag = [83, 73, 71, 58, 48, 48, 48, 49]
    sig_0002_tag = [83, 73, 71, 58, 48, 48, 48, 50]
    return read_file(elf.file_path)

def get_signed_tail_content(customer_info, elf):
    # todo: add real tail
    tail = []
    return tail

def calc_sign_src_hash(file_content, puk_cert_data, signed_tail):
    m = hashlib.sha256()
    src = file_content + puk_cert_data + signed_tail
    m.update(src)
    return m.digest()

def start_sign_file(elf, dir, puk_cert_data, card_info, customer_info):
    file_content = get_needed_signed_file(elf)
    signed_tail = get_signed_tail_content(customer_info, elf)

    hash = calc_sign_src_hash(file_content, puk_cert_data, signed_tail)

    # todo: compose signature
    signature = bytearray()

    apdu = APDU() 
    sign_apdu = apdu.build_sign_apdu(elf, signature)
    data = process_apdu(sign_apdu)

    None

def sign_file(elf, dir, card_info, customer_info):
    print(">> sign file")
    user_nr = 0
    file_tag = user_nr + 32

    apdu = APDU()
    select_file_apdu = apdu.select_file(file_tag)
    reply = process_apdu(select_file_apdu)

    puk_len = 0
    puk_cert_data = bytearray()

    while True:
        print(">> read puk")
        read_cert_req = apdu.read_file(0)
        data = process_apdu(read_cert_req)
        data_len = len(data) - 2
        puk_len += data_len
        puk_cert_data += data[0:data_len]

        if data_len != 0xff:
            break

    # print(">> puk cert = " + binascii.hexlify(puk_cert_data))

    ver_bytes = process_apdu(apdu.build_card_app_ver_ins())

    ver = 0
    if len(ver_bytes) >= 3:
        # todo
        print(">> ver bytes = " + binascii.hexlify(ver_bytes)) 

    if ver >= 30000:
        None
    else:
        start_sign_file(elf, dir, puk_cert_data, card_info, customer_info)

    None

def main():
    global restart_flag
    global k_serial
    k_serial = serial.Serial('/dev/tty.usbserial-AH01SKWE', baudrate=115200)

    connect()

    power_on_card()

    select_application()

    card_info = get_card_info()

    customer_info = get_customer_info()

    elf = FileELF()
    elf.file_name = 'TransPOS'
    elf.file_path = '/Users/a13x/dev/newpos/pyiccsign'
    elf.version = '1.9.2'
    elf.type = 'app'
    dir = '/Users/a13x/dev/newpos/pyiccsign/signed'

    if customer_info and card_info:
        sign_file(elf, dir, card_info, customer_info)

    power_off_card()

if __name__ == "__main__":
    main()
