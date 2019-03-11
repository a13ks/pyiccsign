#!/usr/bin/env python

import struct
import hashlib
import serial
import binascii
import time
import ctypes
import numpy

k_serial = None

restart_flag = False
sequence = 4096

def rshift16(val, n): 
    return val>>n if val >= 0 else (val+0x10000)>>n

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

    SW_9000 = { -112, 0 }
    SW_6a82 = { 106, -126 }
    SW_6986 = { 105, -122 }
    SW_6b00 = { 107, 0 }
    SW_6983 = { 105, -125 }
    SW_6a80 = { 106, -128 }

    def __init__(self):
        self.sw = []

    def set_sw(self, sw):
        self.sw = sw

    def status_sw(self):
        if self.sw == None:
            return 1
        elif len(self.sw) != 2:
            return -1
        elif self.sw == APDU.SW_9000:
            return 0
        elif self.sw == APDU.SW_6a82:
            return -2
        elif self.sw == APDU.SW_6986:
            return -2
        elif self.sw == APDU.SW_6b00:
            return -3
        elif self.sw == APDU.SW_6983:
            return 253
        elif self.sw == APDU.SW_6a80:
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
    print "reset sequence"
    sequence += 1
    return sequence

def packet_in(pkt):
    if not pkt.validate_checksum():
        print "checksum failed"
        return False

    # if pkt.get_restart_flag():
    #     reset_seq()

    if not pkt.is_ack_type():
        seq = pkt.get_sequence()
        send_ack(seq)
    return True

def send_no_receive(pkt):
    global k_serial

    pkt.set_checksum()

    payload = translated(pkt.get_bytes())

    print ">>", binascii.hexlify(payload)

    k_serial.write(payload)
    k_serial.flush()

def send_and_receive(pkt):
    global k_serial

    pkt.set_sequence(get_seq())

    pkt.set_checksum()

    payload = translated(pkt.get_bytes())

    print ">>", binascii.hexlify(payload)

    k_serial.write(payload)
    k_serial.flush()

    while k_serial.in_waiting == 0:
        time.sleep(0.5)

    buf = k_serial.read(k_serial.in_waiting)

    print "<<", binascii.hexlify(buf)

    tmp = []
    # packets = []
    for i in range(0, len(buf)):
        if buf[i] == '~': # 0x7e
            if len(tmp) > 1:
                # found packet
                tmp.append(ord(buf[i]))
                pkt_buf = restore_translated(tmp)
                pkt = Packet.from_buffer(pkt_buf)
                tmp = []
                # packets.append(pkt)
                packet_in(pkt)
                continue
        tmp.append(ord(buf[i]))

    return None

def process_apdu(apdu):
    print ">> process apdu"
    global k_serial
    pkt = Packet()
    pkt.set_command(4)
    pkt.set_ic_data_len(len(apdu))
    pkt.set_ic_data(apdu)

    reply = send_and_receive(pkt)

    if reply and len(reply.get_ic_data()) > 4:
        print "got reply"

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
    print ">> connect"
    return send_command(1)

def power_on_card():
    print ">> power on card"
    return send_command(2)

def power_off_card():
    print ">> power off card"
    return send_command(3)

def get_card_info():
    print ">> get card info"
    apdu = APDU()
    select_file_req = apdu.select_file(1)
    process_apdu(select_file_req)

    read_file_req = apdu.read_file(0)
    process_apdu(read_file_req)


def select_application():
    print ">> select application"
    apdu = APDU()
    application_select_apdu = apdu.select_application("NEWPOS-CARD")
    process_apdu(application_select_apdu)

def send_ack(seq):
    print ">> sending ack"
    pkt = Packet()
    pkt.set_ack_type()
    pkt.set_sequence(seq)
    send_no_receive(pkt)

def main():
    global restart_flag
    global k_serial
    k_serial = serial.Serial('/dev/tty.usbserial-AH01SKWE', baudrate=115200)

    connect()

    power_on_card()

    select_application()

    get_card_info()

    # power_off_card()

if __name__ == "__main__":
    main()
