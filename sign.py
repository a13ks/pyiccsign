#!/usr/bin/env python

import sys
import struct
import hashlib
import serial
import binascii

k_serial = None

# connect = [126, 256-96, 0, 4, 0, 1, 16, 0, 0, 0, 0, 0, 0, 256-2, 256-1, 91, 256-17, 1, 0, 0, 0, 126]
# poweron = [126, 256-96, 0, 4, 0, 1, 16, 0, 0, 0, 0, 0, 0, 256-3, 256-1, 92, 256-17, 2, 0, 0, 0, 126]
# ser = serial.Serial('/dev/tty.usbserial-AH01SKWE', baudrate=115200)
# bytes = ser.write(connect)
# ser.flush()
# print "Written bytes = " + str(bytes)
# bytes = ser.read()
# print "More bytes = ", str(ser.in_waiting)
# print "Read bytes = " + str(len(bytes))
# bytes = ser.write(poweron)
# ser.flush()
# print "Written bytes = " + str(bytes)
# bytes = ser.read()
# print "Read bytes = " + str(len(bytes))
# exit(0)

restart_flag = False
sequence = 4096

class Packet:
    def __init__(self):
        self.restart_flag = False
        self.data_len = 16
        self.data = bytearray(1024)
        self.data[0] = 32
        self.seq = 0

    def set_restart_flag(self):
        self.restart_flag = True
        self.data[0] |= 128

    def get_restart_flag(self):
        return self.data[0] & 0x80
    
    def set_command(self, command):
        self.data[16:18] = struct.pack('<h', command)
        # self.data[17] = command >> 8
        # self.data[16] = command & 0xFF
        self.data[2] = 4
        self.data_len += 4

    def set_checksum_data(self, checksum):
        self.data[12:14] = bytearray(struct.pack('<h', checksum))
        # self.data[13] = (checksum & 0xFF00) >> 8
        # self.data[12] = checksum & 0xFF

    def set_checksum_head(self, checksum):
        self.data[14:16] = bytearray(struct.pack('<h', checksum))
        # self.data[15] = (checksum & 0xFF00) >> 8
        # self.data[14] = checksum & 0xFF

    def set_checksum(self):
        self.set_checksum_data(Packet.checksum(self.data, 16, self.data_len - 16))
        self.set_checksum_head(Packet.checksum(self.data, 0, 16))

    def set_sequence(self, seq):
        self.data[4:8] = struct.pack('<i', seq)

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
        self.data[2:4] = struct.pack('<i', len)
        # self.data[3] = (len >> 8)
        # self.data[2] = (len & 0xFF)

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
        while (sum >> 16 != 0):
            sum = (sum & 0xFFFF) + (sum >> 16)
        return ~sum

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

def get_seq():
    global sequence
    sequence += 1
    return sequence

def send_and_receive(pkt):
    global k_serial

    pkt.set_sequence(get_seq())
    pkt.set_checksum()

    payload = translated(pkt.get_bytes())

    print ">>", binascii.hexlify(payload)

    k_serial.write(payload)
    k_serial.flush()
    byte1 = k_serial.read()
    more_bytes = k_serial.read(k_serial.in_waiting)
    buf = byte1 + more_bytes

    print "<<", binascii.hexlify(buf)
    return buf

def send_command(command):
    global restart_flag

    pkt = Packet()
    if not restart_flag:
        pkt.set_restart_flag()
        restart_flag = True

    pkt.set_command(command)
    reply = send_and_receive(pkt)

def connect():
    return send_command(1)

def power_on_card():
    return send_command(2)

def power_off_card():
    return send_command(3)

def main():
    global restart_flag
    global k_serial
    k_serial = serial.Serial('/dev/tty.usbserial-AH01SKWE', baudrate=115200)

    # pkt = Packet()
    # get_seq()
    # # pkt.set_restart_flag()
    # pkt.set_sequence(get_seq())
    # pkt.set_command(2)
    # pkt.set_checksum()
    # print binascii.hexlify(pkt.get_bytes())
    # print binascii.hexlify(translated(pkt.get_bytes()))
    # return

    connect()

    power_on_card()

    power_off_card()


    
if __name__ == "__main__":
    main()
